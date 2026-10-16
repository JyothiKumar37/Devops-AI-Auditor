"""AWS resource discovery (read-only, metadata only).

Each ``discover_*`` function takes a boto3 client for one service and returns a
list of :class:`DiscoveredResource`. All list calls use paginators (so large
accounts page correctly) and the shared adaptive-retry config handles throttling.
Only configuration metadata is captured - never secret values.

The ``REGIONAL_SERVICES`` / ``GLOBAL_SERVICES`` registries drive the orchestrator
and keep the provider architecture extensible: adding a service is a new function
plus one registry entry.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from core.logging import get_logger
from services.aws.resources import (
    EXPOSURE_PRIVATE,
    EXPOSURE_PUBLIC,
    EXPOSURE_UNKNOWN,
    DiscoveredResource,
    name_from_tags,
    tags_to_dict,
)

logger = get_logger(__name__)


def _paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterable[dict]:
    """Yield items from a paginated AWS operation (falls back to a single call)."""
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, []) or []
    else:
        resp = getattr(client, operation)(**kwargs)
        yield from resp.get(result_key, []) or []


# ---- EC2 / networking -------------------------------------------------------


def discover_ec2_instances(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for reservation in _paginate(client, "describe_instances", "Reservations"):
        for inst in reservation.get("Instances", []):
            tags = tags_to_dict(inst.get("Tags"))
            public_ip = inst.get("PublicIpAddress")
            sg_ids = [g.get("GroupId") for g in inst.get("SecurityGroups", []) if g.get("GroupId")]
            out.append(
                DiscoveredResource(
                    service="ec2", resource_type="instance",
                    resource_id=inst.get("InstanceId", ""),
                    name=name_from_tags(tags, inst.get("InstanceId", "")),
                    region=region, state=inst.get("State", {}).get("Name", ""),
                    exposure=EXPOSURE_PUBLIC if public_ip else EXPOSURE_PRIVATE,
                    tags=tags,
                    attributes={
                        "public_ip": public_ip,
                        "private_ip": inst.get("PrivateIpAddress"),
                        "vpc_id": inst.get("VpcId"),
                        "subnet_id": inst.get("SubnetId"),
                        "security_groups": sg_ids,
                        "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                        "image_id": inst.get("ImageId"),
                        "metadata_options": inst.get("MetadataOptions", {}),
                    },
                )
            )
    return out


def discover_security_groups(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for sg in _paginate(client, "describe_security_groups", "SecurityGroups"):
        out.append(
            DiscoveredResource(
                service="ec2", resource_type="security-group",
                resource_id=sg.get("GroupId", ""), name=sg.get("GroupName", ""),
                region=region, tags=tags_to_dict(sg.get("Tags")),
                attributes={
                    "vpc_id": sg.get("VpcId"),
                    "ingress": _normalize_sg_rules(sg.get("IpPermissions", [])),
                    "egress": _normalize_sg_rules(sg.get("IpPermissionsEgress", [])),
                },
            )
        )
    return out


def _normalize_sg_rules(perms: list[dict]) -> list[dict]:
    rules: list[dict] = []
    for p in perms:
        cidrs = [r.get("CidrIp") for r in p.get("IpRanges", []) if r.get("CidrIp")]
        cidrs6 = [r.get("CidrIpv6") for r in p.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
        rules.append(
            {
                "protocol": p.get("IpProtocol"),
                "from_port": p.get("FromPort"),
                "to_port": p.get("ToPort"),
                "cidrs": cidrs + cidrs6,
            }
        )
    return rules


def discover_vpcs(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for vpc in _paginate(client, "describe_vpcs", "Vpcs"):
        tags = tags_to_dict(vpc.get("Tags"))
        out.append(
            DiscoveredResource(
                service="vpc", resource_type="vpc", resource_id=vpc.get("VpcId", ""),
                name=name_from_tags(tags, vpc.get("VpcId", "")), region=region,
                state=vpc.get("State", ""), tags=tags,
                attributes={"cidr": vpc.get("CidrBlock"), "is_default": vpc.get("IsDefault")},
            )
        )
    return out


def discover_subnets(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for sn in _paginate(client, "describe_subnets", "Subnets"):
        tags = tags_to_dict(sn.get("Tags"))
        out.append(
            DiscoveredResource(
                service="vpc", resource_type="subnet", resource_id=sn.get("SubnetId", ""),
                name=name_from_tags(tags, sn.get("SubnetId", "")), region=region,
                state=sn.get("State", ""), tags=tags,
                attributes={
                    "vpc_id": sn.get("VpcId"),
                    "cidr": sn.get("CidrBlock"),
                    "availability_zone": sn.get("AvailabilityZone"),
                    "map_public_ip_on_launch": sn.get("MapPublicIpOnLaunch"),
                },
            )
        )
    return out


def discover_internet_gateways(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for igw in _paginate(client, "describe_internet_gateways", "InternetGateways"):
        vpcs = [a.get("VpcId") for a in igw.get("Attachments", []) if a.get("VpcId")]
        out.append(
            DiscoveredResource(
                service="vpc", resource_type="internet-gateway",
                resource_id=igw.get("InternetGatewayId", ""), region=region,
                tags=tags_to_dict(igw.get("Tags")), attributes={"vpc_ids": vpcs},
            )
        )
    return out


def discover_route_tables(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for rt in _paginate(client, "describe_route_tables", "RouteTables"):
        routes = [
            {"destination": r.get("DestinationCidrBlock"), "gateway_id": r.get("GatewayId")}
            for r in rt.get("Routes", [])
        ]
        subnet_assocs = [
            a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")
        ]
        out.append(
            DiscoveredResource(
                service="vpc", resource_type="route-table",
                resource_id=rt.get("RouteTableId", ""), region=region,
                tags=tags_to_dict(rt.get("Tags")),
                attributes={
                    "vpc_id": rt.get("VpcId"), "routes": routes, "subnets": subnet_assocs
                },
            )
        )
    return out


def discover_load_balancers(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for lb in _paginate(client, "describe_load_balancers", "LoadBalancers"):
        scheme = lb.get("Scheme", "")
        out.append(
            DiscoveredResource(
                service="elb", resource_type="load-balancer",
                resource_id=lb.get("LoadBalancerName", ""),
                arn=lb.get("LoadBalancerArn", ""), name=lb.get("LoadBalancerName", ""),
                region=region, state=(lb.get("State") or {}).get("Code", ""),
                exposure=EXPOSURE_PUBLIC if scheme == "internet-facing" else EXPOSURE_PRIVATE,
                attributes={
                    "scheme": scheme, "type": lb.get("Type"), "vpc_id": lb.get("VpcId"),
                    "dns_name": lb.get("DNSName"),
                    "security_groups": lb.get("SecurityGroups", []),
                },
            )
        )
    return out


# ---- RDS / storage ----------------------------------------------------------


def discover_rds(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for db in _paginate(client, "describe_db_instances", "DBInstances"):
        public = bool(db.get("PubliclyAccessible"))
        out.append(
            DiscoveredResource(
                service="rds", resource_type="db-instance",
                resource_id=db.get("DBInstanceIdentifier", ""),
                arn=db.get("DBInstanceArn", ""), name=db.get("DBInstanceIdentifier", ""),
                region=region, state=db.get("DBInstanceStatus", ""),
                exposure=EXPOSURE_PUBLIC if public else EXPOSURE_PRIVATE,
                attributes={
                    "engine": db.get("Engine"),
                    "publicly_accessible": public,
                    "storage_encrypted": bool(db.get("StorageEncrypted")),
                    "multi_az": bool(db.get("MultiAZ")),
                    "backup_retention_days": db.get("BackupRetentionPeriod"),
                    "deletion_protection": bool(db.get("DeletionProtection")),
                    "vpc_security_groups": [
                        g.get("VpcSecurityGroupId")
                        for g in db.get("VpcSecurityGroups", [])
                    ],
                },
            )
        )
    return out


def discover_s3(client: Any, region: str) -> list[DiscoveredResource]:
    """List buckets + per-bucket security posture. S3 is a global namespace."""
    out: list[DiscoveredResource] = []
    resp = client.list_buckets()
    for bucket in resp.get("Buckets", []):
        name = bucket.get("Name", "")
        attributes: dict[str, Any] = {
            "public_access_block": _s3_public_access_block(client, name),
            "encryption": _s3_encryption(client, name),
            "versioning": _s3_versioning(client, name),
            "policy_status_public": _s3_policy_is_public(client, name),
        }
        pab = attributes["public_access_block"] or {}
        fully_blocked = all(
            pab.get(k) for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets",
            )
        )
        exposure = EXPOSURE_PRIVATE if fully_blocked else EXPOSURE_UNKNOWN
        if attributes["policy_status_public"]:
            exposure = EXPOSURE_PUBLIC
        out.append(
            DiscoveredResource(
                service="s3", resource_type="bucket", resource_id=name, name=name,
                region=region, exposure=exposure, attributes=attributes,
            )
        )
    return out


def _s3_public_access_block(client: Any, bucket: str) -> dict | None:
    try:
        resp = client.get_public_access_block(Bucket=bucket)
        return resp.get("PublicAccessBlockConfiguration")
    except (ClientError, BotoCoreError):
        return None


def _s3_encryption(client: Any, bucket: str) -> bool:
    try:
        client.get_bucket_encryption(Bucket=bucket)
        return True
    except (ClientError, BotoCoreError):
        return False


def _s3_versioning(client: Any, bucket: str) -> bool:
    try:
        return client.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled"
    except (ClientError, BotoCoreError):
        return False


def _s3_policy_is_public(client: Any, bucket: str) -> bool:
    try:
        return bool(
            client.get_bucket_policy_status(Bucket=bucket)
            .get("PolicyStatus", {})
            .get("IsPublic")
        )
    except (ClientError, BotoCoreError):
        return False


def discover_ecr(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for repo in _paginate(client, "describe_repositories", "repositories"):
        out.append(
            DiscoveredResource(
                service="ecr", resource_type="repository",
                resource_id=repo.get("repositoryName", ""),
                arn=repo.get("repositoryArn", ""), name=repo.get("repositoryName", ""),
                region=region,
                attributes={
                    "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get(
                        "scanOnPush"
                    ),
                    "tag_mutability": repo.get("imageTagMutability"),
                },
            )
        )
    return out


# ---- compute / containers ---------------------------------------------------


def discover_lambda(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for fn in _paginate(client, "list_functions", "Functions"):
        out.append(
            DiscoveredResource(
                service="lambda", resource_type="function",
                resource_id=fn.get("FunctionName", ""), arn=fn.get("FunctionArn", ""),
                name=fn.get("FunctionName", ""), region=region,
                attributes={
                    "runtime": fn.get("Runtime"),
                    "vpc_id": (fn.get("VpcConfig") or {}).get("VpcId"),
                },
            )
        )
    return out


def discover_eks(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    names: list[str] = []
    for page in client.get_paginator("list_clusters").paginate() if client.can_paginate(
        "list_clusters"
    ) else [client.list_clusters()]:
        names.extend(page.get("clusters", []) or [])
    for cluster_name in names:
        try:
            cluster = client.describe_cluster(name=cluster_name).get("cluster", {})
        except (ClientError, BotoCoreError):
            continue
        vpc_cfg = cluster.get("resourcesVpcConfig", {})
        public = bool(vpc_cfg.get("endpointPublicAccess"))
        out.append(
            DiscoveredResource(
                service="eks", resource_type="cluster", resource_id=cluster_name,
                arn=cluster.get("arn", ""), name=cluster_name, region=region,
                state=cluster.get("status", ""),
                exposure=EXPOSURE_PUBLIC if public else EXPOSURE_PRIVATE,
                tags={str(k): str(v) for k, v in (cluster.get("tags") or {}).items()},
                attributes={
                    "version": cluster.get("version"),
                    "vpc_id": vpc_cfg.get("vpcId"),
                    "endpoint_public_access": public,
                    "endpoint_private_access": bool(vpc_cfg.get("endpointPrivateAccess")),
                    "public_access_cidrs": vpc_cfg.get("publicAccessCidrs", []),
                },
            )
        )
    return out


# ---- IAM (global) -----------------------------------------------------------


def discover_iam(client: Any, region: str) -> list[DiscoveredResource]:
    out: list[DiscoveredResource] = []
    for user in _paginate(client, "list_users", "Users"):
        user_name = user.get("UserName", "")
        out.append(
            DiscoveredResource(
                service="iam", resource_type="user", resource_id=user_name,
                arn=user.get("Arn", ""), name=user_name, region="global",
                attributes={
                    "create_date": str(user.get("CreateDate", "")),
                    "password_last_used": str(user.get("PasswordLastUsed", "")),
                    "mfa_devices": _iam_mfa_count(client, user_name),
                    "access_keys": _iam_access_keys(client, user_name),
                },
            )
        )
    for role in _paginate(client, "list_roles", "Roles"):
        role_name = role.get("RoleName", "")
        out.append(
            DiscoveredResource(
                service="iam", resource_type="role", resource_id=role_name,
                arn=role.get("Arn", ""), name=role_name, region="global",
                attributes={
                    "assume_role_policy": role.get("AssumeRolePolicyDocument"),
                },
            )
        )
    return out


def _iam_mfa_count(client: Any, user_name: str) -> int:
    try:
        return len(client.list_mfa_devices(UserName=user_name).get("MFADevices", []))
    except (ClientError, BotoCoreError):
        return 0


def _iam_access_keys(client: Any, user_name: str) -> list[dict]:
    try:
        keys = client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    except (ClientError, BotoCoreError):
        return []
    # Metadata only - NEVER the secret key material.
    return [
        {"status": k.get("Status"), "create_date": str(k.get("CreateDate", ""))}
        for k in keys
    ]


# ---- registry ---------------------------------------------------------------

# service key -> (boto3 client name, discovery function)
REGIONAL_SERVICES: dict[str, tuple[str, Callable[[Any, str], list[DiscoveredResource]]]] = {
    "ec2-instances": ("ec2", discover_ec2_instances),
    "security-groups": ("ec2", discover_security_groups),
    "vpcs": ("ec2", discover_vpcs),
    "subnets": ("ec2", discover_subnets),
    "internet-gateways": ("ec2", discover_internet_gateways),
    "route-tables": ("ec2", discover_route_tables),
    "load-balancers": ("elbv2", discover_load_balancers),
    "rds": ("rds", discover_rds),
    "ecr": ("ecr", discover_ecr),
    "lambda": ("lambda", discover_lambda),
    "eks": ("eks", discover_eks),
}

GLOBAL_SERVICES: dict[str, tuple[str, Callable[[Any, str], list[DiscoveredResource]]]] = {
    "s3": ("s3", discover_s3),
    "iam": ("iam", discover_iam),
}


def discover_all(assumed: Any, regions: list[str]) -> list[DiscoveredResource]:
    """Run every service scanner across the given regions (blocking, thread-safe).

    Failures in one service/region are logged and skipped so a single permission
    gap or throttle does not abort the whole synchronization (graceful failure).
    """
    results: list[DiscoveredResource] = []
    for region in regions:
        for key, (client_name, fn) in REGIONAL_SERVICES.items():
            try:
                client = assumed.client(client_name, region)
                results.extend(fn(client, region))
            except (ClientError, BotoCoreError) as exc:
                logger.warning("aws_discover_failed", service=key, region=region, error=str(exc))
            except Exception as exc:  # noqa: BLE001 - never abort the whole sync
                logger.warning("aws_discover_error", service=key, region=region, error=str(exc))

    global_region = regions[0] if regions else "us-east-1"
    for key, (client_name, fn) in GLOBAL_SERVICES.items():
        try:
            client = assumed.client(client_name, global_region)
            results.extend(fn(client, global_region))
        except (ClientError, BotoCoreError) as exc:
            logger.warning("aws_discover_failed", service=key, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.warning("aws_discover_error", service=key, error=str(exc))
    return results
