import { useState } from "react";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import {
  useCreateNotificationChannel,
  useDeleteNotificationChannel,
  useNotificationChannels,
  useNotificationDeliveries,
  useTestNotificationChannel,
} from "@/hooks/usePlatform";
import { ApiError } from "@/lib/api";
import { prettyLabel, relativeTime } from "@/lib/format";
import type { NotificationChannelType } from "@/types/api";

const EVENTS = [
  "scan_completed",
  "scan_failed",
  "critical_finding",
  "secret_detected",
  "policy_failed",
  "pr_scan_failed",
  "readiness_decreased",
  "new_vulnerability",
  "remediation_completed",
];

function CreateChannelForm({ onDone }: { onDone: () => void }) {
  const create = useCreateNotificationChannel();
  const [type, setType] = useState<NotificationChannelType>("slack");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [recipients, setRecipients] = useState("");
  const [events, setEvents] = useState<string[]>(["pr_scan_failed", "policy_failed"]);

  const toggle = (ev: string) =>
    setEvents((cur) => (cur.includes(ev) ? cur.filter((e) => e !== ev) : [...cur, ev]));

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    let config: Record<string, unknown> = {};
    if (type === "slack" || type === "teams") config = { webhook_url: url.trim() };
    else if (type === "webhook") config = { url: url.trim() };
    else if (type === "email") config = { recipients: recipients.split(",").map((r) => r.trim()).filter(Boolean) };
    create.mutate(
      { type, name: name.trim(), config, events },
      { onSuccess: onDone },
    );
  };

  const needsUrl = type !== "email";

  return (
    <Card className="p-5">
      <h2 className="mb-3 text-sm font-semibold text-slate-900">New channel</h2>
      <form onSubmit={onSubmit} className="space-y-3">
        <div className="flex gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Type</span>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as NotificationChannelType)}
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand"
            >
              <option value="slack">Slack</option>
              <option value="teams">Microsoft Teams</option>
              <option value="webhook">Webhook</option>
              <option value="email">Email</option>
            </select>
          </label>
          <label className="flex flex-1 flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="security-alerts"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
            />
          </label>
        </div>

        {needsUrl ? (
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Webhook URL</span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/…"
              className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
            />
          </label>
        ) : (
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Recipients (comma separated)</span>
            <input
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="team@acme.com, sec@acme.com"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
            />
          </label>
        )}

        <div>
          <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Events</span>
          <div className="mt-1.5 grid grid-cols-2 gap-1.5 sm:grid-cols-3">
            {EVENTS.map((ev) => (
              <label key={ev} className="flex items-center gap-2 text-xs text-slate-600">
                <input type="checkbox" checked={events.includes(ev)} onChange={() => toggle(ev)} />
                {prettyLabel(ev)}
              </label>
            ))}
          </div>
        </div>

        {create.isError ? (
          <p className="text-xs text-rose-600">
            {create.error instanceof ApiError ? create.error.message : "Could not create the channel."}
          </p>
        ) : null}

        <div className="flex gap-2">
          <button type="submit" disabled={create.isPending || !name.trim() || events.length === 0} className="btn-primary px-4 py-2 text-xs disabled:opacity-50">
            {create.isPending ? "Creating…" : "Create channel"}
          </button>
          <button type="button" onClick={onDone} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50">
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

function Deliveries() {
  const { data } = useNotificationDeliveries();
  const items = data ?? [];
  if (items.length === 0) return null;
  return (
    <div>
      <h2 className="mb-2 text-sm font-semibold text-slate-900">Recent deliveries</h2>
      <div className="space-y-1.5">
        {items.slice(0, 15).map((d) => (
          <div key={d.id} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs">
            <span className="flex items-center gap-2">
              <Badge className={d.status === "sent" ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20" : "bg-rose-50 text-rose-700 ring-rose-600/20"}>
                {d.status}
              </Badge>
              <span className="text-slate-600">{prettyLabel(d.event_type)}</span>
              {d.error ? <span className="text-rose-500">· {d.error}</span> : null}
            </span>
            <span className="text-slate-400">{relativeTime(d.created_at)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Notifications() {
  const { data, isLoading } = useNotificationChannels();
  const remove = useDeleteNotificationChannel();
  const test = useTestNotificationChannel();
  const [creating, setCreating] = useState(false);
  const channels = data?.items ?? [];

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Notifications"
        subtitle="Route security events to Slack, Teams, webhooks or email. Secrets are stored encrypted."
        actions={
          !creating ? (
            <button type="button" onClick={() => setCreating(true)} className="btn-primary px-3.5 py-2 text-xs">
              New channel
            </button>
          ) : null
        }
      />

      <div className="space-y-6">
        {creating ? <CreateChannelForm onDone={() => setCreating(false)} /> : null}

        {isLoading ? (
          <Spinner label="Loading channels…" />
        ) : channels.length === 0 && !creating ? (
          <EmptyState
            title="No notification channels"
            description="Add a channel to be alerted when a scan fails, a policy gate blocks a PR, or a secret is detected."
          />
        ) : (
          <div className="space-y-3">
            {channels.map((ch) => (
              <Card key={ch.id} className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <Badge className="bg-brand-50 text-brand-deep ring-brand-200">{ch.type}</Badge>
                      <span className="font-medium text-slate-800">{ch.name}</span>
                      {ch.enabled ? (
                        <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">enabled</Badge>
                      ) : (
                        <Badge className="bg-slate-100 text-slate-500 ring-slate-300">disabled</Badge>
                      )}
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {ch.events.map((ev) => (
                        <span key={ev} className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-500">
                          {prettyLabel(ev)}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => test.mutate(ch.id)}
                      disabled={test.isPending}
                      className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    >
                      {test.isPending ? "Testing…" : "Test"}
                    </button>
                    <button
                      type="button"
                      onClick={() => confirm(`Delete channel "${ch.name}"?`) && remove.mutate(ch.id)}
                      className="rounded-lg border border-rose-200 bg-white px-2.5 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        <Deliveries />
      </div>
    </div>
  );
}
