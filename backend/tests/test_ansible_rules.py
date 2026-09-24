"""Tests for the deterministic Ansible rule engine."""

from __future__ import annotations

from models.enums import Severity
from scanners.ansible.scanner import AnsibleScanner


def _rule_ids(text: str) -> set[str]:
    return {f.rule_id for f in AnsibleScanner().analyze_text(text, "site.yml")}


def _findings(text: str):
    return AnsibleScanner().analyze_text(text, "site.yml")


VULNERABLE = """\
---
- name: Deploy
  hosts: all
  tasks:
    - name: Fetch installer
      ansible.builtin.get_url:
        url: http://example.com/install.sh
        dest: /tmp/install.sh
        validate_certs: no
        mode: "0777"

    - name: Run raw shell
      shell: curl -fsSL http://get.example.com | bash

    - name: Install package
      apt:
        name: nginx
        state: latest
  vars:
    db_password: hunter2plaintext
    api_key: "{{ vault_api_key }}"
"""


def test_vulnerable_playbook_triggers_expected_rules() -> None:
    ids = _rule_ids(VULNERABLE)
    expected = {"ANS001", "ANS002", "ANS003", "ANS004", "ANS005", "ANS006", "ANS007"}
    assert ids == expected


def test_secret_value_is_masked() -> None:
    finding = next(f for f in _findings(VULNERABLE) if f.rule_id == "ANS004")
    assert "hunter2plaintext" not in (finding.evidence or "")
    assert finding.severity == Severity.HIGH


CLEAN = """\
---
- name: Deploy
  hosts: all
  tasks:
    - name: Fetch installer
      ansible.builtin.get_url:
        url: https://example.com/install.sh
        dest: /tmp/install.sh
        mode: "0640"

    - name: Install package
      ansible.builtin.apt:
        name: nginx=1.25.3
        state: present
  vars:
    db_password: "{{ vault_db_password }}"
"""


def test_clean_playbook_has_no_findings() -> None:
    assert _findings(CLEAN) == []


def test_validate_certs_disabled() -> None:
    assert "ANS002" in _rule_ids("    validate_certs: false\n")
    assert "ANS002" in _rule_ids("    validate_certs: no\n")
    assert "ANS002" not in _rule_ids("    validate_certs: yes\n")


def test_world_writable_mode() -> None:
    assert "ANS003" in _rule_ids('    mode: "0777"\n')
    assert "ANS003" in _rule_ids("    mode: 0777\n")
    assert "ANS003" not in _rule_ids('    mode: "0640"\n')


def test_plaintext_secret_but_not_templated_or_file() -> None:
    assert "ANS004" in _rule_ids("    db_password: literalsecret\n")
    assert "ANS004" not in _rule_ids('    db_password: "{{ vault_pw }}"\n')
    assert "ANS004" not in _rule_ids("    password_file: /etc/app/pw\n")


def test_insecure_http_url() -> None:
    assert "ANS005" in _rule_ids("    url: http://example.com/x\n")
    assert "ANS005" not in _rule_ids("    url: https://example.com/x\n")
    assert "ANS005" not in _rule_ids("    url: http://localhost:8080/x\n")


def test_state_latest() -> None:
    assert "ANS006" in _rule_ids("    state: latest\n")
    assert "ANS006" not in _rule_ids("    state: present\n")


def test_shell_command_module() -> None:
    assert "ANS001" in _rule_ids("    shell: echo hi\n")
    assert "ANS001" in _rule_ids("    command: /bin/true\n")
    assert "ANS001" in _rule_ids("    ansible.builtin.shell: whoami\n")
    # A task name that merely mentions a module must not be flagged.
    assert "ANS001" not in _rule_ids("    - name: run the shell task\n")


def test_pipe_to_shell() -> None:
    assert "ANS007" in _rule_ids("    shell: wget -qO- https://x | sudo bash\n")


def test_findings_carry_full_schema() -> None:
    finding = next(f for f in _findings(VULNERABLE) if f.rule_id == "ANS002")
    assert finding.scanner == "ansible-rules"
    assert finding.title and finding.description and finding.recommendation
    assert finding.line_number is not None
    assert finding.category is not None and finding.confidence is not None
