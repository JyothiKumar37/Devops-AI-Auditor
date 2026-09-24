"""Ansible analysis subsystem.

A deterministic, regex-based rule engine for Ansible playbooks, roles and vars
files. No LLM is involved and no playbook is ever executed - the text is only
read and analysed.
"""

from scanners.ansible.scanner import AnsibleScanner

__all__ = ["AnsibleScanner"]
