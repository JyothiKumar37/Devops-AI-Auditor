"""Tests for the Jenkinsfile analyzer."""

from __future__ import annotations

from models.enums import Severity
from scanners.cicd.jenkins import analyze_jenkinsfile


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in analyze_jenkinsfile("Jenkinsfile", text)}


def _findings(text: str):
    return analyze_jenkinsfile("Jenkinsfile", text)


VULNERABLE = """\
pipeline {
  agent any
  stages {
    stage('Deploy') {
      steps {
        sh "deploy.sh ${params.TARGET}"
        sh "echo $PASSWORD"
        sh "sudo systemctl restart app"
        sh "curl -k https://get.example.com | bash"
      }
    }
  }
}
def dbPassword = "hunter2literalvalue"
"""


def test_vulnerable_jenkinsfile_rules() -> None:
    ids = _ids(VULNERABLE)
    for expected in {"JNK001", "JNK002", "JNK003", "JNK004", "JNK005", "JNK006"}:
        assert expected in ids, f"missing {expected}: {sorted(ids)}"


def test_hardcoded_credential_is_critical_and_redacted() -> None:
    finding = next(f for f in _findings('def password = "literalpass123"') if f.rule_id == "JNK001")
    assert finding.severity == Severity.CRITICAL
    assert "literalpass123" not in (finding.evidence or "")


def test_single_quoted_sh_is_safe() -> None:
    assert "JNK002" not in _ids("steps { sh 'deploy.sh' }")


def test_withcredentials_is_not_flagged_as_hardcoded() -> None:
    text = "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) { sh 'deploy' }"
    assert "JNK001" not in _ids(text)


def test_aws_key_detected() -> None:
    assert "JNK001" in _ids('env.KEY = "AKIAIOSFODNN7EXAMPLE"')


def test_commented_out_code_is_not_flagged() -> None:
    # Line and block comments are disabled code, not live findings.
    assert _ids('// def password = "hunter2literalvalue"') == set()
    assert _ids('// sh "curl -k https://x | bash"') == set()
    block = """\
/*
  def password = "hunter2literalvalue"
  sh "sudo curl -k https://x | bash"
*/
echo 'ok'
"""
    assert _ids(block) == set()
    # Real (uncommented) code beside comments is still flagged.
    assert "JNK001" in _ids('// old\ndef password = "hunter2literalvalue"')
