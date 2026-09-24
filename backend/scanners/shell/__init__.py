"""Shell-script analysis subsystem.

A deterministic, regex-based rule engine for shell scripts. No LLM is involved
and no script is ever executed - the text is only read and analysed.
"""

from scanners.shell.scanner import ShellScanner

__all__ = ["ShellScanner"]
