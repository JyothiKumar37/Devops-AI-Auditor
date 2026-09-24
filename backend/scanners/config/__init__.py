"""Generic configuration-file analysis subsystem.

A deterministic, key/value rule engine for YAML/JSON/TOML/ini/.env config files.
No LLM is involved and no file is executed - the text is only read and analysed.
Secret detection is handled by the dedicated secret scanner, not duplicated here.
"""

from scanners.config.scanner import ConfigScanner

__all__ = ["ConfigScanner"]
