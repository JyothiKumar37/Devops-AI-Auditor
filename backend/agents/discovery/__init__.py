"""Repository Discovery Agent.

Deterministically inspects an extracted repository and classifies every file into
DevOps artifact categories. No LLM is involved - detection is rule-based and
reproducible. The agent produces structured, grouped output and a flat list of
per-file records suitable for persistence.
"""

from agents.discovery.agent import RepositoryDiscoveryAgent
from agents.discovery.classifier import DiscoveryContext, FileClassifier, classify_file
from agents.discovery.types import (
    CATEGORY_BY_TYPE,
    DetectedType,
    DiscoveredFile,
    DiscoveryResult,
    FileCategory,
    category_for,
)

__all__ = [
    "CATEGORY_BY_TYPE",
    "DetectedType",
    "DiscoveredFile",
    "DiscoveryContext",
    "DiscoveryResult",
    "FileCategory",
    "FileClassifier",
    "RepositoryDiscoveryAgent",
    "category_for",
    "classify_file",
]
