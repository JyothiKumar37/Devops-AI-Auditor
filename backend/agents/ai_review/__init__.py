"""AI review subsystem.

A complementary, LLM-backed detection pass that augments the deterministic
scanners. It is gated on an available LLM provider, marks its findings distinctly
(``scanner="ai-review"``), and never replaces the reproducible rule engine.
"""

from agents.ai_review.scanner import AIReviewScanner

__all__ = ["AIReviewScanner"]
