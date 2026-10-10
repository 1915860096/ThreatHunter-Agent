"""Verdict tests reuse the finding fixtures (scripted payloads + T06 extractor)."""

from tests.findings.conftest import (  # noqa: F401 - fixtures are re-exported
    make_extraction,
    malicious_extraction,
)
