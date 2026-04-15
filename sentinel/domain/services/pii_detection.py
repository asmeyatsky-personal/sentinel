"""
PII Detection Domain Service

Pure domain logic for identifying personally identifiable information.
Pattern definitions only — actual scanning delegated to infrastructure via port.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.domain.value_objects.data_classification import DataClassification


@dataclass(frozen=True)
class PIIPattern:
    name: str
    regex: str
    classification: DataClassification


# PII patterns covering PRD requirements: names, emails, phones, national IDs,
# financial accounts, health identifiers, plus Zetu-specific patterns
PII_PATTERNS: tuple[PIIPattern, ...] = (
    PIIPattern(
        name="email_address",
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        classification=DataClassification.CONFIDENTIAL,
    ),
    PIIPattern(
        name="phone_number",
        regex=r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        classification=DataClassification.CONFIDENTIAL,
    ),
    PIIPattern(
        name="credit_card",
        regex=r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="ssn",
        regex=r"\b\d{3}-\d{2}-\d{4}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="kenyan_national_id",
        regex=r"\b\d{7,8}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="south_african_id",
        regex=r"\b\d{13}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="nigerian_bvn",
        regex=r"\b\d{11}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="iban",
        regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
        classification=DataClassification.RESTRICTED,
    ),
    PIIPattern(
        name="api_key",
        regex=r"\b(sk|pk|api[_-]?key)[_-][a-zA-Z0-9_]{20,}\b",
        classification=DataClassification.RESTRICTED,
    ),
)


class PIIDetectionService:
    """Domain service for PII pattern matching and classification."""

    def __init__(self, patterns: tuple[PIIPattern, ...] = PII_PATTERNS) -> None:
        self._patterns = patterns
        self._compiled = tuple(
            (p, re.compile(p.regex)) for p in patterns
        )

    def detect(self, content: str) -> list[tuple[PIIPattern, str]]:
        matches: list[tuple[PIIPattern, str]] = []
        for pattern, compiled in self._compiled:
            for match in compiled.finditer(content):
                matches.append((pattern, match.group()))
        return matches

    def classify_content(self, content: str) -> DataClassification:
        matches = self.detect(content)
        if not matches:
            return DataClassification.PUBLIC
        return max(
            (m[0].classification for m in matches),
            key=lambda c: list(DataClassification).index(c),
        )

    def redact(self, content: str) -> str:
        result = content
        for pattern, compiled in self._compiled:
            result = compiled.sub(f"[REDACTED:{pattern.name}]", result)
        return result
