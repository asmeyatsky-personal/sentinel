"""Pattern-based prompt injection detector implementing PromptInjectionDetectorPort."""

from __future__ import annotations

import re

from sentinel.domain.ports.detection import PromptInjectionResult

# Each pattern is a tuple of (compiled regex, human-readable label, weight 0-1).
_INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "ignore_previous_instructions",
        0.95,
    ),
    (
        re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
        "system_prompt_leak",
        0.85,
    ),
    (
        re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
        "role_override",
        0.80,
    ),
    (
        re.compile(r"disregard\s+(all\s+)?(your\s+)?(the\s+)?(previous|prior|above)", re.IGNORECASE),
        "disregard_instructions",
        0.90,
    ),
    (
        re.compile(r"forget\s+(everything|all|your)", re.IGNORECASE),
        "forget_instructions",
        0.85,
    ),
    (
        re.compile(r"do\s+not\s+follow\s+(any|your|the)", re.IGNORECASE),
        "do_not_follow",
        0.88,
    ),
    (
        re.compile(r"act\s+as\s+(if\s+you\s+are|a|an)\b", re.IGNORECASE),
        "act_as_override",
        0.70,
    ),
    (
        re.compile(r"override\s+(your\s+)?(instructions|rules|guidelines)", re.IGNORECASE),
        "override_instructions",
        0.92,
    ),
    (
        re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
        "new_instructions",
        0.80,
    ),
    (
        re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE),
        "xml_system_tag",
        0.90,
    ),
    (
        re.compile(r"\bDAN\b.*\bjailbreak\b|\bjailbreak\b.*\bDAN\b", re.IGNORECASE),
        "dan_jailbreak",
        0.95,
    ),
    (
        re.compile(
            r"(print|reveal|show|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)",
            re.IGNORECASE,
        ),
        "prompt_extraction",
        0.85,
    ),
)


class PatternBasedInjectionDetector:
    """Scans text for common prompt injection patterns and returns a confidence score."""

    async def analyse(self, content: str) -> PromptInjectionResult:
        matched_labels: list[str] = []
        max_weight: float = 0.0

        for compiled, label, weight in _INJECTION_PATTERNS:
            if compiled.search(content):
                matched_labels.append(label)
                if weight > max_weight:
                    max_weight = weight

        is_injection = len(matched_labels) > 0
        # Boost confidence when multiple patterns match
        confidence = max_weight
        if len(matched_labels) > 1:
            confidence = min(confidence + 0.05 * (len(matched_labels) - 1), 1.0)

        return PromptInjectionResult(
            is_injection=is_injection,
            confidence=confidence if is_injection else 0.0,
            matched_patterns=tuple(matched_labels),
        )
