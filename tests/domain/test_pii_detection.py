"""Tests for PIIDetectionService — pure domain service tests."""

from __future__ import annotations

from sentinel.domain.services.pii_detection import PIIDetectionService
from sentinel.domain.value_objects.data_classification import DataClassification


class TestPIIDetectionService:
    def setup_method(self):
        self.service = PIIDetectionService()

    def test_detect_email(self):
        matches = self.service.detect("Contact us at user@example.com for info")
        assert any(m[0].name == "email_address" for m in matches)

    def test_detect_credit_card(self):
        matches = self.service.detect("Card: 4111-1111-1111-1111")
        assert any(m[0].name == "credit_card" for m in matches)

    def test_detect_ssn(self):
        matches = self.service.detect("SSN: 123-45-6789")
        assert any(m[0].name == "ssn" for m in matches)

    def test_detect_api_key(self):
        matches = self.service.detect("key: sk_live_abc12345678901234567890")
        assert any(m[0].name == "api_key" for m in matches)

    def test_no_pii_returns_empty(self):
        matches = self.service.detect("This is clean text with no PII")
        assert len(matches) == 0

    def test_classify_restricted(self):
        classification = self.service.classify_content("Card: 4111-1111-1111-1111")
        assert classification is DataClassification.RESTRICTED

    def test_classify_confidential(self):
        classification = self.service.classify_content("Email: user@example.com")
        assert classification is DataClassification.CONFIDENTIAL

    def test_classify_public(self):
        classification = self.service.classify_content("Hello world")
        assert classification is DataClassification.PUBLIC

    def test_redact_replaces_pii(self):
        text = "Contact user@example.com for help"
        redacted = self.service.redact(text)
        assert "user@example.com" not in redacted
        assert "[REDACTED:email_address]" in redacted

    def test_redact_multiple(self):
        text = "Email: a@b.com, Card: 4111-1111-1111-1111"
        redacted = self.service.redact(text)
        assert "a@b.com" not in redacted
        assert "4111-1111-1111-1111" not in redacted
