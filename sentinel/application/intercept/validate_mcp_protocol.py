"""
Validate MCP Protocol Use Case — INTERCEPT module

Architectural Intent:
- Validates MCP message structure before processing
- Checks for required fields, malformed payloads, protocol violations
- Acts as a pre-processing gate before tool calls reach detection/shield
- Returns a validation result with any violation details
"""

from __future__ import annotations

from sentinel.application.dtos.schemas import MCPValidationResultDTO


# Required fields per MCP tool call message spec
_REQUIRED_FIELDS = ("method", "params")
_REQUIRED_PARAMS_FIELDS = ("name",)
_MAX_PAYLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
_VALID_METHODS = frozenset({
    "tools/call",
    "tools/list",
    "resources/read",
    "resources/list",
    "prompts/get",
    "prompts/list",
    "completion/complete",
    "initialize",
    "ping",
})


class ValidateMCPProtocolUseCase:
    """Validates MCP message structure and checks for protocol violations."""

    def __init__(
        self,
        max_payload_size_bytes: int = _MAX_PAYLOAD_SIZE_BYTES,
    ) -> None:
        self._max_payload_size = max_payload_size_bytes

    async def execute(self, message: dict) -> MCPValidationResultDTO:
        violations: list[str] = []

        # Check top-level structure
        if not isinstance(message, dict):
            return MCPValidationResultDTO(
                valid=False,
                violations=["Message must be a JSON object"],
            )

        # JSON-RPC version
        if message.get("jsonrpc") != "2.0":
            violations.append(
                "Missing or invalid 'jsonrpc' field — must be '2.0'"
            )

        # Method field
        method = message.get("method")
        if not method:
            violations.append("Missing required 'method' field")
        elif not isinstance(method, str):
            violations.append("'method' field must be a string")
        elif method not in _VALID_METHODS:
            violations.append(
                f"Unknown method '{method}' — not in MCP specification"
            )

        # Params validation for tool calls
        if method == "tools/call":
            params = message.get("params")
            if params is None:
                violations.append(
                    "Missing required 'params' field for tools/call"
                )
            elif not isinstance(params, dict):
                violations.append("'params' must be a JSON object")
            else:
                if "name" not in params:
                    violations.append(
                        "Missing required 'name' in params for tools/call"
                    )
                if "arguments" in params and not isinstance(
                    params["arguments"], dict
                ):
                    violations.append(
                        "'arguments' in params must be a JSON object"
                    )

        # Payload size check
        import json

        try:
            payload_bytes = len(json.dumps(message, default=str).encode())
            if payload_bytes > self._max_payload_size:
                violations.append(
                    f"Payload size ({payload_bytes} bytes) exceeds maximum "
                    f"({self._max_payload_size} bytes)"
                )
        except (TypeError, ValueError):
            violations.append("Message is not JSON-serialisable")

        # ID field (required for requests, absent for notifications)
        if "id" not in message and method in _VALID_METHODS - {"ping"}:
            violations.append(
                "Missing 'id' field — required for request messages"
            )

        return MCPValidationResultDTO(
            valid=len(violations) == 0,
            violations=violations,
        )
