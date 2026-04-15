"""
Generic DAG Orchestrator — skill2026.md Rule 7

Architectural Intent:
- Executes workflow steps respecting dependency order
- Parallelises independent steps via asyncio.gather
- Validates DAG has no cycles before execution
- Step failures propagate as OrchestrationError

Parallelisation Notes:
- Steps with satisfied dependencies run concurrently per wave
- Each wave completes before the next wave is computed
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine


class OrchestrationError(Exception):
    """Raised when a workflow step fails or a cycle is detected."""


@dataclass
class WorkflowStep:
    """A single step in a DAG workflow."""

    name: str
    execute: Callable[..., Coroutine[Any, Any, Any]]
    depends_on: list[str] = field(default_factory=list)


class DAGOrchestrator:
    """
    Executes workflow steps respecting dependency order,
    parallelising independent steps automatically.
    """

    def __init__(self, steps: list[WorkflowStep]) -> None:
        self.steps: dict[str, WorkflowStep] = {s.name: s for s in steps}
        self._validate_no_cycles()

    async def execute(self, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run all steps, returning a mapping of step name to result."""
        if context is None:
            context = {}
        completed: dict[str, Any] = {}
        pending: set[str] = set(self.steps.keys())

        while pending:
            ready = [
                name
                for name in pending
                if all(dep in completed for dep in self.steps[name].depends_on)
            ]
            if not ready:
                raise OrchestrationError(
                    f"Circular dependency or unsatisfied deps among: {pending}"
                )

            results = await asyncio.gather(
                *(self.steps[name].execute(context, completed) for name in ready),
                return_exceptions=True,
            )

            for name, result in zip(ready, results):
                if isinstance(result, BaseException):
                    raise OrchestrationError(
                        f"Step '{name}' failed: {result}"
                    ) from result
                completed[name] = result
                pending.discard(name)

        return completed

    # ── Private helpers ──────────────────────────────────────────────────

    def _validate_no_cycles(self) -> None:
        """Kahn's algorithm — checks for cycles in the dependency graph."""
        in_degree: dict[str, int] = {name: 0 for name in self.steps}
        for step in self.steps.values():
            for dep in step.depends_on:
                if dep not in self.steps:
                    raise OrchestrationError(
                        f"Step '{step.name}' depends on unknown step '{dep}'"
                    )
                in_degree[step.name] += 1

        queue = [name for name, degree in in_degree.items() if degree == 0]
        visited = 0

        while queue:
            current = queue.pop(0)
            visited += 1
            for step in self.steps.values():
                if current in step.depends_on:
                    in_degree[step.name] -= 1
                    if in_degree[step.name] == 0:
                        queue.append(step.name)

        if visited != len(self.steps):
            raise OrchestrationError("Cycle detected in workflow DAG")
