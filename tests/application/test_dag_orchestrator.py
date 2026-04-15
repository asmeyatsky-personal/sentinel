"""Tests for DAGOrchestrator — verify parallel execution and failure modes."""

from __future__ import annotations

import asyncio

import pytest


@pytest.mark.asyncio
class TestDAGOrchestrator:
    async def test_sequential_execution(self):
        from sentinel.application.orchestration.dag_orchestrator import (
            DAGOrchestrator,
            WorkflowStep,
        )

        execution_order: list[str] = []

        async def step_a(ctx, completed):
            execution_order.append("a")
            return "result_a"

        async def step_b(ctx, completed):
            execution_order.append("b")
            return f"result_b({completed['a']})"

        orchestrator = DAGOrchestrator([
            WorkflowStep(name="a", execute=step_a),
            WorkflowStep(name="b", execute=step_b, depends_on=["a"]),
        ])

        results = await orchestrator.execute({})
        assert results["a"] == "result_a"
        assert results["b"] == "result_b(result_a)"
        assert execution_order == ["a", "b"]

    async def test_parallel_execution(self):
        from sentinel.application.orchestration.dag_orchestrator import (
            DAGOrchestrator,
            WorkflowStep,
        )

        started: list[str] = []

        async def step_a(ctx, completed):
            started.append("a")
            await asyncio.sleep(0.01)
            return "a"

        async def step_b(ctx, completed):
            started.append("b")
            await asyncio.sleep(0.01)
            return "b"

        async def step_c(ctx, completed):
            return f"c({completed['a']},{completed['b']})"

        orchestrator = DAGOrchestrator([
            WorkflowStep(name="a", execute=step_a),
            WorkflowStep(name="b", execute=step_b),
            WorkflowStep(name="c", execute=step_c, depends_on=["a", "b"]),
        ])

        results = await orchestrator.execute({})
        assert results["c"] == "c(a,b)"
        # a and b should both start before c
        assert set(started) == {"a", "b"}

    async def test_step_failure_raises(self):
        from sentinel.application.orchestration.dag_orchestrator import (
            DAGOrchestrator,
            OrchestrationError,
            WorkflowStep,
        )

        async def failing_step(ctx, completed):
            raise ValueError("boom")

        orchestrator = DAGOrchestrator([
            WorkflowStep(name="fail", execute=failing_step),
        ])

        with pytest.raises(OrchestrationError, match="fail"):
            await orchestrator.execute({})

    async def test_diamond_dependency(self):
        from sentinel.application.orchestration.dag_orchestrator import (
            DAGOrchestrator,
            WorkflowStep,
        )

        async def root(ctx, completed):
            return "root"

        async def left(ctx, completed):
            return f"left({completed['root']})"

        async def right(ctx, completed):
            return f"right({completed['root']})"

        async def join(ctx, completed):
            return f"join({completed['left']},{completed['right']})"

        orchestrator = DAGOrchestrator([
            WorkflowStep(name="root", execute=root),
            WorkflowStep(name="left", execute=left, depends_on=["root"]),
            WorkflowStep(name="right", execute=right, depends_on=["root"]),
            WorkflowStep(name="join", execute=join, depends_on=["left", "right"]),
        ])

        results = await orchestrator.execute({})
        assert results["join"] == "join(left(root),right(root))"
