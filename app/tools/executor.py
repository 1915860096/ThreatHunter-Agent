"""``ToolExecutor``: turn a T02 ``ToolCall`` into a T02 ``ToolResult``."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from app.benchmark.loader import BenchmarkError, BenchmarkLoader
from app.schemas.tools import ToolCall, ToolResult
from app.tools.contracts import (
    CTISearchInput,
    EndpointSearchInput,
    FileReputationInput,
    IOCReputationInput,
    NetworkSearchInput,
)
from app.tools.cti import search_cti
from app.tools.endpoint import search_endpoint_events
from app.tools.file_reputation import lookup_file_reputation
from app.tools.ioc_reputation import lookup_ioc_reputation
from app.tools.network import search_network_activity

SUPPORTED_TOOL_NAMES: Final[tuple[str, ...]] = (
    "search_endpoint_events",
    "search_network_activity",
    "lookup_file_reputation",
    "lookup_ioc_reputation",
    "search_cti",
)


class UnknownToolError(Exception):
    """Raised internally when a ``ToolCall`` names an unsupported tool."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ToolExecutor:
    """Execute one :class:`~app.schemas.tools.ToolCall` and report a result.

    The executor validates ``ToolCall.arguments`` into the selected tool's
    input schema, runs the tool, measures latency and returns a T02
    :class:`~app.schemas.tools.ToolResult` whose ``data`` is the tool payload
    serialised with ``model_dump(mode="json")``.

    It does not mutate the incoming ``ToolCall`` and does not manage call
    lifecycle (``requested -> running -> succeeded/failed`` belongs to future
    orchestration). Failures - invalid arguments, unknown tool name, dataset
    errors - are reported as ``success=False`` results instead of exceptions.
    """

    def __init__(
        self,
        loader: BenchmarkLoader | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._loader = loader or BenchmarkLoader()
        self._clock = clock or _utc_now
        self._sequence = 0
        self._tools: dict[str, tuple[type[BaseModel], Callable[..., BaseModel]]] = {
            "search_endpoint_events": (EndpointSearchInput, search_endpoint_events),
            "search_network_activity": (NetworkSearchInput, search_network_activity),
            "lookup_file_reputation": (FileReputationInput, lookup_file_reputation),
            "lookup_ioc_reputation": (IOCReputationInput, lookup_ioc_reputation),
            "search_cti": (CTISearchInput, search_cti),
        }

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute ``tool_call`` and return its result; never raises."""
        started = time.perf_counter()
        data: dict[str, Any] | list[Any] | None = None
        error: str | None = None
        try:
            data = self._run(tool_call)
        except Exception as exc:  # noqa: BLE001 - failures become ToolResult.error
            error = self._describe_failure(tool_call.tool_name, exc)

        latency_ms = max(round((time.perf_counter() - started) * 1000), 0)
        return ToolResult(
            tool_result_id=self._next_tool_result_id(),
            tool_call_id=tool_call.tool_call_id,
            tool_name=tool_call.tool_name,
            success=error is None,
            data=data,
            error=error,
            latency_ms=latency_ms,
            returned_at=self._clock(),
        )

    def _run(self, tool_call: ToolCall) -> dict[str, Any] | list[Any] | None:
        """Dispatch one call and serialise the payload for ``ToolResult.data``."""
        spec = self._tools.get(tool_call.tool_name)
        if spec is None:
            raise UnknownToolError(
                f"unknown tool {tool_call.tool_name!r}; supported tools: "
                f"{', '.join(SUPPORTED_TOOL_NAMES)}"
            )

        input_model, tool = spec
        request = input_model.model_validate(tool_call.arguments)
        payload = tool(request, self._loader)
        return payload.model_dump(mode="json")

    def _next_tool_result_id(self) -> str:
        """Return the next executor-scoped result id (``TR-0001``, ``TR-0002``, ...).

        T02 fixes only the ``TR-`` prefix, so a per-executor sequence is the
        smallest deterministic scheme that keeps results distinguishable.
        """
        self._sequence += 1
        return f"TR-{self._sequence:04d}"

    @staticmethod
    def _describe_failure(tool_name: str, error: Exception) -> str:
        """Build a clear ``ToolResult.error`` message.

        Validation errors are summarised by field location and message only:
        echoing the rejected input back would leak tool arguments into logs and
        reports.
        """
        if isinstance(error, ValidationError):
            details = "; ".join(
                f"{'.'.join(str(part) for part in issue['loc']) or '<request>'}: {issue['msg']}"
                for issue in error.errors(include_url=False, include_input=False)[:3]
            )
            return f"invalid arguments for tool {tool_name!r}: {details}"
        if isinstance(error, UnknownToolError):
            return str(error)
        if isinstance(error, BenchmarkError):
            return f"tool {tool_name!r} failed: {error}"
        return f"tool {tool_name!r} failed: {type(error).__name__}: {error}"
