"""Deterministic investigation tool layer (T04).

Five read-only tools query agent-visible benchmark data and return raw
structured payloads:

* :func:`~app.tools.endpoint.search_endpoint_events`
* :func:`~app.tools.network.search_network_activity`
* :func:`~app.tools.file_reputation.lookup_file_reputation`
* :func:`~app.tools.ioc_reputation.lookup_ioc_reputation`
* :func:`~app.tools.cti.search_cti`

Boundaries kept by this layer:

    ToolCall != ToolResult != Evidence != Finding

* tools answer "what does the telemetry/knowledge say", never "is this
  malicious";
* tools create no ``Evidence``, no ``Finding``, no verdict and no confidence;
* typed payloads reach T02 :class:`~app.schemas.tools.ToolResult` as plain JSON
  through :class:`~app.tools.executor.ToolExecutor`;
* only ``datasets/cases`` and ``datasets/knowledge`` are read - ground truth is
  unreachable from this package.
"""

from app.tools.contracts import (
    CTISearchInput,
    CTISearchPayload,
    EndpointSearchInput,
    EndpointSearchPayload,
    FileReputationInput,
    FileReputationPayload,
    IOCReputationInput,
    IOCReputationPayload,
    NetworkSearchInput,
    NetworkSearchPayload,
)
from app.tools.cti import search_cti
from app.tools.endpoint import search_endpoint_events
from app.tools.executor import SUPPORTED_TOOL_NAMES, ToolExecutor, UnknownToolError
from app.tools.file_reputation import lookup_file_reputation
from app.tools.ioc_reputation import lookup_ioc_reputation
from app.tools.network import search_network_activity

__all__ = [
    "CTISearchInput",
    "CTISearchPayload",
    "EndpointSearchInput",
    "EndpointSearchPayload",
    "FileReputationInput",
    "FileReputationPayload",
    "IOCReputationInput",
    "IOCReputationPayload",
    "NetworkSearchInput",
    "NetworkSearchPayload",
    "SUPPORTED_TOOL_NAMES",
    "ToolExecutor",
    "UnknownToolError",
    "lookup_file_reputation",
    "lookup_ioc_reputation",
    "search_cti",
    "search_endpoint_events",
    "search_network_activity",
]
