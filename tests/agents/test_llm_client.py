"""Tests for the OpenAI-compatible client and its configuration."""

from __future__ import annotations

import json
import socket
import urllib.error
from typing import Any

import pytest
from pydantic import ValidationError

from app.agents import (
    LLMAuthenticationError,
    LLMClient,
    LLMClientConfig,
    LLMClientError,
    LLMConfigurationError,
    LLMHTTPError,
    LLMResponseError,
    LLMTimeoutError,
    OpenAICompatibleLLMClient,
)
from app.core.config import Settings


class FakeResponse:
    """Minimal context-manager response object."""

    def __init__(self, body: str, status: int = 200) -> None:
        self._body = body.encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def config(**overrides: Any) -> LLMClientConfig:
    payload: dict[str, Any] = {
        "base_url": "https://llm.example.test/v1",
        "api_key": "sk-test-SECRET",
        "model": "test-model",
        "timeout_seconds": 5.0,
    }
    payload.update(overrides)
    return LLMClientConfig(**payload)  # type: ignore[arg-type]


def completion_body(content: str = '{"action":"complete_step"}') -> str:
    return json.dumps(
        {
            "model": "test-model",
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        }
    )


def client_returning(body: str) -> OpenAICompatibleLLMClient:
    return OpenAICompatibleLLMClient(
        config(), opener=lambda request, timeout=None: FakeResponse(body)
    )


def test_config_rejects_empty_values() -> None:
    with pytest.raises(ValidationError):
        config(base_url="  ")

    with pytest.raises(ValidationError):
        config(api_key="")

    with pytest.raises(ValidationError):
        config(timeout_seconds=0.5)


def test_config_normalises_url_and_hides_the_key() -> None:
    built = config(base_url="https://llm.example.test/v1/")

    assert built.base_url == "https://llm.example.test/v1"
    assert "sk-test-SECRET" not in repr(built)
    assert "**********" in repr(built)


def test_config_from_settings_requires_llm_values() -> None:
    settings = Settings(".env-missing", llm_base_url="", llm_api_key="", llm_model="")

    with pytest.raises(LLMConfigurationError) as exc_info:
        LLMClientConfig.from_settings(settings)

    message = str(exc_info.value)
    for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        assert name in message


def test_config_from_settings_builds_client_config() -> None:
    settings = Settings(
        ".env-missing",
        llm_base_url="https://llm.example.test/v1",
        llm_api_key="sk-test-SECRET",
        llm_model="test-model",
        llm_timeout_seconds=12,
    )

    built = LLMClientConfig.from_settings(settings)

    assert built.model == "test-model"
    assert built.timeout_seconds == 12
    assert built.api_key.get_secret_value() == "sk-test-SECRET"


def test_complete_parses_content_model_usage_and_request() -> None:
    captured: dict[str, Any] = {}

    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["headers"] = {key.lower(): value for key, value in request.headers.items()}
        captured["timeout"] = timeout
        return FakeResponse(completion_body("hello"))

    completion = OpenAICompatibleLLMClient(config(), opener=opener).complete(
        [{"role": "user", "content": "hi"}]
    )

    assert (completion.content, completion.model) == ("hello", "test-model")
    assert (completion.prompt_tokens, completion.completion_tokens) == (11, 7)
    assert captured["url"] == "https://llm.example.test/v1/chat/completions"
    assert captured["body"]["temperature"] == 0
    assert captured["body"]["messages"] == [{"role": "user", "content": "hi"}]
    assert captured["headers"]["authorization"].startswith("Bearer ")
    assert captured["timeout"] == 5.0


def test_client_satisfies_the_protocol() -> None:
    assert isinstance(client_returning(completion_body()), LLMClient)


def test_usage_is_none_when_not_reported() -> None:
    body = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}}]})

    completion = client_returning(body).complete([{"role": "user", "content": "hi"}])

    assert completion.prompt_tokens is None
    assert completion.completion_tokens is None


def test_timeout_raises_timeout_error() -> None:
    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        raise socket.timeout("timed out")

    with pytest.raises(LLMTimeoutError):
        OpenAICompatibleLLMClient(config(), opener=opener).complete(
            [{"role": "user", "content": "hi"}]
        )


def test_url_error_with_timeout_reason_is_a_timeout() -> None:
    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        raise urllib.error.URLError(socket.timeout("slow"))

    with pytest.raises(LLMTimeoutError):
        OpenAICompatibleLLMClient(config(), opener=opener).complete(
            [{"role": "user", "content": "hi"}]
        )


def test_network_error_is_sanitized() -> None:
    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        raise urllib.error.URLError(ConnectionResetError("reset"))

    with pytest.raises(LLMClientError) as exc_info:
        OpenAICompatibleLLMClient(config(), opener=opener).complete(
            [{"role": "user", "content": "hi"}]
        )

    assert "ConnectionResetError" in str(exc_info.value)
    assert "sk-test-SECRET" not in str(exc_info.value)


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_http_errors_report_the_status(status: int) -> None:
    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        raise urllib.error.HTTPError(request.full_url, status, "server error", {}, None)

    with pytest.raises(LLMHTTPError) as exc_info:
        OpenAICompatibleLLMClient(config(), opener=opener).complete(
            [{"role": "user", "content": "hi"}]
        )

    assert exc_info.value.status_code == status
    assert "sk-test-SECRET" not in str(exc_info.value)


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors_are_distinguished(status: int) -> None:
    def opener(request: Any, timeout: float | None = None) -> FakeResponse:
        raise urllib.error.HTTPError(request.full_url, status, "unauthorized", {}, None)

    with pytest.raises(LLMAuthenticationError) as exc_info:
        OpenAICompatibleLLMClient(config(), opener=opener).complete(
            [{"role": "user", "content": "hi"}]
        )

    assert exc_info.value.status_code == status


@pytest.mark.parametrize(
    "body",
    [
        "not json at all",
        json.dumps({"choices": []}),
        json.dumps({"choices": [{"message": {"content": ""}}]}),
        json.dumps({"choices": [{"message": {}}]}),
        json.dumps(["not", "an", "object"]),
    ],
)
def test_unusable_bodies_raise_response_errors(body: str) -> None:
    with pytest.raises(LLMResponseError):
        client_returning(body).complete([{"role": "user", "content": "hi"}])


def test_oversized_response_is_rejected() -> None:
    huge = json.dumps({"choices": [{"message": {"content": "x" * 500_000}}]})

    with pytest.raises(LLMResponseError, match="maximum accepted size"):
        client_returning(huge).complete([{"role": "user", "content": "hi"}])
