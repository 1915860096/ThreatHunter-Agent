"""OpenAI-compatible Chat Completions client (standard library only).

The client is intentionally minimal: an injectable :class:`LLMClient` protocol
plus one HTTP adapter that speaks the widely supported ``/chat/completions``
shape. It does not depend on an SDK, on provider-specific function calling or on
JSON-schema response modes, and the API key is held as a ``SecretStr`` so it
cannot leak through ``repr``, logs or error messages.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, Field, SecretStr, model_validator

from app.core.config import Settings

CHAT_COMPLETIONS_PATH: Final[str] = "/chat/completions"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
MAX_RESPONSE_CHARACTERS: Final[int] = 200_000


class LLMClientError(Exception):
    """Base class for sanitized LLM client failures (never contains the API key)."""


class LLMConfigurationError(LLMClientError):
    """The client cannot be built from the current configuration."""


class LLMTimeoutError(LLMClientError):
    """The provider did not answer within the configured timeout."""


class LLMHTTPError(LLMClientError):
    """The provider answered with a non-success HTTP status."""

    def __init__(self, status_code: int, reason: str) -> None:
        super().__init__(f"LLM request failed with HTTP {status_code}: {reason}")
        self.status_code = status_code


class LLMAuthenticationError(LLMHTTPError):
    """Authentication with the provider failed (401/403)."""


class LLMResponseError(LLMClientError):
    """The provider response was unusable (malformed, empty or oversized)."""


class LLMCompletion(BaseModel):
    """One model completion.

    Token usage is ``None`` when the provider does not report it - it is never
    estimated.
    """

    content: str
    model: str
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal completion interface the LLM planner depends on."""

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMCompletion:
        """Return one completion for ``messages``."""


class LLMClientConfig(BaseModel):
    """Connection settings for the OpenAI-compatible adapter."""

    base_url: str
    api_key: SecretStr
    model: str
    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=1.0)

    @model_validator(mode="after")
    def _validate_values(self) -> "LLMClientConfig":
        for name, value in (
            ("base_url", self.base_url),
            ("model", self.model),
            ("api_key", self.api_key.get_secret_value()),
        ):
            if not value.strip():
                raise ValueError(f"{name} must not be empty")
        self.base_url = self.base_url.strip().rstrip("/")
        self.model = self.model.strip()
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> "LLMClientConfig":
        """Build the config from project settings, or fail with the missing names."""
        values = {
            "LLM_BASE_URL": (settings.llm_base_url or "").strip(),
            "LLM_API_KEY": (settings.llm_api_key or "").strip(),
            "LLM_MODEL": (settings.llm_model or "").strip(),
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise LLMConfigurationError(
                "missing LLM configuration: " + ", ".join(missing)
            )
        return cls(
            base_url=values["LLM_BASE_URL"],
            api_key=values["LLM_API_KEY"],
            model=values["LLM_MODEL"],
            timeout_seconds=settings.llm_timeout_seconds,
        )


def _extract_content(payload: Any) -> str:
    """Return ``choices[0].message.content`` or raise a sanitized response error."""
    if not isinstance(payload, dict):
        raise LLMResponseError("response body is not a JSON object")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMResponseError("response contains no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise LLMResponseError("response contains no message content")
    return content


def _usage_value(payload: dict[str, Any], key: str) -> int | None:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    value = usage.get(key)
    return value if isinstance(value, int) and value >= 0 else None


class OpenAICompatibleLLMClient:
    """Chat Completions adapter built on :mod:`urllib`."""

    def __init__(
        self,
        config: LLMClientConfig,
        *,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._opener = opener or urllib.request.urlopen

    @property
    def config(self) -> LLMClientConfig:
        """Connection settings (the key stays a ``SecretStr``)."""
        return self._config

    @property
    def model(self) -> str:
        """Configured model name."""
        return self._config.model

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMCompletion:
        """POST ``messages`` to ``<base_url>/chat/completions``."""
        model_name = (model or self._config.model).strip()
        body = json.dumps(
            {
                "model": model_name,
                "temperature": 0,
                "messages": [dict(message) for message in messages],
            }
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - fixed https endpoint from config
            url=f"{self._config.base_url}{CHAT_COMPLETIONS_PATH}",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._config.api_key.get_secret_value()}",
            },
        )
        timeout = timeout_seconds or self._config.timeout_seconds

        try:
            with self._opener(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            reason = str(getattr(exc, "reason", "") or "").strip() or "request rejected"
            if exc.code in (401, 403):
                raise LLMAuthenticationError(exc.code, reason) from exc
            raise LLMHTTPError(exc.code, reason) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise LLMTimeoutError(f"LLM request timed out after {timeout} seconds") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise LLMTimeoutError(
                    f"LLM request timed out after {timeout} seconds"
                ) from exc
            raise LLMClientError(
                f"LLM request failed: {type(exc.reason).__name__}"
            ) from exc

        if len(raw) > MAX_RESPONSE_CHARACTERS:
            raise LLMResponseError("response exceeds the maximum accepted size")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMResponseError("response body is not valid JSON") from exc

        return LLMCompletion(
            content=_extract_content(payload),
            model=str(payload.get("model") or model_name),
            prompt_tokens=_usage_value(payload, "prompt_tokens"),
            completion_tokens=_usage_value(payload, "completion_tokens"),
        )
