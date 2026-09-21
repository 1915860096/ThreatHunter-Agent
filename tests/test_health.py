"""Smoke tests for the FastAPI application skeleton."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_http_200() -> None:
    response = client.get("/health")

    assert response.status_code == 200


def test_health_reports_status_ok() -> None:
    payload = client.get("/health").json()

    assert payload["status"] == "ok"


def test_health_reports_service_name() -> None:
    payload = client.get("/health").json()

    assert payload["service"] == "threathunter-agent"


def test_health_reports_version() -> None:
    payload = client.get("/health").json()

    assert payload["version"] == "0.1.0"


def test_health_payload_matches_contract() -> None:
    payload = client.get("/health").json()

    assert payload == {
        "status": "ok",
        "service": "threathunter-agent",
        "version": "0.1.0",
    }
