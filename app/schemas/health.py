"""Response models for the health endpoint."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Payload returned by ``GET /health``."""

    status: str
    service: str
    version: str
