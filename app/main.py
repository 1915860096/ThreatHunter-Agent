"""FastAPI application entrypoint."""

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.schemas.health import HealthResponse


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the FastAPI application."""
    settings = settings or get_settings()
    application = FastAPI(title=settings.app_name, version=settings.app_version)

    @application.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
        summary="Service health check",
    )
    def health() -> HealthResponse:
        """Report service liveness together with the configured name and version."""
        return HealthResponse(
            status="ok",
            service=settings.app_name,
            version=settings.app_version,
        )

    return application


app: FastAPI = create_app()
