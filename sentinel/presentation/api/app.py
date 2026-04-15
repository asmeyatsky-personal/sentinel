"""
SENTINEL™ FastAPI Application

Presentation layer — only interacts with application layer via use cases.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel.infrastructure.config.dependency_injection import Container, create_container
from sentinel.presentation.api.recon_controller import create_recon_router
from sentinel.presentation.api.detect_controller import create_detect_router
from sentinel.presentation.api.shield_controller import create_shield_router
from sentinel.presentation.api.intercept_controller import create_intercept_router
from sentinel.presentation.api.contain_controller import create_contain_router
from sentinel.presentation.api.signal_controller import create_signal_router

_container: Container | None = None


def get_container() -> Container:
    assert _container is not None, "Container not initialized"
    return _container


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _container
    _container = create_container()
    yield
    _container = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="SENTINEL™",
        description="Agentic Security Platform — Security control plane for autonomous agent systems",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.include_router(create_recon_router(get_container), prefix="/api/v1/recon", tags=["RECON"])
    app.include_router(create_detect_router(get_container), prefix="/api/v1/detect", tags=["DETECT"])
    app.include_router(create_shield_router(get_container), prefix="/api/v1/shield", tags=["SHIELD"])
    app.include_router(
        create_intercept_router(get_container), prefix="/api/v1/intercept", tags=["INTERCEPT"]
    )
    app.include_router(
        create_contain_router(get_container), prefix="/api/v1/contain", tags=["CONTAIN"]
    )
    app.include_router(
        create_signal_router(get_container), prefix="/api/v1/signal", tags=["SIGNAL"]
    )

    @app.get("/health")
    async def health():
        return {"status": "operational", "product": "SENTINEL™", "version": "1.0.0"}

    return app


app = create_app()
