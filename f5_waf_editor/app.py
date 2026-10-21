"""
Main FastAPI web application for F5 WAF Policy Manager.
Serves both the REST API and the responsive single-page DevSecOps UI.
"""

from contextlib import asynccontextmanager
from pathlib import Path
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
import logging
from .storage import get_storage, get_logging_storage, get_custom_signatures_storage, init_github_storage
from .storage.github_service import is_github_configured, pull_from_github
from .storage.clickhouse_service import get_clickhouse_service
from .api.routes import router as api_router
from .api.logging_routes import router as logging_router
from .api.custom_signatures_routes import router as custom_sigs_router
from .api.clickhouse_routes import router as clickhouse_router

logger = logging.getLogger("f5_waf_editor.app")

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize primary storage (Redis / Memory fallback)
    pol_store = get_storage()
    log_store = get_logging_storage()
    custom_store = get_custom_signatures_storage()

    # Load persisted ClickHouse configuration from Redis if present
    try:
        get_clickhouse_service().load_config_from_redis()
    except Exception as exc:
        logger.debug("ClickHouse config load on startup skipped: %s", exc)

    # If GitHub is configured, initialize GitHub GitOps storage
    if is_github_configured() or settings.storage_backend == "github":
        try:
            logger.info("GitHub is configured; initializing GitHub GitOps storage...")
            init_github_storage(auto_pull=True)
            logger.info("GitHub GitOps storage initialized.")
        except Exception as exc:
            logger.warning("Failed to initialize GitHub storage on startup: %s", exc)

    yield

    # Shutdown logic if needed


from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI(
    title="F5 WAF Policy Manager for NGINX",
    description="Comprehensive management and editing UI for F5 WAF for NGINX policies backed by Redis",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable response compression for large JSON payloads
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include API routes
app.include_router(api_router)
app.include_router(logging_router)
app.include_router(custom_sigs_router)
app.include_router(clickhouse_router)


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Serve the single-page application dashboard and editor."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"version": "1.0.0"},
    )


def start():
    """CLI launcher entrypoint."""
    uvicorn.run(
        "f5_waf_editor.app:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_debug,
    )


if __name__ == "__main__":
    start()
