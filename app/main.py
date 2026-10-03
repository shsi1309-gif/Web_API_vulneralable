"""
FastAPI Main Application Entry Point.
Serves the REST API backend and the Modern Cyber Security Web SPA Dashboard.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import settings
from .database import init_db
from .api import (
    scans_router,
    vulnerabilities_router,
    endpoints_router,
    templates_router,
    reports_router,
    system_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Automated Web Application & REST API Vulnerability Scanner with Nuclei Integration and OWASP Top 10 Auditing.",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under /api
app.include_router(scans_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(endpoints_router, prefix="/api")
app.include_router(templates_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(system_router, prefix="/api")

# Mount Static Files for Dashboard SPA
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
def serve_spa():
    """Serves the main single page cyber dashboard."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Scanner API is running. Dashboard static files not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
