"""
FastAPI API routers package.
"""

from .scans import router as scans_router
from .vulnerabilities import router as vulnerabilities_router
from .endpoints import router as endpoints_router
from .templates import router as templates_router
from .reports import router as reports_router
from .system import router as system_router

__all__ = [
    "scans_router",
    "vulnerabilities_router",
    "endpoints_router",
    "templates_router",
    "reports_router",
    "system_router",
]
