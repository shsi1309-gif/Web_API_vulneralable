"""
Built-in Security Checks module.
"""

from .base import BaseCheck
from .headers import SecurityHeadersCheck
from .sensitive_files import SensitiveFilesCheck
from .injection_sqli import SQLInjectionCheck
from .injection_xss import XSSInjectionCheck
from .open_redirect import OpenRedirectCheck
from .path_traversal import PathTraversalCheck
from .api_security import APISecurityCheck

ALL_CHECKS = [
    SecurityHeadersCheck,
    SensitiveFilesCheck,
    SQLInjectionCheck,
    XSSInjectionCheck,
    OpenRedirectCheck,
    PathTraversalCheck,
    APISecurityCheck,
]

__all__ = [
    "BaseCheck",
    "SecurityHeadersCheck",
    "SensitiveFilesCheck",
    "SQLInjectionCheck",
    "XSSInjectionCheck",
    "OpenRedirectCheck",
    "PathTraversalCheck",
    "APISecurityCheck",
    "ALL_CHECKS",
]
