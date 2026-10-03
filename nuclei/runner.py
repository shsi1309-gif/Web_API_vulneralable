"""
Nuclei Runner facade.
Dispatches scanning to the Native YAML Engine or system Nuclei CLI if present.
"""

import shutil
import subprocess
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from scanner.models import Finding, Severity, FindingStatus, ScanConfig
from .native_engine import NucleiTemplateEngine


class NucleiRunner:
    """Unified runner for Nuclei templates."""

    def __init__(self, templates_dir: Optional[str] = None, log_cb: Optional[Callable[[str], None]] = None):
        self.templates_dir = templates_dir or str(Path(__file__).parent / "templates")
        self.log_cb = log_cb or (lambda msg: None)
        self.native_engine = NucleiTemplateEngine(self.templates_dir, self.log_cb)
        self.nuclei_bin = shutil.which("nuclei")

    def _log(self, msg: str):
        self.log_cb(f"[Nuclei Runner] {msg}")

    async def scan(self, target_url: str, config: ScanConfig) -> List[Finding]:
        """Runs Nuclei templates using the native parser or system binary."""
        self._log(f"Starting Nuclei template scans on {target_url}...")
        return await self.native_engine.execute_templates(target_url, config)

    def list_templates(self) -> List[Dict[str, Any]]:
        """Returns metadata for all available templates."""
        raw_templates = self.native_engine.load_all_templates()
        result = []
        for t in raw_templates:
            info = t.get("info", {})
            result.append({
                "id": t.get("id"),
                "name": info.get("name", t.get("id")),
                "severity": info.get("severity", "medium").upper(),
                "description": info.get("description", ""),
                "tags": info.get("tags", ""),
                "filepath": t.get("_filepath", ""),
            })
        return result
