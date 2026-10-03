"""
Template Studio API: Manage and test Nuclei YAML security templates.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import yaml

from nuclei.runner import NucleiRunner
from scanner.models import ScanConfig

router = APIRouter(prefix="/templates", tags=["Templates"])
runner = NucleiRunner()


class TemplateTestRequest(BaseModel):
    target_url: str
    yaml_content: str


@router.get("")
def list_templates():
    """Lists all available Nuclei security templates."""
    return {"templates": runner.list_templates()}


@router.post("/test")
async def test_custom_template(req: TemplateTestRequest):
    """Parses and executes custom Nuclei YAML template against target in real-time."""
    try:
        doc = yaml.safe_load(req.yaml_content)
        if not isinstance(doc, dict) or "id" not in doc:
            raise HTTPException(status_code=400, detail="Invalid Nuclei template: Missing 'id' or invalid YAML root.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YAML Parse Error: {str(e)}")

    config = ScanConfig(target_url=req.target_url)
    findings = await runner.native_engine.execute_templates(req.target_url, config, templates=[doc])

    return {
        "matched": len(findings) > 0,
        "findings_count": len(findings),
        "findings": [f.model_dump() for f in findings],
    }
