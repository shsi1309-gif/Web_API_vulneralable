"""
Endpoint Inventory API: Discover and explore crawled endpoints and API definitions.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import EndpointModel
from ..schemas import EndpointResponse

router = APIRouter(prefix="/endpoints", tags=["Endpoints"])


@router.get("", response_model=List[EndpointResponse])
def list_endpoints(
    scan_id: Optional[str] = None,
    source: Optional[str] = None,
    method: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Lists discovered endpoints and parameters across scans."""
    query = db.query(EndpointModel)
    if scan_id:
        query = query.filter(EndpointModel.scan_id == scan_id)
    if source:
        query = query.filter(EndpointModel.source == source)
    if method:
        query = query.filter(EndpointModel.method == method.upper())

    endpoints = query.order_by(EndpointModel.discovered_at.desc()).offset(offset).limit(limit).all()

    result = []
    for ep in endpoints:
        result.append(
            EndpointResponse(
                id=ep.id,
                scan_id=ep.scan_id,
                url=ep.url,
                method=ep.method,
                status_code=ep.status_code,
                content_type=ep.content_type,
                parameters=json.loads(ep.parameters_json or "[]"),
                source=ep.source,
                discovered_at=ep.discovered_at,
            )
        )
    return result
