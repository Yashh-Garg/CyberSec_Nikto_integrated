"""
FastAPI backend server for orchestrating local web security scans.

Exposes endpoints:
- POST /api/scan
- GET  /api/scan/{scan_id}/status
- GET  /api/scan/{scan_id}/results
- GET  /download/{scan_id}/{filename}
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Any
from uuid import uuid4
from pathlib import Path

from .run_scans import (
    start_scan,
    get_scan_status,
    get_scan_results,
    REPORTS_DIR,
)


class ScanRequest(BaseModel):
    """Request body for starting a new scan."""

    target: HttpUrl
    tools: List[str]


app = FastAPI(title="Local Web Security Scanner API")

# Allow local development origins (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/scan")
def api_start_scan(payload: ScanRequest) -> Dict[str, Any]:
    """
    Start a new scan and return a unique scan_id.
    """
    scan_id = str(uuid4())
    try:
        start_scan(scan_id=scan_id, target=str(payload.target), tools=payload.tools)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}/status")
def api_scan_status(scan_id: str) -> Dict[str, Any]:
    """
    Get current scan status and logs.
    """
    status = get_scan_status(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status


@app.get("/api/scan/{scan_id}/results")
def api_scan_results(scan_id: str) -> Dict[str, Any]:
    """
    Fetch normalized and enriched scan results and report file links.
    """
    results = get_scan_results(scan_id)
    if results is None:
        raise HTTPException(status_code=404, detail="Scan not found or not completed")
    return results


@app.get("/download/{scan_id}/{filename}")
def download_report(scan_id: str, filename: str):
    """
    Serve generated report files (JSON, HTML, PDF, etc.).
    """
    scan_dir = REPORTS_DIR / scan_id
    file_path = scan_dir / filename

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(path=str(file_path), filename=filename)


@app.get("/health")
def healthcheck() -> Dict[str, str]:
    """
    Simple healthcheck endpoint for local debugging.
    """
    return {"status": "ok"}


