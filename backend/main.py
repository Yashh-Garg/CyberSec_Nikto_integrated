"""FastAPI application for CyberSec AI Assistant."""

import asyncio
import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

from nikto_scanner import NiktoScanner
from zap_scanner import ZapScanner
from nuclei_scanner import NucleiScanner
from wapiti_scanner import WapitiScanner
from utils.parser import normalize_results
from utils.analytics import ScanAnalytics
from utils.file_manager import FileManager

# Ensure logs directory exists
logs_dir = Path("logs")
logs_dir.mkdir(exist_ok=True)
log_file = logs_dir / "app.log"

# Configure logging with absolute path
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_file.absolute()), mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True  # Override any existing configuration
)
logger = logging.getLogger(__name__)
logger.info(f"Logging initialized. Log file: {log_file.absolute()}")

# Get local timezone (IST for Kolkata: UTC+5:30)
# This will use system timezone or default to IST
def get_local_time():
    """Get current time in local timezone (IST/Kolkata)."""
    try:
        # Try to get system timezone
        import time
        local_tz = datetime.now().astimezone().tzinfo
        return datetime.now(local_tz)
    except:
        # Default to IST (UTC+5:30) if system timezone not available
        ist = timezone(timedelta(hours=5, minutes=30))
        return datetime.now(ist)

# Initialize FastAPI app
app = FastAPI(
    title="CyberSec AI Assistant",
    description="Vulnerability scanning platform with AI-powered analysis",
    version="1.0.0"
)

# CORS middleware for React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],  # Vite default ports and common alternatives
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Note: React app serving is added at the end, after all API routes

# In-memory storage for scan jobs (replace with DB in production)
scan_jobs: Dict[str, Dict] = {}

# File manager for persisting scan results
file_manager = FileManager()

# Initialize scanners lazily (only when needed)
_scanner_instances: Dict[str, any] = {}

def get_scanner(scan_type: str = "nikto"):
    """Get or create scanner instance based on scan type.
    
    Args:
        scan_type: Type of scanner ('nikto' or 'zap')
        
    Returns:
        Scanner instance (NiktoScanner or ZapScanner)
    """
    global _scanner_instances
    
    if scan_type not in _scanner_instances:
        try:
            scan_type_lower = scan_type.lower()
            if scan_type_lower == "zap":
                _scanner_instances[scan_type] = ZapScanner()
            elif scan_type_lower == "nuclei":
                _scanner_instances[scan_type] = NucleiScanner()
            elif scan_type_lower == "wapiti":
                _scanner_instances[scan_type] = WapitiScanner()
            else:  # Default to nikto
                _scanner_instances[scan_type] = NiktoScanner()
        except Exception as e:
            logger.error(f"Failed to initialize {scan_type} scanner: {e}", exc_info=True)
            error_detail = str(e)
            # Provide helpful Windows-specific instructions
            if "Cannot connect to Docker" in error_detail or "Docker connection failed" in error_detail:
                error_detail += (
                    "\n\nFor Windows users:\n"
                    "1. Enable 'Expose daemon on tcp://localhost:2375' in Docker Desktop Settings\n"
                    "2. Use: docker-compose -f docker-compose.windows.yml up -d --build\n"
                    "Or enable WSL2 backend in Docker Desktop settings."
                )
            raise HTTPException(
                status_code=503,
                detail=error_detail
            )
    return _scanner_instances[scan_type]


# Pydantic models
class ScanRequest(BaseModel):
    """Scan request model."""
    target: str = Field(..., description="Target hostname or IP address")
    port: int = Field(80, ge=1, le=65535, description="Target port")
    ssl: bool = Field(False, description="Use SSL/TLS")
    scan_type: str = Field("nikto", description="Scanner type")
    options: Optional[List[str]] = Field(None, description="Additional scanner options (e.g., ['-Tuning', '49'] for SQL injection and authentication bypass)")
    scan_mode: Optional[str] = Field(None, description="Scan mode: 'all' or 'selective'")
    selected_scans: Optional[List[str]] = Field(None, description="Selected scan types for selective mode")
    
    @validator('target')
    def validate_target(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Target cannot be empty")
        return v.strip()


class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str
    status: str
    target: str
    created_at: str
    message: str


class ScanStatus(BaseModel):
    """Scan status model."""
    scan_id: str
    status: str  # pending, running, completed, failed
    target: str
    port: int
    ssl: bool
    created_at: str
    completed_at: Optional[str] = None
    findings_count: Optional[int] = None
    results: Optional[Dict] = None
    error: Optional[str] = None


# Background task
async def run_scan(scan_id: str, request: ScanRequest):
    """Execute scan in background."""
    try:
        # Update status to running
        scan_jobs[scan_id]["status"] = "running"
        scan_jobs[scan_id]["started_at"] = get_local_time().isoformat()
        
        logger.info(f"Starting scan {scan_id} for {request.target}:{request.port}")
        
        # Build options from request
        scan_options = request.options or []
        
        # If selective mode with selected scans, build tuning options (only for Nikto)
        if request.scan_type == 'nikto' and request.scan_mode == 'selective' and request.selected_scans:
            # Combine selected scan types into tuning string
            tuning_string = ''.join(request.selected_scans)
            if tuning_string:
                scan_options.extend(['-Tuning', tuning_string])
        
        # Run scan (blocking operation in thread pool)
        loop = asyncio.get_event_loop()
        scanner_instance = get_scanner(request.scan_type)
        scan_result = await loop.run_in_executor(
            None,
            lambda: scanner_instance.scan(
                target=request.target,
                port=request.port,
                ssl=request.ssl,
                options=scan_options if scan_options else None
            )
        )
        
        # Parse results
        logger.info(f"Parsing results for scanner type: '{request.scan_type}'")
        normalized_results = normalize_results(
            raw_output=scan_result["raw_output"],
            output_format=scan_result.get("output_format", "xml"),
            scanner=request.scan_type
        )
        
        # Calculate risk score
        risk_score = ScanAnalytics.calculate_risk_score(normalized_results.get("findings", []))
        
        # Save scan results to file
        scan_data = {
            "scan_id": scan_id,
            "target": request.target,
            "port": request.port,
            "ssl": request.ssl,
            "created_at": scan_jobs[scan_id]["created_at"],
            "completed_at": get_local_time().isoformat(),
            "findings_count": normalized_results["findings_count"],
            "results": normalized_results,
            "risk_score": risk_score,
            "raw_output": scan_result.get("raw_output", ""),
            "logs": scan_result.get("logs", ""),
            "log_events": scan_result.get("log_events", [])
        }
        
        try:
            results_file = file_manager.save_scan_results(scan_id, scan_data)
            logger.info(f"Scan results persisted to file: {results_file}")
        except Exception as e:
            logger.warning(f"Failed to save scan results to file: {e}")
        
        # Update job with results
        scan_jobs[scan_id].update({
            "status": "completed",
            "completed_at": get_local_time().isoformat(),
            "findings_count": normalized_results["findings_count"],
            "results": normalized_results,
            "raw_output": scan_result.get("raw_output", ""),
            "logs": scan_result.get("logs", ""),
            "log_events": scan_result.get("log_events", []),
            "risk_score": risk_score
        })
        
        logger.info(f"Scan {scan_id} completed with {normalized_results['findings_count']} findings")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan_jobs[scan_id].update({
            "status": "failed",
            "completed_at": get_local_time().isoformat(),
            "error": str(e)
        })


# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "cybersec-ai-assistant",
        "version": "1.0.0",
        "timestamp": get_local_time().isoformat()
    }


@app.post("/api/v1/scan", response_model=ScanResponse, status_code=202)
async def initiate_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Initiate a vulnerability scan."""
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Create job record
    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "target": request.target,
        "port": request.port,
        "ssl": request.ssl,
        "scan_type": request.scan_type,
        "created_at": get_local_time().isoformat()
    }
    
    # Add background task
    background_tasks.add_task(run_scan, scan_id, request)
    
    logger.info(f"Scan {scan_id} queued for {request.target}:{request.port}")
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        target=request.target,
        created_at=scan_jobs[scan_id]["created_at"],
        message="Scan initiated"
    )


@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get scan status and results."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    job = scan_jobs[scan_id]
    
    return ScanStatus(
        scan_id=job["scan_id"],
        status=job["status"],
        target=job["target"],
        port=job["port"],
        ssl=job["ssl"],
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        findings_count=job.get("findings_count"),
        results=job.get("results"),
        error=job.get("error")
    )


@app.get("/api/v1/scans")
async def list_scans():
    """List all scans."""
    return {
        "total": len(scan_jobs),
        "scans": [
            {
                "scan_id": job["scan_id"],
                "status": job["status"],
                "target": job["target"],
                "port": job["port"],
                "created_at": job["created_at"],
                "findings_count": job.get("findings_count")
            }
            for job in scan_jobs.values()
        ]
    }


@app.delete("/api/v1/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan record."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scan_jobs[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


@app.get("/api/v1/stats")
async def get_statistics():
    """Get platform statistics."""
    total_scans = len(scan_jobs)
    completed = sum(1 for job in scan_jobs.values() if job["status"] == "completed")
    failed = sum(1 for job in scan_jobs.values() if job["status"] == "failed")
    running = sum(1 for job in scan_jobs.values() if job["status"] == "running")
    pending = sum(1 for job in scan_jobs.values() if job["status"] == "pending")
    
    total_findings = sum(
        job.get("findings_count", 0)
        for job in scan_jobs.values()
        if job.get("findings_count")
    )
    
    # Calculate severity breakdown
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for job in scan_jobs.values():
        if job.get("results") and job.get("results").get("findings"):
            for finding in job["results"]["findings"]:
                severity = finding.get("severity", "LOW")
                if severity in severity_counts:
                    severity_counts[severity] += 1
    
    return {
        "total_scans": total_scans,
        "completed": completed,
        "failed": failed,
        "running": running,
        "pending": pending,
        "total_findings": total_findings,
        "success_rate": (completed / total_scans * 100) if total_scans > 0 else 0,
        "severity_breakdown": severity_counts
    }


@app.get("/api/v1/analytics", response_model=Dict)
async def get_analytics():
    """Get comprehensive analytics and insights."""
    # Convert scan_jobs to list format
    scans = []
    for scan_id, job in scan_jobs.items():
        scan_data = {
            "scan_id": scan_id,
            "status": job.get("status"),
            "target": job.get("target"),
            "port": job.get("port"),
            "created_at": job.get("created_at"),
            "completed_at": job.get("completed_at"),
            "findings_count": job.get("findings_count"),
            "results": job.get("results")
        }
        scans.append(scan_data)
    
    # Generate insights
    insights = ScanAnalytics.generate_insights(scans)
    
    return insights


@app.get("/api/v1/scans/files", response_model=Dict)
async def list_scan_files():
    """List all scan result files on disk."""
    summary = file_manager.get_scan_summary()
    return summary


@app.get("/api/v1/scan/{scan_id}/risk-score", response_model=Dict)
async def get_risk_score(scan_id: str):
    """Get risk score for a specific scan."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    job = scan_jobs[scan_id]
    if job.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    # Use stored risk score if available, otherwise calculate
    if "risk_score" in job:
        risk_score = job["risk_score"]
    else:
        findings = []
        if job.get("results") and job["results"].get("findings"):
            findings = job["results"]["findings"]
        risk_score = ScanAnalytics.calculate_risk_score(findings)
    
    return {
        "scan_id": scan_id,
        "target": job.get("target"),
        "risk_score": risk_score
    }


@app.get("/api/v1/scan/{scan_id}/export")
async def export_scan_results(
    scan_id: str,
    format: str = Query("json", regex="^(json|csv)$")
):
    """Export scan results in specified format."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    job = scan_jobs[scan_id]
    if job["status"] != "completed" or not job.get("results"):
        raise HTTPException(status_code=400, detail="Scan not completed or has no results")
    
    results = job["results"]
    findings = results.get("findings", [])
    
    if format == "json":
        export_data = {
            "scan_id": scan_id,
            "target": job["target"],
            "port": job["port"],
            "ssl": job["ssl"],
            "created_at": job["created_at"],
            "completed_at": job.get("completed_at"),
            "findings_count": len(findings),
            "findings": findings
        }
        return Response(
            content=json.dumps(export_data, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id}.json"
            }
        )
    
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "ID", "Severity", "Title", "Description", "URI", "Method",
            "CVE IDs", "OSVDB ID", "CVSS Score", "Scanner"
        ])
        
        # Write findings
        for finding in findings:
            writer.writerow([
                finding.get("id", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("uri", ""),
                finding.get("method", ""),
                ", ".join(finding.get("cve_ids", [])),
                finding.get("osvdb_id", ""),
                finding.get("cvss_score", ""),
                finding.get("scanner", "")
            ])
        
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"
            }
        )


# Serve React build files (for production) - MUST be last, after all API routes
static_path = Path("../frontend/dist")
if not static_path.exists():
    static_path = Path("./frontend/dist")  # Try relative path in Docker

if static_path.exists():
    # Serve static assets
    app.mount("/assets", StaticFiles(directory=str(static_path / "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        """Serve React app for all non-API routes."""
        # Don't serve API routes, docs, or openapi
        if full_path.startswith("api/") or full_path in ["docs", "openapi.json", "redoc"]:
            raise HTTPException(status_code=404)
        
        # Serve static files if they exist
        file_path = static_path / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        
        # Serve index.html for React Router (SPA)
        index_path = static_path / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        raise HTTPException(status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

