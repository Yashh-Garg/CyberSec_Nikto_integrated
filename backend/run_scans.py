"""
Scan orchestration module.

Responsibilities:
- Start scans for ZAP / Nuclei / Wapiti using Docker.
- Track scan status and logs in memory (per process).
- Store raw scanner outputs in backend/scanners/output/.
- Trigger parsing, normalization, enrichment, and report generation.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from .parsers.zap_parser import parse_zap_output
from .parsers.nuclei_parser import parse_nuclei_output
from .parsers.wapiti_parser import parse_wapiti_output
from .parsers.normalize import normalize_findings
from .parsers.enrich import enrich_findings
from .reports.generator import generate_reports

BASE_DIR = Path(__file__).resolve().parent
SCANNERS_OUTPUT_DIR = BASE_DIR / "scanners" / "output"
REPORTS_DIR = BASE_DIR / "reports"

SCANNERS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory status store (for local development)
_scan_status: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def _run_docker_command(cmd: List[str], log_prefix: str, scan_id: str) -> int:
    """
    Run a Docker command and stream logs into the status store.
    """
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    assert process.stdout is not None  # for type checkers
    for line in process.stdout:
        _append_log(scan_id, f"[{log_prefix}] {line.strip()}")

    return process.wait()


def _append_log(scan_id: str, message: str) -> None:
    """Append a log message to the in-memory log for a given scan_id."""
    with _lock:
        state = _scan_status.setdefault(
            scan_id,
            {"status": "started", "logs": [], "tools": [], "target": "", "error": None},
        )
        state["logs"].append(message)


def start_scan(scan_id: str, target: str, tools: List[str]) -> None:
    """
    Start the requested scanners in a background thread.
    """
    supported_tools = {"zap", "nuclei", "wapiti"}
    if not tools:
        raise ValueError("At least one tool must be selected")
    if not set(tools).issubset(supported_tools):
        raise ValueError(f"Tools must be subset of {supported_tools}")

    with _lock:
        _scan_status[scan_id] = {
            "status": "running",
            "logs": [f"Starting scan for {target} with tools: {', '.join(tools)}"],
            "tools": tools,
            "target": target,
            "error": None,
        }

    thread = threading.Thread(
        target=_scan_worker, args=(scan_id, target, tools), daemon=True
    )
    thread.start()


def _scan_worker(scan_id: str, target: str, tools: List[str]) -> None:
    """
    Worker function that runs in a separate thread for each scan.
    """
    try:
        scan_dir = REPORTS_DIR / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        raw_files: Dict[str, Path] = {}

        # Run tools sequentially for simplicity; could be parallelized later.
        if "zap" in tools:
            zap_output = SCANNERS_OUTPUT_DIR / f"{scan_id}_zap.json"
            cmd = [
                "docker",
                "compose",
                "run",
                "--rm",
                "-e",
                f"TARGET={target}",
                "-e",
                f"OUTPUT_FILE=/output/{zap_output.name}",
                "zap",
            ]
            _append_log(scan_id, "Running ZAP scanner...")
            exit_code = _run_docker_command(cmd, "ZAP", scan_id)
            if exit_code == 0 and zap_output.exists():
                raw_files["zap"] = zap_output
            else:
                _append_log(scan_id, "ZAP scanner failed or output not found.")

        if "nuclei" in tools:
            nuclei_output = SCANNERS_OUTPUT_DIR / f"{scan_id}_nuclei.json"
            cmd = [
                "docker",
                "compose",
                "run",
                "--rm",
                "-e",
                f"TARGET={target}",
                "-e",
                f"OUTPUT_FILE=/output/{nuclei_output.name}",
                "nuclei",
            ]
            _append_log(scan_id, "Running Nuclei scanner...")
            exit_code = _run_docker_command(cmd, "NUCLEI", scan_id)
            if exit_code == 0 and nuclei_output.exists():
                raw_files["nuclei"] = nuclei_output
            else:
                _append_log(scan_id, "Nuclei scanner failed or output not found.")

        if "wapiti" in tools:
            wapiti_output = SCANNERS_OUTPUT_DIR / f"{scan_id}_wapiti.json"
            cmd = [
                "docker",
                "compose",
                "run",
                "--rm",
                "-e",
                f"TARGET={target}",
                "-e",
                f"OUTPUT_FILE=/output/{wapiti_output.name}",
                "wapiti",
            ]
            _append_log(scan_id, "Running Wapiti scanner...")
            exit_code = _run_docker_command(cmd, "WAPITI", scan_id)
            if exit_code == 0 and wapiti_output.exists():
                raw_files["wapiti"] = wapiti_output
            else:
                _append_log(scan_id, "Wapiti scanner failed or output not found.")

        # Parse individual outputs
        all_findings = []
        if "zap" in raw_files:
            all_findings.extend(parse_zap_output(raw_files["zap"], target))
        if "nuclei" in raw_files:
            all_findings.extend(parse_nuclei_output(raw_files["nuclei"], target))
        if "wapiti" in raw_files:
            all_findings.extend(parse_wapiti_output(raw_files["wapiti"], target))

        _append_log(scan_id, f"Parsed {len(all_findings)} raw findings from tools.")

        normalized = [normalize_findings(f) for f in all_findings]
        enriched = enrich_findings(normalized)

        # Generate reports (JSON, enriched JSON, HTML, PDF)
        generate_reports(scan_id=scan_id, target=target, findings=normalized, enriched_findings=enriched)

        with _lock:
            _scan_status[scan_id]["status"] = "completed"
            _scan_status[scan_id]["normalized_count"] = len(normalized)
            _scan_status[scan_id]["enriched_count"] = len(enriched)
        _append_log(scan_id, "Scan completed and reports generated.")
    except Exception as exc:  # pragma: no cover - defensive
        with _lock:
            state = _scan_status.setdefault(
                scan_id,
                {"status": "error", "logs": [], "tools": tools, "target": target},
            )
        state["status"] = "error"
        state["error"] = str(exc)
        _append_log(scan_id, f"Scan failed: {exc}")


def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Return the current status and logs for a scan_id.
    """
    with _lock:
        state = _scan_status.get(scan_id)
        if state is None:
            return None
        # Return a shallow copy to avoid external mutation
        return dict(state)


def get_scan_results(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Return metadata about generated reports for a given scan.
    """
    with _lock:
        state = _scan_status.get(scan_id)
        if state is None or state.get("status") != "completed":
            return None
        target = state.get("target", "")

    scan_dir = REPORTS_DIR / scan_id
    report_json = scan_dir / "report.json"
    report_enriched_json = scan_dir / "report_enriched.json"
    report_html = scan_dir / "report.html"
    report_pdf = scan_dir / "report.pdf"

    files = {
        "json": report_json.name if report_json.exists() else None,
        "enriched_json": report_enriched_json.name
        if report_enriched_json.exists()
        else None,
        "html": report_html.name if report_html.exists() else None,
        "pdf": report_pdf.name if report_pdf.exists() else None,
    }

    return {
        "scan_id": scan_id,
        "target": target,
        "status": "completed",
        "files": files,
    }


__all__ = [
    "start_scan",
    "get_scan_status",
    "get_scan_results",
    "SCANNERS_OUTPUT_DIR",
    "REPORTS_DIR",
]


