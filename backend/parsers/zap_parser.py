"""
Parser for OWASP ZAP JSON output.

This module reads a ZAP JSON report and converts findings into a simple
intermediate representation that will be normalized later.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any


def parse_zap_output(path: Path, target_url: str) -> List[Dict[str, Any]]:
    """
    Parse ZAP JSON output file and return a list of raw findings.
    """
    if not path.is_file():
        return []

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = data.get("site", [])
    findings: List[Dict[str, Any]] = []

    # ZAP formats can vary; this parser is intentionally defensive.
    for site in alerts:
        for alert in site.get("alerts", []):
            item = {
                "host": site.get("host", ""),
                "target_url": target_url,
                "name": alert.get("name", ""),
                "risk": alert.get("risk", ""),
                "severity": alert.get("risk", ""),
                "description": alert.get("desc", ""),
                "solution": alert.get("solution", ""),
                "evidence": ", ".join(
                    e.get("evidence", "") for e in alert.get("instances", [])
                ),
                "reference": alert.get("reference", ""),
                "plugin_id": alert.get("pluginId", ""),
                "confidence": alert.get("confidence", ""),
                "tool": "zap",
            }
            findings.append(item)

    return findings


__all__ = ["parse_zap_output"]


