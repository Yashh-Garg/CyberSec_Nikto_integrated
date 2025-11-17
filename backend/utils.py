"""
Shared utility helpers for the backend.
"""

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """
    Return the current UTC time as an ISO 8601 string.
    """
    return datetime.now(timezone.utc).isoformat()


__all__ = ["utc_now_iso"]


