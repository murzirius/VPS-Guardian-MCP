"""Cooperative resource budgets for small VPS instances."""

from __future__ import annotations

from typing import Any, Dict

import psutil


def get_runtime_budget() -> Dict[str, Any]:
    """Return conservative limits based on immediately available host resources."""
    memory = psutil.virtual_memory()
    cores = psutil.cpu_count(logical=True) or 1
    constrained = memory.available < 512 * 1024 * 1024 or cores <= 1
    critical = memory.available < 256 * 1024 * 1024
    return {
        "status": "ok",
        "profile": "critical" if critical else "constrained" if constrained else "standard",
        "available_memory_bytes": memory.available,
        "available_memory_percent": round(memory.available / max(memory.total, 1) * 100, 1),
        "logical_cpu_cores": cores,
        "limits": {
            "http_response_bytes": 64 * 1024 if constrained else 256 * 1024,
            "directory_items": 1000 if constrained else 5000,
            "journal_lines": 150 if constrained else 500,
            "changeset_files": 2 if constrained else 3,
            "changeset_total_bytes": 200_000 if constrained else 400_000,
        },
        "background_workers": 0,
        "note": "VPS-Guardian uses on-demand, bounded checks and does not start background polling workers.",
    }


def is_constrained() -> bool:
    return get_runtime_budget()["profile"] != "standard"
