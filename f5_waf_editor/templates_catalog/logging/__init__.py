"""
Built-in F5 WAF for NGINX Logging Profiles Catalog.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGING_TEMPLATES_DIR = Path(__file__).parent

LOGGING_TEMPLATE_METADATA = [
    {
        "id": "log_default",
        "name": "Default (Illegal Requests)",
        "file": "log_default.json",
        "format": "default",
        "request_type": "illegal",
        "description": "Standard built-in F5 logging profile. Logs illegal requests with default key-value format.",
        "badge": "Default",
    },
    {
        "id": "log_all",
        "name": "Log All Traffic",
        "file": "log_all.json",
        "format": "default",
        "request_type": "all",
        "description": "Comprehensive audit profile logging both legal and illegal requests.",
        "badge": "Full Audit",
    },
    {
        "id": "log_blocked",
        "name": "Blocked Requests Only",
        "file": "log_blocked.json",
        "format": "default",
        "request_type": "blocked",
        "description": "High-signal profile logging only transactions that were actively blocked.",
        "badge": "Enforcement",
    },
    {
        "id": "log_grpc_all",
        "name": "gRPC Protocol All",
        "file": "log_grpc_all.json",
        "format": "grpc",
        "request_type": "all",
        "description": "Optimized for gRPC microservices traffic with Base64 payload decoding.",
        "badge": "gRPC",
    },
    {
        "id": "log_splunk",
        "name": "Splunk SIEM Profile",
        "file": "log_splunk.json",
        "format": "splunk",
        "request_type": "illegal",
        "description": "Formatted specifically for ingest by Splunk SIEM via F5 WAF for NGINX add-on.",
        "badge": "SIEM",
    },
    {
        "id": "log_arcsight",
        "name": "ArcSight CEF Profile",
        "file": "log_arcsight.json",
        "format": "arcsight",
        "request_type": "illegal",
        "description": "Formatted according to ArcSight Common Event Format (CEF) standard.",
        "badge": "CEF",
    },
    {
        "id": "log_key_value",
        "name": "Custom Key-Value Profile",
        "file": "log_key_value.json",
        "format": "user-defined",
        "request_type": "illegal",
        "description": "Custom format_string with explicit timestamp, client IP, violation list, and support ID.",
        "badge": "Custom",
    },
]


def list_logging_templates() -> List[Dict[str, Any]]:
    """Return catalog of built-in starter logging profiles."""
    return LOGGING_TEMPLATE_METADATA


def get_logging_template_json(template_id: str) -> Optional[str]:
    """Retrieve raw JSON string for a given template ID."""
    for tmpl in LOGGING_TEMPLATE_METADATA:
        if tmpl["id"] == template_id:
            p = LOGGING_TEMPLATES_DIR / tmpl["file"]
            if p.exists():
                return p.read_text(encoding="utf-8")
    return None


def get_logging_template_dict(template_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve parsed JSON object dictionary for a given template ID."""
    raw = get_logging_template_json(template_id)
    if raw:
        return json.loads(raw)
    return None
