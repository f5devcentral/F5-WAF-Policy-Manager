"""
Templates catalog for F5 WAF for NGINX.
Provides reference starting points for policies.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

TEMPLATES_DIR = Path(__file__).parent

TEMPLATES_METADATA = [
    {
        "id": "default",
        "name": "NGINX Default Base",
        "filename": "default_policy.json",
        "description": "Factory default baseline with OWASP Top 10 and Bot protection.",
        "enforcementMode": "blocking",
        "tag": "Recommended",
    },
    {
        "id": "strict",
        "name": "Strict Security & Data Guard",
        "filename": "strict_policy.json",
        "description": "Enforces Data Guard (CCN/SSN masking), blocks evasions, and limits methods.",
        "enforcementMode": "blocking",
        "tag": "High Security",
    },
    {
        "id": "api_security",
        "name": "API & JSON Gateway",
        "filename": "api_security.json",
        "description": "Optimized for REST APIs, enforces valid JSON format, and masks credentials.",
        "enforcementMode": "blocking",
        "tag": "API / Cloud",
    },
    {
        "id": "transparent",
        "name": "Transparent Monitor",
        "filename": "transparent_base.json",
        "description": "Safe zero-impact auditing mode. Violations are logged but never blocked.",
        "enforcementMode": "transparent",
        "tag": "Staging / Audit",
    },
    {
        "id": "grpc_security",
        "name": "gRPC Microservices Protection",
        "filename": "grpc_security.json",
        "description": "Enforces gRPC Protobuf IDL schema compliance, method validation, and malformed frame blocking.",
        "enforcementMode": "blocking",
        "tag": "gRPC / Microservices",
    },
]


def list_templates() -> List[Dict[str, Any]]:
    """Return catalog metadata for all built-in templates."""
    return TEMPLATES_METADATA


def get_template_json(template_id: str) -> Dict[str, Any] | None:
    """Retrieve the JSON content of a built-in template by its id."""
    for meta in TEMPLATES_METADATA:
        if meta["id"] == template_id:
            file_path = TEMPLATES_DIR / meta["filename"]
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
    return None
