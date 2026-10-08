"""
F5 WAF for NGINX Logging Profile Schema and Attribute Definitions.
Based on official F5 WAF for NGINX documentation:
https://docs.nginx.com/waf/logging/logs-overview/
"""

from typing import Any, Dict, List, Optional

# Supported Filter Request Types
REQUEST_TYPES = ["all", "illegal", "blocked"]

# Predefined Output Formats
LOG_FORMATS = [
    "default",
    "arcsight",
    "bigiq",
    "grpc",
    "splunk",
    "user-defined",
]

# Official Security Log Attributes Catalog for format_string (%attribute%)
LOG_ATTRIBUTES = [
    {
        "name": "attack_type",
        "token": "%attack_type%",
        "description": "Suspected attacks identified in the transaction (comma-separated).",
    },
    {
        "name": "blocking_exception_reason",
        "token": "%blocking_exception_reason%",
        "description": "Reason when a configured violation was not blocked.",
    },
    {
        "name": "bot_anomalies",
        "token": "%bot_anomalies%",
        "description": "Anomalies detected in automated bot traffic.",
    },
    {
        "name": "bot_category",
        "token": "%bot_category%",
        "description": "Classification category of the detected bot client.",
    },
    {
        "name": "bot_signature_name",
        "token": "%bot_signature_name%",
        "description": "Name of matching bot signature.",
    },
    {
        "name": "client_type",
        "token": "%client_type%",
        "description": "Client classification (browser, mobile, bot, etc.).",
    },
    {
        "name": "date_time",
        "token": "%date_time%",
        "description": "Timestamp when the request was processed (YYYY-MM-DD HH:MM:SS).",
    },
    {
        "name": "dest_port",
        "token": "%dest_port%",
        "description": "Destination TCP/UDP port.",
    },
    {
        "name": "ip_client",
        "token": "%ip_client%",
        "description": "Client IP address (or X-Forwarded-For if configured).",
    },
    {
        "name": "is_truncated",
        "token": "%is_truncated%",
        "description": "Boolean flag indicating if the log message was truncated due to size limits.",
    },
    {
        "name": "method",
        "token": "%method%",
        "description": "HTTP request method (GET, POST, PUT, DELETE, etc.).",
    },
    {
        "name": "policy_name",
        "token": "%policy_name%",
        "description": "Name of the active F5 WAF policy that evaluated the request.",
    },
    {
        "name": "protocol",
        "token": "%protocol%",
        "description": "HTTP protocol version (HTTP/1.1, HTTP/2, etc.).",
    },
    {
        "name": "request",
        "token": "%request%",
        "description": "Full HTTP request headers and payload (bounded by max_request_size).",
    },
    {
        "name": "request_status",
        "token": "%request_status%",
        "description": "Outcome of request evaluation: blocked, alerted, passed.",
    },
    {
        "name": "response_code",
        "token": "%response_code%",
        "description": "HTTP status code sent to the client (e.g. 200, 403, 500).",
    },
    {
        "name": "route_domain",
        "token": "%route_domain%",
        "description": "Routing domain identifier.",
    },
    {
        "name": "server_entry",
        "token": "%server_entry%",
        "description": "Target server definition.",
    },
    {
        "name": "severity",
        "token": "%severity%",
        "description": "Log severity level (Emergency, Alert, Critical, Error, Warning, Notice, Informational).",
    },
    {
        "name": "sig_cves",
        "token": "%sig_cves%",
        "description": "List of Common Vulnerabilities and Exposures (CVEs) associated with matched signatures.",
    },
    {
        "name": "sig_ids",
        "token": "%sig_ids%",
        "description": "IDs of all attack signatures triggered in the request.",
    },
    {
        "name": "sig_names",
        "token": "%sig_names%",
        "description": "Human-readable names of all attack signatures triggered.",
    },
    {
        "name": "sig_set_names",
        "token": "%sig_set_names%",
        "description": "Names of signature sets containing triggered signatures.",
    },
    {
        "name": "src_port",
        "token": "%src_port%",
        "description": "Client source TCP port.",
    },
    {
        "name": "sub_violations",
        "token": "%sub_violations%",
        "description": "Detailed sub-violation flags (e.g. specific metacharacters, evasion codes).",
    },
    {
        "name": "support_id",
        "token": "%support_id%",
        "description": "Unique transaction correlation ID assigned by F5 WAF.",
    },
    {
        "name": "threat_campaign_names",
        "token": "%threat_campaign_names%",
        "description": "Names of matched Threat Campaigns.",
    },
    {
        "name": "unit_hostname",
        "token": "%unit_hostname%",
        "description": "Hostname of the NGINX / F5 WAF instance processing the request.",
    },
    {
        "name": "uri",
        "token": "%uri%",
        "description": "Normalized URI path of the request.",
    },
    {
        "name": "violation_details",
        "token": "%violation_details%",
        "description": "Granular XML/JSON details explaining the violation cause.",
    },
    {
        "name": "violation_rating",
        "token": "%violation_rating%",
        "description": "Calculated threat score (1 to 5).",
    },
    {
        "name": "violations",
        "token": "%violations%",
        "description": "Names of all violations triggered by the request.",
    },
    {
        "name": "x_forwarded_for_header_value",
        "token": "%x_forwarded_for_header_value%",
        "description": "Exact value of the X-Forwarded-For header.",
    },
]


def extract_logging_metadata(
    profile_dict: Optional[Dict[str, Any]], size_bytes: int = 0
) -> Dict[str, Any]:
    """Extract summary information from a parsed logging profile document."""
    if not profile_dict or not isinstance(profile_dict, dict):
        return {
            "name": "unknown",
            "request_type": "unknown",
            "format": "unknown",
            "max_message_size": "unknown",
            "max_request_size": "unknown",
            "sizeBytes": size_bytes,
        }

    flt = profile_dict.get("filter", {})
    req_type = flt.get("request_type", "all") if isinstance(flt, dict) else "all"

    content = profile_dict.get("content", {})
    fmt = "default"
    max_msg = "32k"
    max_req = "2k"
    has_custom = False

    if isinstance(content, dict):
        fmt = content.get("format", "default")
        max_msg = str(content.get("max_message_size", "32k"))
        max_req = str(content.get("max_request_size", "2k"))
        has_custom = fmt == "user-defined" and bool(content.get("format_string"))

    return {
        "request_type": req_type,
        "format": fmt,
        "max_message_size": max_msg,
        "max_request_size": max_req,
        "is_custom_format": has_custom,
        "sizeBytes": size_bytes,
    }
