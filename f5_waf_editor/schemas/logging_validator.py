"""
Validator for F5 WAF for NGINX Logging Profiles.
Validates declarative JSON schema according to official F5 WAF for NGINX specifications.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from f5_waf_editor.schemas.logging_schema import REQUEST_TYPES, LOG_FORMATS


def validate_logging_profile_json(
    content: Union[str, Dict[str, Any]]
) -> Tuple[bool, List[str], List[str], Optional[Dict[str, Any]]]:
    """
    Validates an F5 WAF logging profile JSON document.
    Returns:
        (is_valid: bool, errors: List[str], warnings: List[str], parsed_dict: Optional[Dict[str, Any]])
    """
    errors: List[str] = []
    warnings: List[str] = []
    parsed: Optional[Dict[str, Any]] = None

    if isinstance(content, str):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            return False, [f"Invalid JSON syntax: {e.msg} at line {e.lineno}, col {e.colno}"], warnings, None
    elif isinstance(content, dict):
        parsed = content
    else:
        return False, ["Logging profile content must be a JSON string or JSON object dictionary"], warnings, None

    if not isinstance(parsed, dict):
        return False, ["Root logging profile structure must be a JSON object"], warnings, None

    # 1. Filter Validation
    if "filter" not in parsed:
        errors.append("Missing required top-level key: 'filter'")
    else:
        flt = parsed["filter"]
        if not isinstance(flt, dict):
            errors.append("'filter' must be a JSON object")
        else:
            req_type = flt.get("request_type")
            if req_type is not None:
                if req_type not in REQUEST_TYPES:
                    errors.append(
                        f"Invalid 'filter.request_type': '{req_type}'. Allowed values: {', '.join(REQUEST_TYPES)}"
                    )

    # 2. Content Validation
    if "content" not in parsed:
        errors.append("Missing required top-level key: 'content'")
    else:
        cnt = parsed["content"]
        if not isinstance(cnt, dict):
            errors.append("'content' must be a JSON object")
        else:
            fmt = cnt.get("format", "default")
            if fmt not in LOG_FORMATS:
                errors.append(
                    f"Invalid 'content.format': '{fmt}'. Allowed values: {', '.join(LOG_FORMATS)}"
                )

            # If user-defined, format_string is mandatory
            if fmt == "user-defined":
                fmt_str = cnt.get("format_string")
                if not fmt_str or not isinstance(fmt_str, str) or not fmt_str.strip():
                    errors.append(
                        "When 'content.format' is 'user-defined', 'content.format_string' must be a non-empty string"
                    )
                else:
                    # Check placeholders in format_string
                    tokens = re.findall(r"%([a-zA-Z0-9_]+)%", fmt_str)
                    if not tokens:
                        warnings.append(
                            "User-defined format_string does not appear to contain any %attribute% tokens."
                        )

            # max_message_size validation (range 1k-64k or 1024-65536 bytes, must be > 0)
            max_msg = cnt.get("max_message_size")
            if max_msg is not None:
                if isinstance(max_msg, str):
                    m = re.match(r"^(\d+)[kK]$", max_msg.strip())
                    m_bytes = re.match(r"^(\d+)$", max_msg.strip())
                    if m:
                        val = int(m.group(1))
                        if val <= 0 or not (1 <= val <= 64):
                            errors.append(
                                f"Invalid 'content.max_message_size': '{max_msg}'. Must be greater than zero (between 1k and 64k)"
                            )
                    elif m_bytes:
                        val = int(m_bytes.group(1))
                        if val <= 0 or not (1024 <= val <= 65536):
                            errors.append(
                                f"Invalid 'content.max_message_size': '{max_msg}'. Must be greater than zero and between 1024 (1k) and 65536 (64k) bytes"
                            )
                    else:
                        errors.append(
                            f"Invalid 'content.max_message_size': '{max_msg}'. Expected a format like '32k' (between 1k and 64k) or positive byte count"
                        )
                elif isinstance(max_msg, (int, float)):
                    if max_msg <= 0 or not (1024 <= max_msg <= 65536):
                        errors.append(
                            f"Invalid 'content.max_message_size' bytes: {max_msg}. Must be greater than zero and between 1024 (1k) and 65536 (64k)"
                        )

            # max_request_size validation (1-10240, or 1k-10k, or "any", must be > 0)
            max_req = cnt.get("max_request_size")
            if max_req is not None:
                if isinstance(max_req, str):
                    if max_req.lower() != "any":
                        m = re.match(r"^(\d+)[kK]$", max_req.strip())
                        m_bytes = re.match(r"^(\d+)$", max_req.strip())
                        if m:
                            val = int(m.group(1))
                            if val <= 0 or not (1 <= val <= 10):
                                errors.append(
                                    f"Invalid 'content.max_request_size': '{max_req}'. Must be greater than zero (between 1k and 10k or 'any')"
                                )
                        elif m_bytes:
                            val = int(m_bytes.group(1))
                            if val <= 0 or not (1 <= val <= 10240):
                                errors.append(
                                    f"Invalid 'content.max_request_size': '{max_req}'. Must be greater than zero and between 1 and 10240 bytes"
                                )
                        else:
                            errors.append(
                                f"Invalid 'content.max_request_size': '{max_req}'. Expected 'any', format like '2k', or byte count between 1 and 10240"
                            )
                elif isinstance(max_req, (int, float)):
                    if max_req <= 0 or not (1 <= max_req <= 10240):
                        errors.append(
                            f"Invalid 'content.max_request_size': {max_req}. Must be greater than zero and between 1 and 10240 bytes"
                        )

            # escaping_characters validation
            esc = cnt.get("escaping_characters")
            if esc is not None:
                if not isinstance(esc, list):
                    errors.append("'content.escaping_characters' must be a list of objects")
                else:
                    for idx, item in enumerate(esc):
                        if not isinstance(item, dict) or "from" not in item or "to" not in item:
                            errors.append(
                                f"Invalid escaping character item at index {idx}: must be an object with 'from' and 'to' string properties"
                            )

    is_valid = len(errors) == 0
    return is_valid, errors, warnings, parsed
