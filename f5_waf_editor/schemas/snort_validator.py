"""
Snort Rule Syntax Validator, Parser, and Evaluator for F5 WAF for NGINX.
Official documentation:
- https://docs.nginx.com/waf/policies/user-signatures/#signatures
- https://techdocs.f5.com/kb/en-us/products/big-ip_asm/manuals/product/asm-bot-and-attack-signatures-13-0-0/7.html#guid-797a0c69-a859-45cd-be11-fd0e1a975780
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs


# Recognized Snort keywords in F5 WAF
MATCHING_KEYWORDS = {
    "content",
    "uricontent",
    "headercontent",
    "valuecontent",
    "pcre",
    "re2",
    "ipp",
    "reference",
}

MODIFIER_KEYWORDS = {
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "objonly",
    "norm",
    "plaintextonly",
    "httponly",
    "jsononly",
    "xmlonly",
    "gwtonly",
    "useragentonly",
}

ALL_RECOGNIZED_OPTIONS = MATCHING_KEYWORDS | MODIFIER_KEYWORDS


def decode_snort_hex(pattern: str) -> Tuple[str, Optional[str]]:
    """
    Decodes Snort hex escape sequences surrounded by pipes, e.g. |20| -> ' ', |22 22| -> '""'.
    Returns (decoded_string, error_message).
    """
    err = None
    parts = []
    i = 0
    n = len(pattern)

    while i < n:
        if pattern[i] == "|":
            # Find closing pipe
            end = pattern.find("|", i + 1)
            if end == -1:
                return pattern, "Unclosed hex escape pipe symbol '|'"
            hex_chunk = pattern[i + 1 : end].strip()
            # Split tokens by space
            tokens = hex_chunk.split()
            decoded_chars = []
            for token in tokens:
                # Handle concatenated hex pairs or single pairs
                token_clean = token.replace(" ", "")
                if len(token_clean) % 2 != 0:
                    return pattern, f"Odd number of hex digits in hex escape sequence '|{hex_chunk}|'"
                for h_idx in range(0, len(token_clean), 2):
                    hex_pair = token_clean[h_idx : h_idx + 2]
                    try:
                        byte_val = int(hex_pair, 16)
                        decoded_chars.append(chr(byte_val))
                    except ValueError:
                        return pattern, f"Invalid hex digits '{hex_pair}' in '|{hex_chunk}|'"
            parts.append("".join(decoded_chars))
            i = end + 1
        else:
            parts.append(pattern[i])
            i += 1

    return "".join(parts), None


def parse_snort_rule(rule_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parses a Snort rule string into structured clauses.
    Returns (clauses, syntax_errors).
    """
    if not rule_text or not isinstance(rule_text, str):
        return [], ["Rule is empty"]

    cleaned = rule_text.strip()
    clauses: List[Dict[str, Any]] = []
    errors: List[str] = []

    # Tokenize by semicolons while respecting quotes
    raw_clauses: List[str] = []
    current: List[str] = []
    in_quotes = False
    escaped = False

    for char in cleaned:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            current.append(char)
        elif char == ";" and not in_quotes:
            raw_clauses.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    trailing = "".join(current).strip()
    if trailing:
        errors.append(f"Clause '{trailing}' is missing trailing semicolon ';'")

    for raw in raw_clauses:
        if not raw:
            continue
        # Split on first ':'
        negated = False
        if ":" in raw:
            kw_part, val_part = raw.split(":", 1)
            kw = kw_part.strip()
            val = val_part.strip()
            if kw.endswith("!"):
                negated = True
                kw = kw[:-1].strip()
            elif val.startswith("!"):
                negated = True
                val = val[1:].strip()

            # Clean quotes if present
            quote_wrapped = False
            unquoted_val = val
            if val.startswith('"') and val.endswith('"') and len(val) >= 2:
                quote_wrapped = True
                unquoted_val = val[1:-1]

            clauses.append({
                "raw": raw,
                "keyword": kw.lower(),
                "original_keyword": kw,
                "value": unquoted_val,
                "raw_value": val,
                "quote_wrapped": quote_wrapped,
                "negated": negated,
                "is_modifier": kw.lower() in MODIFIER_KEYWORDS,
            })
        else:
            # Standalone modifier like nocase, objonly, norm, etc.
            kw = raw.strip()
            negated = False
            if kw.startswith("!"):
                negated = True
                kw = kw[1:].strip()

            clauses.append({
                "raw": raw,
                "keyword": kw.lower(),
                "original_keyword": kw,
                "value": "",
                "raw_value": "",
                "quote_wrapped": False,
                "negated": negated,
                "is_modifier": True,
            })

    return clauses, errors


def validate_snort_rule(rule_text: str) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    """
    Validates a Snort rule for F5 WAF for NGINX.
    Returns (is_valid, errors, warnings, parsed_info).
    """
    errors: List[str] = []
    warnings: List[str] = []
    parsed_info: Dict[str, Any] = {
        "rule": rule_text,
        "clauses": [],
        "scopes": [],
        "modifiers": [],
        "keywords": [],
        "has_pcre": False,
        "has_re2": False,
        "has_hex_escape": False,
        "decoded_patterns": [],
    }

    if not rule_text or not isinstance(rule_text, str) or not rule_text.strip():
        return False, ["Rule string cannot be empty"], [], parsed_info

    clauses, parse_errors = parse_snort_rule(rule_text)
    errors.extend(parse_errors)

    if not clauses and not errors:
        return False, ["No valid Snort clauses found in rule"], [], parsed_info

    matching_found = False
    scopes_present = set()
    has_valuecontent = False
    last_keyword: Optional[str] = None
    preceding_matches = 0

    for idx, clause in enumerate(clauses):
        kw = clause["keyword"]
        val = clause["value"]
        negated = clause["negated"]

        if kw not in ALL_RECOGNIZED_OPTIONS:
            warnings.append(f"Clause #{idx+1}: Unrecognized or custom Snort keyword '{clause['original_keyword']}'")
        else:
            parsed_info["keywords"].append(kw)

        # Keyword checks
        if kw in MATCHING_KEYWORDS:
            matching_found = True
            preceding_matches += 1
            last_keyword = kw

            if kw in ("content", "uricontent", "headercontent", "valuecontent"):
                scopes_present.add(kw)
                if not clause["quote_wrapped"] and kw != "reference":
                    warnings.append(f"{kw} pattern should be enclosed in double quotes: {kw}:\"{val}\";")

                # Validate hex escaping
                if "|" in val:
                    parsed_info["has_hex_escape"] = True
                    _, hex_err = decode_snort_hex(val)
                    if hex_err:
                        errors.append(f"In {kw} clause #{idx+1}: {hex_err}")
                    else:
                        decoded, _ = decode_snort_hex(val)
                        parsed_info["decoded_patterns"].append({"keyword": kw, "raw": val, "decoded": decoded})
                else:
                    parsed_info["decoded_patterns"].append({"keyword": kw, "raw": val, "decoded": val})

            if kw == "valuecontent":
                has_valuecontent = True

            if kw in ("pcre", "re2", "ipp"):
                if kw == "pcre":
                    parsed_info["has_pcre"] = True
                elif kw == "re2":
                    parsed_info["has_re2"] = True
                # Validate regex syntax format: "/regex/[flags]"
                if not (val.startswith("/") and "/" in val[1:]):
                    errors.append(f"{kw} expression must be formatted as '/<regex>/[options]', got: '{val}'")
                else:
                    # Try compiling regex pattern
                    parts = val[1:].rsplit("/", 1)
                    pattern_str = parts[0]
                    flags_str = parts[1] if len(parts) > 1 else ""
                    py_flags = 0
                    if "i" in flags_str:
                        py_flags |= re.IGNORECASE
                    if "s" in flags_str:
                        py_flags |= re.DOTALL
                    if "m" in flags_str:
                        py_flags |= re.MULTILINE
                    try:
                        re.compile(pattern_str, py_flags)
                    except re.error as re_err:
                        errors.append(f"Invalid regex in {kw}: {re_err}")

            if kw == "reference":
                if "," not in val:
                    errors.append("reference must be formatted as 'reference:<type>,<value>;' (e.g. 'reference:cve,2021-1234;')")
                else:
                    ref_type = val.split(",", 1)[0].strip().lower()
                    if ref_type not in ("url", "bugtraq", "cve", "nessus"):
                        warnings.append(f"reference type '{ref_type}' is unconventional (expected url, bugtraq, cve, or nessus)")

            if negated and kw not in ("pcre", "re2") and preceding_matches <= 1:
                errors.append(f"Negated keyword '{kw}' (!) cannot be the first condition in a signature without a preceding positive match")

        elif kw in MODIFIER_KEYWORDS:
            parsed_info["modifiers"].append(kw)

            # Integer modifiers
            if kw in ("offset", "depth", "distance", "within"):
                if not val:
                    errors.append(f"Modifier '{kw}' requires an integer value (e.g. {kw}:10;)")
                else:
                    try:
                        int_val = int(val)
                        if int_val < 0:
                            errors.append(f"Modifier '{kw}' value must be non-negative, got '{val}'")
                    except ValueError:
                        errors.append(f"Modifier '{kw}' requires a valid integer, got '{val}'")

                if kw in ("distance", "within") and preceding_matches < 2:
                    warnings.append(f"Modifier '{kw}' specifies relative byte distance and typically requires two preceding match keywords")

            # Context-specific modifiers
            if kw == "objonly" and last_keyword != "uricontent":
                errors.append("Modifier 'objonly' can only be used with 'uricontent'")

            if kw == "norm" and last_keyword != "valuecontent":
                errors.append("Modifier 'norm' can only be used with 'valuecontent'")

            if kw in ("plaintextonly", "httponly", "jsononly", "xmlonly", "gwtonly") and last_keyword != "valuecontent":
                warnings.append(f"Modifier '{kw}' is specifically designed for 'valuecontent' parameter signatures")

            if kw == "useragentonly" and last_keyword not in ("headercontent", "ipp"):
                errors.append("Modifier 'useragentonly' can only be used with 'headercontent' or 'ipp'")

    # Scope conflicts: valuecontent cannot be mixed with content/uricontent/headercontent
    if has_valuecontent and len(scopes_present) > 1:
        errors.append(
            f"F5 WAF parameter signature restriction: 'valuecontent' cannot be combined with other scopes ({', '.join(s for s in scopes_present if s != 'valuecontent')}) in the same rule"
        )

    if not matching_found:
        errors.append("Rule must contain at least one match option (e.g. content, uricontent, headercontent, valuecontent, pcre, re2)")

    parsed_info["clauses"] = clauses
    parsed_info["scopes"] = list(scopes_present)
    is_valid = len(errors) == 0
    return is_valid, errors, warnings, parsed_info


def evaluate_snort_rule(
    rule_text: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Evaluates a Snort rule against a simulated HTTP request context.
    Context keys:
    - 'uri': str (e.g. '/admin/users?token=secret')
    - 'headers': dict or list (e.g. {'User-Agent': 'EvilBot/1.0', 'X-Debug': '1'})
    - 'body': str (e.g. '{"user": "apple", "role": "admin"}')
    - 'method': str (e.g. 'GET', 'POST')
    - 'params': dict of query/form params (optional, inferred from uri/body if omitted)
    """
    is_valid, errors, warnings, parsed_info = validate_snort_rule(rule_text)
    if not is_valid:
        return {
            "matched": False,
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "details": [],
            "message": f"Cannot evaluate invalid Snort rule: {'; '.join(errors)}",
        }

    uri = context.get("uri", "") or ""
    headers = context.get("headers", {}) or {}
    body = context.get("body", "") or ""
    method = (context.get("method", "GET") or "GET").upper()

    # Prepare normalized URI and URI path
    parsed_url = urlparse(uri)
    uri_path = parsed_url.path or uri
    uri_query = parsed_url.query or ""

    # Prepare headers as single string and map
    header_lines = []
    user_agent = ""
    if isinstance(headers, dict):
        for h_k, h_v in headers.items():
            header_lines.append(f"{h_k}: {h_v}")
            if h_k.lower() == "user-agent":
                user_agent = str(h_v)
    elif isinstance(headers, list):
        for item in headers:
            header_lines.append(str(item))
            if str(item).lower().startswith("user-agent:"):
                user_agent = str(item).split(":", 1)[1].strip()
    headers_text = "\r\n".join(header_lines)

    # Full content representation (Method + URI + Headers + Body)
    full_content = f"{method} {uri} HTTP/1.1\r\n{headers_text}\r\n\r\n{body}"

    # Extract parameters for valuecontent
    params = context.get("params")
    if not isinstance(params, dict):
        params = {}
        if uri_query:
            for k, v in parse_qs(uri_query).items():
                params[k] = v[0] if v else ""
        if body and ("=" in body or body.startswith("{")):
            if body.startswith("{"):
                import json
                try:
                    json_data = json.loads(body)
                    if isinstance(json_data, dict):
                        for k, v in json_data.items():
                            params[k] = str(v)
                except Exception:
                    pass
            else:
                for k, v in parse_qs(body).items():
                    params[k] = v[0] if v else ""

    # Evaluate clauses in sequence
    clauses = parsed_info["clauses"]
    details: List[Dict[str, Any]] = []
    overall_matched = True

    # Group clauses into rule segments (matching keyword + its modifiers)
    segments: List[Dict[str, Any]] = []
    current_segment: Optional[Dict[str, Any]] = None

    for c in clauses:
        kw = c["keyword"]
        if kw in MATCHING_KEYWORDS:
            if current_segment:
                segments.append(current_segment)
            current_segment = {
                "clause": c,
                "modifiers": {},
            }
        elif current_segment and kw in MODIFIER_KEYWORDS:
            current_segment["modifiers"][kw] = c["value"] or True

    if current_segment:
        segments.append(current_segment)

    last_match_end: Optional[int] = None

    for seg_idx, seg in enumerate(segments):
        c = seg["clause"]
        mods = seg["modifiers"]
        kw = c["keyword"]
        val = c["value"]
        negated = c["negated"]
        nocase = "nocase" in mods
        offset_val = int(mods["offset"]) if "offset" in mods and str(mods["offset"]).isdigit() else None
        depth_val = int(mods["depth"]) if "depth" in mods and str(mods["depth"]).isdigit() else None
        distance_val = int(mods["distance"]) if "distance" in mods and str(mods["distance"]).isdigit() else None
        within_val = int(mods["within"]) if "within" in mods and str(mods["within"]).isdigit() else None

        # Determine target text based on scope
        target_text = ""
        scope_name = "content"

        if kw == "content":
            # Default content checks full payload / body
            target_text = body if body else full_content
            scope_name = "full_payload"
        elif kw == "uricontent":
            if "objonly" in mods:
                target_text = uri_path
                scope_name = "uri_path"
            else:
                target_text = uri
                scope_name = "uri"
        elif kw == "headercontent":
            if "useragentonly" in mods:
                target_text = user_agent
                scope_name = "user_agent_header"
            else:
                target_text = headers_text
                scope_name = "http_headers"
        elif kw == "valuecontent":
            # Formatted as name=value
            param_pairs = [f"{k}={v}" for k, v in params.items()]
            target_text = " & ".join(param_pairs)
            scope_name = "parameters"
        elif kw in ("pcre", "re2", "ipp"):
            scope_name = "regex"
            target_text = full_content

        # Decode hex escapes in pattern
        decoded_val, _ = decode_snort_hex(val)

        matched = False
        match_start = -1
        match_end = -1
        matched_substr = ""

        if kw in ("content", "uricontent", "headercontent", "valuecontent"):
            search_haystack = target_text
            search_needle = decoded_val

            start_bound = 0
            end_bound = len(search_haystack)

            # Apply offset
            if offset_val is not None:
                start_bound = min(offset_val, end_bound)

            # Apply distance relative to previous keyword
            if distance_val is not None and last_match_end is not None:
                start_bound = min(last_match_end + distance_val, end_bound)

            # Apply depth
            if depth_val is not None:
                end_bound = min(start_bound + depth_val, len(search_haystack))

            # Apply within
            if within_val is not None and last_match_end is not None:
                end_bound = min(last_match_end + within_val, len(search_haystack))

            slice_text = search_haystack[start_bound:end_bound]

            if nocase:
                idx_pos = slice_text.lower().find(search_needle.lower())
            else:
                idx_pos = slice_text.find(search_needle)

            if idx_pos != -1:
                matched = True
                match_start = start_bound + idx_pos
                match_end = match_start + len(search_needle)
                matched_substr = search_haystack[match_start:match_end]
                last_match_end = match_end
            else:
                matched = False

        elif kw in ("pcre", "re2", "ipp"):
            parts = val[1:].rsplit("/", 1)
            pattern_str = parts[0]
            flags_str = parts[1] if len(parts) > 1 else ""
            py_flags = 0
            if "i" in flags_str or nocase:
                py_flags |= re.IGNORECASE
            if "s" in flags_str:
                py_flags |= re.DOTALL
            if "m" in flags_str:
                py_flags |= re.MULTILINE

            try:
                m = re.search(pattern_str, target_text, py_flags)
                if m:
                    matched = True
                    match_start = m.start()
                    match_end = m.end()
                    matched_substr = m.group(0)
                    last_match_end = match_end
                else:
                    matched = False
            except Exception:
                matched = False

        elif kw == "reference":
            matched = True
            matched_substr = val

        # Handle negation
        clause_effective_matched = (not matched) if negated else matched

        details.append({
            "segment_index": seg_idx + 1,
            "keyword": kw,
            "pattern": decoded_val if kw not in ("pcre", "re2", "ipp") else val,
            "negated": negated,
            "scope": scope_name,
            "found_in_input": matched,
            "passed": clause_effective_matched,
            "matched_at": match_start if matched else None,
            "matched_snippet": matched_substr if matched else None,
        })

        if not clause_effective_matched:
            overall_matched = False

    msg = "Signature matched the request successfully!" if overall_matched else "Signature did not match the request."
    return {
        "matched": overall_matched,
        "valid": True,
        "errors": [],
        "warnings": warnings,
        "details": details,
        "message": msg,
        "decoded_patterns": parsed_info.get("decoded_patterns", []),
    }
