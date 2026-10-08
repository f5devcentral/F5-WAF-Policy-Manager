"""
Policy validator for F5 WAF for NGINX JSON files.
Validates structural integrity, required keys, enforcement modes, and violation formats.
"""
from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from .waf_schema import (
    BASE_TEMPLATES,
    ENFORCEMENT_MODES,
    SUPPORTED_ENCODINGS,
    VIOLATIONS_CATALOG,
    STANDARD_EVASION_DESCRIPTIONS,
    IP_BLOCK_REQUESTS_ACTIONS,
    OFFICIAL_SIGNATURE_SET_NAMES,
    SIGNATURE_SET_NAME_ALIASES,
    OFFICIAL_SERVER_TECHNOLOGIES,
    SERVER_TECHNOLOGY_ALIASES,
    NON_CONFIGURABLE_VIOLATIONS,
)
from .snort_validator import validate_snort_rule


# Valid policy name regex: allowed characters are a-z, A-Z, 0-9, dot, dash, colon, underscore
POLICY_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\.\-:]+$")

KNOWN_VIOLATION_NAMES = {v["name"] for v in VIOLATIONS_CATALOG}


def validate_policy_json(content: Any) -> Tuple[bool, List[str], List[str], Dict[str, Any] | None]:
    """
    Validates an F5 WAF policy JSON string or dictionary.

    Returns:
        (is_valid, errors, warnings, parsed_dict)
    """
    errors: List[str] = []
    warnings: List[str] = []
    parsed: Dict[str, Any] | None = None

    if isinstance(content, str):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return False, [f"Invalid JSON syntax: {exc.msg} at line {exc.lineno}, column {exc.colno}"], [], None
    elif isinstance(content, dict):
        parsed = content
    else:
        return False, ["Policy must be a valid JSON object or JSON string"], [], None

    if not isinstance(parsed, dict):
        return False, ["Root policy must be a JSON object"], [], None

    # Must contain 'policy' key
    if "policy" not in parsed:
        errors.append("Missing required top-level key: 'policy'")
        return False, errors, warnings, parsed

    policy = parsed.get("policy")
    if not isinstance(policy, dict):
        errors.append("'policy' must be a JSON object")
        return False, errors, warnings, parsed

    # Validate policy name
    name = policy.get("name")
    if not name:
        errors.append("Missing required field: 'policy.name'")
    elif not isinstance(name, str):
        errors.append("'policy.name' must be a string")
    elif not POLICY_NAME_REGEX.match(name):
        errors.append(
            f"Invalid 'policy.name': '{name}'. Allowed characters are alphanumeric, dot, dash, colon, and underscore."
        )

    # Validate template
    template = policy.get("template")
    if template is not None:
        if isinstance(template, dict):
            tmpl_name = template.get("name")
            if not tmpl_name:
                warnings.append("'policy.template' object is missing a 'name' property")
            elif tmpl_name not in BASE_TEMPLATES:
                warnings.append(
                    f"Template '{tmpl_name}' is custom or not in standard reference set ({', '.join(BASE_TEMPLATES)})"
                )
        elif isinstance(template, str):
            warnings.append(
                "Policy template should ideally be an object: {'name': 'POLICY_TEMPLATE_NGINX_BASE'}"
            )
        else:
            errors.append("'policy.template' must be an object with a 'name' property")

    # Validate enforcementMode
    mode = policy.get("enforcementMode")
    if mode is not None:
        if not isinstance(mode, str):
            errors.append("'policy.enforcementMode' must be a string")
        elif mode.lower() not in ENFORCEMENT_MODES:
            errors.append(
                f"Invalid enforcementMode '{mode}'. Allowed values: {', '.join(ENFORCEMENT_MODES)}"
            )

    # Validate applicationLanguage
    lang = policy.get("applicationLanguage")
    if lang is not None:
        if not isinstance(lang, str):
            errors.append("'policy.applicationLanguage' must be a string")
        elif lang.lower() not in SUPPORTED_ENCODINGS:
            warnings.append(
                f"Character encoding '{lang}' is non-standard. Recommended: 'utf-8'"
            )

    # Validate blocking-settings
    blocking_settings = policy.get("blocking-settings")
    if blocking_settings is not None:
        if not isinstance(blocking_settings, dict):
            errors.append("'policy.blocking-settings' must be a JSON object")
        else:
            violations = blocking_settings.get("violations")
            if violations is not None:
                if not isinstance(violations, list):
                    errors.append("'policy.blocking-settings.violations' must be an array")
                else:
                    for i, viol in enumerate(violations):
                        if not isinstance(viol, dict):
                            errors.append(f"Violation item #{i+1} must be an object")
                            continue
                        viol_name = viol.get("name")
                        if not viol_name:
                            errors.append(f"Violation item #{i+1} is missing required 'name'")
                        elif viol_name in NON_CONFIGURABLE_VIOLATIONS:
                            warnings.append(
                                f"Violation item #{i+1} '{viol_name}' cannot be configured under 'blocking-settings.violations' in F5 WAF for NGINX (managed via signature-sets or bot-defense; omitted automatically during compilation)."
                            )
                        elif viol_name not in KNOWN_VIOLATION_NAMES:
                            warnings.append(
                                f"Violation item #{i+1} '{viol_name}' is not in known F5 WAF violations catalog"
                            )
                        if "alarm" in viol and not isinstance(viol["alarm"], bool):
                            errors.append(f"Violation '{viol_name}' alarm property must be a boolean")
                        if "block" in viol and not isinstance(viol["block"], bool):
                            errors.append(f"Violation '{viol_name}' block property must be a boolean")

            # Validate evasions inside blocking-settings
            # https://docs.nginx.com/waf/policies/evasion-techniques/
            evasions = blocking_settings.get("evasions")
            if evasions is not None:
                if not isinstance(evasions, list):
                    errors.append("'policy.blocking-settings.evasions' must be an array")
                else:
                    for i, ev in enumerate(evasions):
                        if not isinstance(ev, dict):
                            errors.append(f"Evasion item #{i+1} must be an object")
                            continue
                        desc = ev.get("description")
                        if not desc or not isinstance(desc, str):
                            errors.append(f"Evasion item #{i+1} must contain a 'description' string")
                        elif desc not in STANDARD_EVASION_DESCRIPTIONS:
                            errors.append(f"Unknown or unsupported evasion technique '{desc}'. Must be one of standard techniques")
                        if "enabled" in ev and not isinstance(ev["enabled"], bool):
                            errors.append(f"Evasion '{desc or i+1}' 'enabled' must be a boolean")
                        if "learn" in ev and not isinstance(ev["learn"], bool):
                            errors.append(f"Evasion '{desc or i+1}' 'learn' must be a boolean")
                        if "maxDecodingPasses" in ev:
                            passes = ev["maxDecodingPasses"]
                            if not isinstance(passes, int) or passes < 1:
                                errors.append(f"Evasion '{desc or i+1}' maxDecodingPasses must be a positive integer")

    # Validate signature-sets
    signature_sets = policy.get("signature-sets")
    if signature_sets is not None:
        if not isinstance(signature_sets, list):
            errors.append("'policy.signature-sets' must be an array")
        else:
            for i, sig_set in enumerate(signature_sets):
                if not isinstance(sig_set, dict):
                    errors.append(f"Signature set item #{i+1} must be an object")
                    continue
                set_name = sig_set.get("name")
                if not set_name or not isinstance(set_name, str):
                    errors.append(f"Signature set item #{i+1} is missing a valid 'name' string")
                    continue

                # Check for Threat Campaigns misplacement
                if set_name.lower() in ("threat campaigns", "threat-campaigns", "threat campaign"):
                    errors.append(
                        f"'{set_name}' is not a valid signature set in F5 WAF for NGINX. "
                        "Threat Campaigns are configured via violation 'VIOL_THREAT_CAMPAIGN' in "
                        "'policy.blocking-settings.violations' (with alarm/block) instead of 'signature-sets'."
                    )
                    continue

                if "alarm" in sig_set and not isinstance(sig_set["alarm"], bool):
                    errors.append(f"Signature set '{set_name}' alarm property must be a boolean")
                if "block" in sig_set and not isinstance(sig_set["block"], bool):
                    errors.append(f"Signature set '{set_name}' block property must be a boolean")

                # Check alias warnings
                lower_name = set_name.lower()
                if lower_name in SIGNATURE_SET_NAME_ALIASES:
                    canonical = SIGNATURE_SET_NAME_ALIASES[lower_name]
                    warnings.append(
                        f"Signature set '{set_name}' is an alias. In F5 WAF for NGINX, the official name is '{canonical}'."
                    )

                # Predefined vs Custom signature set
                if "signatureSet" not in sig_set:
                    # Must be an official predefined signature set (or deleted)
                    if sig_set.get("$action") != "delete":
                        if set_name not in OFFICIAL_SIGNATURE_SET_NAMES and lower_name not in SIGNATURE_SET_NAME_ALIASES:
                            errors.append(
                                f"Unknown predefined signature set '{set_name}'. In F5 WAF for NGINX, predefined sets "
                                "must match one of the 30 official signature set names (e.g., 'Path Traversal Signatures', "
                                "'High Accuracy Signatures'). Custom sets require a 'signatureSet' definition object."
                            )
                else:
                    if not isinstance(sig_set["signatureSet"], dict):
                        errors.append(f"Signature set '{set_name}' signatureSet property must be an object")
                    else:
                        ss_obj = sig_set["signatureSet"]
                        ss_type = ss_obj.get("type")
                        if ss_type is None:
                            if "filter" in ss_obj:
                                ss_type = "filter-based"
                            elif "signatures" in ss_obj:
                                ss_type = "manual"
                        if ss_type not in ("filter-based", "manual"):
                            errors.append(f"Signature set '{set_name}' signatureSet.type must be 'filter-based' or 'manual'")
                        if ss_type == "filter-based":
                            filter_obj = ss_obj.get("filter")
                            if not isinstance(filter_obj, dict):
                                errors.append(f"Signature set '{set_name}' filter-based signatureSet requires a 'filter' object")
                            else:
                                if "signatureType" in filter_obj:
                                    sig_type = filter_obj["signatureType"]
                                    if sig_type not in ("request", "response", "all"):
                                        errors.append(f"Signature set '{set_name}' signatureType must be 'request', 'response', or 'all'")
                        elif ss_type == "manual":
                            sigs = ss_obj.get("signatures")
                            if not isinstance(sigs, list) or len(sigs) == 0:
                                errors.append(f"Signature set '{set_name}' manual signatureSet requires a non-empty 'signatures' array")
                            else:
                                for s_idx, sig_item in enumerate(sigs):
                                    if not isinstance(sig_item, dict) or "signatureId" not in sig_item:
                                        errors.append(f"Signature set '{set_name}' manual signature #{s_idx+1} must be an object with 'signatureId'")


    # Validate general settings (allowedResponseCodes, responseCheck, responseCheckLength)
    # https://docs.nginx.com/waf/policies/response-signatures/
    general = policy.get("general")
    if general is not None:
        if not isinstance(general, dict):
            errors.append("'policy.general' must be an object")
        else:
            if "allowedResponseCodes" in general:
                codes = general["allowedResponseCodes"]
                if not isinstance(codes, list):
                    errors.append("'policy.general.allowedResponseCodes' must be an array of HTTP status codes")
                else:
                    for c_idx, code in enumerate(codes):
                        if not isinstance(code, int) or code < 100 or code > 599:
                            errors.append(f"Allowed response code #{c_idx+1} '{code}' must be a valid integer between 100 and 599")
            if "responseCheck" in general and not isinstance(general["responseCheck"], bool):
                errors.append("'policy.general.responseCheck' must be a boolean")
            if "responseCheckLength" in general:
                rlen = general["responseCheckLength"]
                if not isinstance(rlen, int) or rlen < 0:
                    errors.append("'policy.general.responseCheckLength' must be a non-negative integer (bytes)")

    # Validate ip-address-lists (official IP Address Lists feature)
    # https://docs.nginx.com/waf/policies/ip-address-lists/
    ip_lists = policy.get("ip-address-lists")
    if ip_lists is not None:
        if not isinstance(ip_lists, list):
            errors.append("'policy.ip-address-lists' must be an array")
        else:
            for i, ip_group in enumerate(ip_lists):
                ctx = f"IP address list #{i+1}"
                if not isinstance(ip_group, dict):
                    errors.append(f"{ctx} must be an object")
                    continue
                list_name = ip_group.get("name")
                if not list_name or not isinstance(list_name, str) or not list_name.strip():
                    errors.append(f"{ctx} must contain a non-empty string 'name'")
                else:
                    ctx = f"IP address list '{list_name}'"

                block_action = ip_group.get("blockRequests")
                if block_action is not None:
                    if block_action not in ("policy-default", "never", "always"):
                        errors.append(f"{ctx} Invalid blockRequests '{block_action}'. Must be one of: 'policy-default', 'never', 'always'")

                geo = ip_group.get("setGeolocation")
                if geo is not None and (not isinstance(geo, str) or len(geo.strip()) != 2 or not geo.isalpha()):
                    errors.append(f"{ctx} 'setGeolocation' must be a 2-letter uppercase ISO country code (e.g. 'US')")

                ref = ip_group.get("$ref")
                if ref is not None and not isinstance(ref, str):
                    errors.append(f"{ctx} '$ref' must be a string path or URI")

                addresses = ip_group.get("ipAddresses")
                if addresses is not None:
                    if not isinstance(addresses, list):
                        errors.append(f"{ctx} 'ipAddresses' must be an array")
                    else:
                        for a_idx, addr_item in enumerate(addresses):
                            if not isinstance(addr_item, dict):
                                errors.append(f"{ctx} ipAddress #{a_idx+1} must be an object")
                                continue
                            addr_val = addr_item.get("ipAddress")
                            if not addr_val or not isinstance(addr_val, str) or not addr_val.strip():
                                errors.append(f"{ctx} ipAddress #{a_idx+1} is missing a required 'ipAddress' string (e.g. '1.2.3.4' or '10.0.0.0/8')")


    # Validate signatures (individual signature exceptions/overrides)
    # Supports both pre-defined (by numeric signatureId) and user-defined (by name and tag)
    signatures = policy.get("signatures")
    if signatures is not None:
        if not isinstance(signatures, list):
            errors.append("'policy.signatures' must be an array")
        else:
            for i, sig in enumerate(signatures):
                if not isinstance(sig, dict):
                    errors.append(f"Signature item #{i+1} must be an object")
                elif "signatureId" not in sig and ("name" not in sig or "tag" not in sig):
                    errors.append(
                        f"Signature item #{i+1} is missing 'signatureId' or custom signature 'name' and 'tag'"
                    )
                else:
                    if "signatureId" in sig and not isinstance(sig["signatureId"], (int, float)):
                        errors.append(f"Signature item #{i+1} 'signatureId' must be a numeric ID")
                    if "name" in sig and (not isinstance(sig["name"], str) or not sig["name"].strip()):
                        errors.append(f"Signature item #{i+1} 'name' must be a non-empty string")
                    if "tag" in sig and (not isinstance(sig["tag"], str) or not sig["tag"].strip()):
                        errors.append(f"Signature item #{i+1} 'tag' must be a non-empty string")
                if "enabled" in sig and not isinstance(sig["enabled"], bool):
                    errors.append(f"Signature item #{i+1} 'enabled' must be a boolean")
                if "performStaging" in sig and not isinstance(sig["performStaging"], bool):
                    errors.append(f"Signature item #{i+1} 'performStaging' must be a boolean")

    # Validate signature-requirements (official user-defined signature dependencies)
    sig_reqs = policy.get("signature-requirements")
    if sig_reqs is not None:
        if not isinstance(sig_reqs, list):
            errors.append("'policy.signature-requirements' must be an array")
        else:
            for i, req in enumerate(sig_reqs):
                if not isinstance(req, dict):
                    errors.append(f"Signature requirement #{i+1} must be an object")
                    continue
                tag = req.get("tag")
                if not tag or not isinstance(tag, str) or not tag.strip():
                    errors.append(f"Signature requirement #{i+1} is missing a required non-empty 'tag' string")
                for dt_field in ("minRevisionDatetime", "maxRevisionDatetime"):
                    if dt_field in req and req[dt_field] is not None:
                        val = req[dt_field]
                        if not isinstance(val, str) or not val.strip():
                            errors.append(f"Signature requirement #{i+1} '{dt_field}' must be an ISO datetime string")

    # Validate custom-signatures (user-defined signatures defined within policy)
    custom_sigs = policy.get("custom-signatures")
    if custom_sigs is None:
        custom_sigs = policy.get("user-defined-signatures")
    if custom_sigs is not None:
        if not isinstance(custom_sigs, list):
            errors.append("'policy.custom-signatures' must be an array")
        else:
            for i, cs in enumerate(custom_sigs):
                if not isinstance(cs, dict):
                    errors.append(f"Custom signature #{i+1} must be an object")
                    continue
                cs_name = cs.get("name")
                if not cs_name or not isinstance(cs_name, str) or not cs_name.strip():
                    errors.append(f"Custom signature #{i+1} is missing required 'name'")
                rule = cs.get("rule")
                if not rule or not isinstance(rule, str) or not rule.strip():
                    errors.append(f"Custom signature '{cs_name or i+1}' is missing required 'rule' (Snort syntax)")
                else:
                    s_valid, s_errs, s_warns, _ = validate_snort_rule(rule)
                    for err in s_errs:
                        errors.append(f"Custom signature '{cs_name or i+1}' Snort rule error: {err}")
                    for warn in s_warns:
                        warnings.append(f"Custom signature '{cs_name or i+1}' Snort rule warning: {warn}")

                sig_type = cs.get("signatureType", "request")
                if sig_type not in ("request", "response"):
                    errors.append(f"Custom signature '{cs_name or i+1}' signatureType must be 'request' or 'response'")
                risk = cs.get("risk", "medium")
                if risk not in ("low", "medium", "high"):
                    errors.append(f"Custom signature '{cs_name or i+1}' risk must be 'low', 'medium', or 'high'")
                accuracy = cs.get("accuracy", "medium")
                if accuracy not in ("low", "medium", "high"):
                    errors.append(f"Custom signature '{cs_name or i+1}' accuracy must be 'low', 'medium', or 'high'")


    # Validate server-technologies
    techs = policy.get("server-technologies")
    if techs is not None:
        if not isinstance(techs, list):
            errors.append("'policy.server-technologies' must be an array")
        else:
            official_lookup = {t.lower(): t for t in OFFICIAL_SERVER_TECHNOLOGIES}
            for i, tech in enumerate(techs):
                if not isinstance(tech, dict):
                    errors.append(f"Server technology item #{i+1} must be an object")
                    continue
                t_name = tech.get("serverTechnologyName") or tech.get("name")
                if not t_name:
                    errors.append(f"Server technology item #{i+1} is missing required 'serverTechnologyName'")
                    continue
                t_str = str(t_name).strip()
                t_lower = t_str.lower()
                if t_lower in SERVER_TECHNOLOGY_ALIASES:
                    warnings.append(
                        f"Server technology item #{i+1} '{t_str}' should use official predefined name '{SERVER_TECHNOLOGY_ALIASES[t_lower]}'."
                    )
                elif t_str not in OFFICIAL_SERVER_TECHNOLOGIES and t_lower not in official_lookup:
                    warnings.append(
                        f"Server technology item #{i+1} '{t_str}' is not recognized in F5 WAF for NGINX catalog and will cause SQLite NOT NULL constraint failures during compilation."
                    )

    # Validate URLs and urlContentProfiles
    urls = policy.get("urls")
    if urls is not None:
        if not isinstance(urls, list):
            errors.append("'policy.urls' must be an array")
        else:
            valid_content_profile_types = {
                "json", "xml", "graphql", "grpc", "form-data", "gwt", "do-nothing"
            }
            for u_idx, u in enumerate(urls):
                if not isinstance(u, dict):
                    errors.append(f"URL entry #{u_idx + 1} must be an object")
                    continue
                u_name = u.get("name", f"#{u_idx + 1}")
                if "name" not in u:
                    errors.append(f"URL entry #{u_idx + 1} is missing required 'name'")
                elif not isinstance(u["name"], str) or not u["name"].strip():
                    errors.append(f"URL entry #{u_idx + 1} 'name' must be a non-empty string")

                if "type" in u and u["type"] not in ("explicit", "wildcard"):
                    warnings.append(f"URL '{u_name}' type should be 'explicit' or 'wildcard'")

                # Validate urlContentProfiles
                content_profiles = u.get("urlContentProfiles")
                if content_profiles is not None:
                    if not isinstance(content_profiles, list):
                        errors.append(f"URL '{u_name}': 'urlContentProfiles' must be an array")
                    else:
                        for cp_idx, cp in enumerate(content_profiles):
                            if not isinstance(cp, dict):
                                errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} must be an object")
                                continue
                            cp_type = cp.get("type")
                            cp_type_str = str(cp_type).lower() if cp_type is not None else ""
                            if not cp_type:
                                errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} missing required 'type'")
                            elif cp_type_str not in valid_content_profile_types:
                                errors.append(
                                    f"URL '{u_name}' content profile #{cp_idx + 1}: Invalid content profile type '{cp_type}'. "
                                    f"Allowed types: {', '.join(sorted(valid_content_profile_types))}"
                                )
                            if "headerName" in cp and not isinstance(cp["headerName"], str):
                                errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} 'headerName' must be a string")
                            if "headerValue" in cp and not isinstance(cp["headerValue"], str):
                                errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} 'headerValue' must be a string")
                            if "headerOrder" in cp and not isinstance(cp["headerOrder"], (str, int)):
                                errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} 'headerOrder' must be a string or integer")
                            
                            if cp_type_str in ("json", "xml", "graphql", "grpc", "gwt"):
                                if "contentProfile" not in cp or not isinstance(cp.get("contentProfile"), dict) or not cp["contentProfile"].get("name"):
                                    errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} of type '{cp_type}' must specify 'contentProfile.name'")
                            elif "contentProfile" in cp:
                                if not isinstance(cp["contentProfile"], dict):
                                    errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} 'contentProfile' must be an object")
                                elif "name" not in cp["contentProfile"] or not cp["contentProfile"]["name"]:
                                    errors.append(f"URL '{u_name}' content profile #{cp_idx + 1} 'contentProfile' must contain 'name'")

    # Validate parameters
    params = policy.get("parameters")
    if params is not None and not isinstance(params, list):
        errors.append("'policy.parameters' must be an array")

    # Validate OpenAPI external references
    open_api_files = policy.get("open-api-files")
    open_api_ref = policy.get("openApiFileReference")

    if open_api_files is not None and open_api_ref is not None:
        warnings.append(
            "Both 'open-api-files' and 'openApiFileReference' are defined in the policy. F5 WAF for NGINX typically uses only one OpenAPI specification reference."
        )

    def _validate_link(link: Any, context: str) -> None:
        if not link or not isinstance(link, str):
            errors.append(f"{context} 'link' must be a non-empty string")
            return
        if not (link.startswith("http://") or link.startswith("https://") or link.startswith("file://")):
            errors.append(
                f"{context} 'link' must use 'http://', 'https://', or 'file:///'"
            )
        elif not any(link.lower().split("?")[0].endswith(ext) for ext in [".json", ".yaml", ".yml", ".txt"]):
            warnings.append(
                f"{context} 'link' usually references a .json, .yaml, .yml, or .txt specification file"
            )

    if open_api_files is not None:
        if not isinstance(open_api_files, list):
            errors.append("'policy.open-api-files' must be an array")
        else:
            if len(open_api_files) > 1:
                errors.append(
                    f"F5 WAF for NGINX supports only one OpenAPI specification file reference per policy ({len(open_api_files)} provided)."
                )
            for i, item in enumerate(open_api_files):
                if not isinstance(item, dict):
                    errors.append(f"OpenAPI file item #{i+1} must be an object")
                    continue
                _validate_link(item.get("link"), f"OpenAPI file item #{i+1}")
                if "basicAuth" in item:
                    errors.append(
                        f"OpenAPI file item #{i+1} contains 'basicAuth', which is not supported by F5 WAF for NGINX. "
                        "Remove 'basicAuth' from policy JSON; 'open-api-files' items must only contain 'link'."
                    )

    if open_api_ref is not None:
        if not isinstance(open_api_ref, dict):
            errors.append("'policy.openApiFileReference' must be an object")
        else:
            _validate_link(open_api_ref.get("link"), "'policy.openApiFileReference'")
            if "basicAuth" in open_api_ref:
                errors.append(
                    "'policy.openApiFileReference' contains 'basicAuth', which is not supported by F5 WAF for NGINX. "
                    "Remove 'basicAuth' from policy JSON; OpenAPI reference must only contain 'link'."
                )

    # Validate gRPC profiles
    grpc_profiles = policy.get("grpc-profiles")
    if grpc_profiles is not None:
        if not isinstance(grpc_profiles, list):
            errors.append("'policy.grpc-profiles' must be an array")
        else:
            for i, prof in enumerate(grpc_profiles):
                ctx = f"gRPC profile #{i+1}"
                if not isinstance(prof, dict):
                    errors.append(f"{ctx} must be an object")
                    continue
                prof_name = prof.get("name")
                if not prof_name or not isinstance(prof_name, str) or not prof_name.strip():
                    errors.append(f"{ctx} is missing required non-empty 'name' string")

                # decodeStringValuesAsBase64
                if "decodeStringValuesAsBase64" in prof:
                    b64_val = prof["decodeStringValuesAsBase64"]
                    if b64_val not in ("enabled", "disabled"):
                        errors.append(f"{ctx} 'decodeStringValuesAsBase64' must be 'enabled' or 'disabled'")

                # defenseAttributes
                def_attrs = prof.get("defenseAttributes")
                if def_attrs is not None:
                    if not isinstance(def_attrs, dict):
                        errors.append(f"{ctx} 'defenseAttributes' must be an object")
                    else:
                        if "maximumDataLength" in def_attrs:
                            max_len = def_attrs["maximumDataLength"]
                            if not isinstance(max_len, int) or max_len < 0:
                                errors.append(f"{ctx} 'defenseAttributes.maximumDataLength' must be a non-negative integer")
                            elif max_len > 10 * 1024 * 1024:
                                warnings.append(f"{ctx} 'defenseAttributes.maximumDataLength' exceeds 10 MB (10485760 bytes), which is F5 WAF for NGINX's maximum gRPC buffer size")
                        if "allowUnknownFields" in def_attrs:
                            if not isinstance(def_attrs["allowUnknownFields"], bool):
                                errors.append(f"{ctx} 'defenseAttributes.allowUnknownFields' must be a boolean")

                # idlFiles
                idl_files = prof.get("idlFiles")
                if idl_files is not None:
                    if not isinstance(idl_files, list):
                        errors.append(f"{ctx} 'idlFiles' must be an array")
                    else:
                        for j, idl_item in enumerate(idl_files):
                            idl_ctx = f"{ctx} IDL file #{j+1}"
                            if not isinstance(idl_item, dict):
                                errors.append(f"{idl_ctx} must be an object")
                                continue
                            idl_file_obj = idl_item.get("idlFile")
                            if not idl_file_obj or not isinstance(idl_file_obj, dict):
                                errors.append(f"{idl_ctx} must contain an 'idlFile' object")
                                continue

                            ref_path = idl_file_obj.get("$ref") or idl_file_obj.get("link") or idl_file_obj.get("fileName")
                            if not ref_path or not isinstance(ref_path, str):
                                errors.append(f"{idl_ctx} 'idlFile' must specify '$ref', 'link', or 'fileName'")
                                continue

                            # Validate scheme if URI
                            if ref_path.startswith(("http://", "https://", "file://")):
                                pass
                            elif ":" in ref_path and not ref_path.startswith(("http", "file")):
                                errors.append(f"{idl_ctx} reference must use 'http://', 'https://', or 'file:///' scheme")

                            # Check extension
                            lower_ref = ref_path.lower().split("?")[0]
                            is_tar = any(lower_ref.endswith(ext) for ext in [".tar", ".tgz", ".tar.gz"])
                            is_proto = lower_ref.endswith(".proto")
                            if not (is_tar or is_proto):
                                errors.append(f"{idl_ctx} has unsupported file extension: must point to a .proto file or .tar/.tgz archive bundle")

                            # If archive, check primaryIdlFileName
                            if is_tar:
                                primary_name = idl_item.get("primaryIdlFileName")
                                if not primary_name or not isinstance(primary_name, str) or not primary_name.strip():
                                    errors.append(f"{idl_ctx} references an archive bundle but requires 'primaryIdlFileName' (the entry-point .proto file)")
                                elif not primary_name.lower().endswith(".proto"):
                                    errors.append(f"{idl_ctx} 'primaryIdlFileName' must be a string ending in .proto")

    # Validate idl-files at policy root
    root_idl_files = policy.get("idl-files")
    if root_idl_files is not None:
        if not isinstance(root_idl_files, list):
            errors.append("'policy.idl-files' must be an array")
        else:
            for k, idl in enumerate(root_idl_files):
                k_ctx = f"Root IDL file #{k+1}"
                if not isinstance(idl, dict):
                    errors.append(f"{k_ctx} must be an object")
                    continue
                if not idl.get("link") and not idl.get("fileName"):
                    errors.append(f"{k_ctx} must provide 'link' or 'fileName'")

    # Validate data-guard (Data Loss Prevention)
    data_guard = policy.get("data-guard")
    if data_guard is not None:
        if not isinstance(data_guard, dict):
            errors.append("'policy.data-guard' must be an object")
        else:
            if "maskCreditCardNumbersInResponse" in data_guard:
                errors.append(
                    "Unknown field 'maskCreditCardNumbersInResponse' in data-guard. Use 'creditCardNumbers' (boolean) instead."
                )
            if "maskUssnInResponse" in data_guard:
                errors.append(
                    "Unknown field 'maskUssnInResponse' in data-guard. Use 'usSocialSecurityNumbers' (boolean) instead."
                )
            if "enabled" in data_guard and not isinstance(data_guard["enabled"], bool):
                errors.append("'policy.data-guard.enabled' must be a boolean")
            if "maskData" in data_guard and not isinstance(data_guard["maskData"], bool):
                errors.append("'policy.data-guard.maskData' must be a boolean")
            if "creditCardNumbers" in data_guard and not isinstance(data_guard["creditCardNumbers"], bool):
                errors.append("'policy.data-guard.creditCardNumbers' must be a boolean")
            if "usSocialSecurityNumbers" in data_guard and not isinstance(data_guard["usSocialSecurityNumbers"], bool):
                errors.append("'policy.data-guard.usSocialSecurityNumbers' must be a boolean")
            if "enforcementMode" in data_guard:
                val = data_guard["enforcementMode"]
                if val not in ("ignore-urls-in-list", "enforce-urls-in-list"):
                    errors.append(
                        f"Invalid 'policy.data-guard.enforcementMode': '{val}'. Must be 'ignore-urls-in-list' or 'enforce-urls-in-list'"
                    )
            if "enforcementUrls" in data_guard and not isinstance(data_guard["enforcementUrls"], list):
                errors.append("'policy.data-guard.enforcementUrls' must be an array")
            if "customPatterns" in data_guard and not isinstance(data_guard["customPatterns"], bool):
                errors.append("'policy.data-guard.customPatterns' must be a boolean (use 'customPatternsList' for regex strings)")
            if "customPatternsList" in data_guard and not isinstance(data_guard["customPatternsList"], list):
                errors.append("'policy.data-guard.customPatternsList' must be an array of regex pattern strings")

    # Validate cookies (Cookie Protection & Tampering Defense)
    cookies = policy.get("cookies")
    if cookies is not None:
        if not isinstance(cookies, list):
            errors.append("'policy.cookies' must be an array")
        else:
            for c_idx, c_item in enumerate(cookies):
                ctx = f"Cookie #{c_idx+1}"
                if not isinstance(c_item, dict):
                    errors.append(f"{ctx} must be an object")
                    continue
                c_name = c_item.get("name")
                if not c_name or not isinstance(c_name, str) or not c_name.strip():
                    errors.append(f"{ctx} must contain a non-empty string 'name'")
                else:
                    ctx = f"Cookie '{c_name}'"

                c_type = c_item.get("type")
                if c_type is not None and c_type not in ("explicit", "wildcard"):
                    errors.append(f"{ctx} invalid 'type': '{c_type}'. Must be 'explicit' or 'wildcard'")

                enf = c_item.get("enforcementType")
                if enf is not None and enf not in ("enforce", "allow"):
                    errors.append(f"{ctx} invalid 'enforcementType': '{enf}'. Must be 'enforce' or 'allow'")

                if "attackSignaturesCheck" in c_item and not isinstance(c_item["attackSignaturesCheck"], bool):
                    errors.append(f"{ctx} 'attackSignaturesCheck' must be a boolean")

                if "maskValueInLogs" in c_item and not isinstance(c_item["maskValueInLogs"], bool):
                    errors.append(f"{ctx} 'maskValueInLogs' must be a boolean")

                if "accessibleOnlyThroughTheHttpProtocol" in c_item and not isinstance(c_item["accessibleOnlyThroughTheHttpProtocol"], bool):
                    errors.append(f"{ctx} 'accessibleOnlyThroughTheHttpProtocol' must be a boolean")

                if "wildcardOrder" in c_item:
                    w_order = c_item["wildcardOrder"]
                    if not isinstance(w_order, int) or w_order < 1:
                        errors.append(f"{ctx} 'wildcardOrder' must be a positive integer (>= 1)")

    # Validate cookie-settings (Global Cookie Sizing & Constraints)
    cookie_settings = policy.get("cookie-settings")
    if cookie_settings is not None:
        if not isinstance(cookie_settings, dict):
            errors.append("'policy.cookie-settings' must be an object")
        else:
            if "maximumCookieHeaderLength" in cookie_settings:
                max_len = cookie_settings["maximumCookieHeaderLength"]
                if not (isinstance(max_len, int) and max_len >= 0) and max_len != "any":
                    errors.append("'policy.cookie-settings.maximumCookieHeaderLength' must be a non-negative integer or 'any'")

    # Validate enforcer-settings (Enforcer State Cookies)
    enforcer_settings = policy.get("enforcer-settings")
    if enforcer_settings is not None:
        if not isinstance(enforcer_settings, dict):
            errors.append("'policy.enforcer-settings' must be an object")
        else:
            enforcer_cookies = enforcer_settings.get("enforcerStateCookies")
            if enforcer_cookies is not None:
                if not isinstance(enforcer_cookies, dict):
                    errors.append("'policy.enforcer-settings.enforcerStateCookies' must be an object")
                else:
                    if "httpOnlyAttribute" in enforcer_cookies and not isinstance(enforcer_cookies["httpOnlyAttribute"], bool):
                        errors.append("'policy.enforcer-settings.enforcerStateCookies.httpOnlyAttribute' must be a boolean")
                    if "secureAttribute" in enforcer_cookies:
                        sec_attr = enforcer_cookies["secureAttribute"]
                        if sec_attr not in ("never", "always"):
                            errors.append(f"Invalid secureAttribute '{sec_attr}'. Must be 'never' or 'always'")
                    if "sameSiteAttribute" in enforcer_cookies:
                        ss_attr = enforcer_cookies["sameSiteAttribute"]
                        if ss_attr not in ("strict", "lax", "none", "none-value"):
                            errors.append(f"Invalid sameSiteAttribute '{ss_attr}'. Must be 'strict', 'lax', 'none', or 'none-value'")

    is_valid = len(errors) == 0
    return is_valid, errors, warnings, parsed


def validate_user_defined_signatures_file(
    content: Any,
) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    """
    Validate a standalone User-Defined Signatures JSON definition file.
    Follows official F5 specification: https://docs.nginx.com/waf/policies/user-signatures/#signatures
    """
    errors: List[str] = []
    warnings: List[str] = []
    parsed: Dict[str, Any] = {}

    if isinstance(content, str):
        try:
            content = json.loads(content)
        except json.JSONDecodeError as exc:
            return False, [f"Invalid JSON format: {exc}"], [], {}

    if not isinstance(content, dict):
        return False, ["User-defined signature definition must be a JSON object"], [], {}

    parsed = content

    # tag (recommended at root)
    tag = content.get("tag")
    if tag is not None and (not isinstance(tag, str) or not tag.strip()):
        errors.append("'tag' must be a non-empty string")
    elif not tag:
        warnings.append("No top-level 'tag' provided; default tag will be 'user-defined-signatures'")

    # revisionDatetime (optional ISO datetime)
    rev = content.get("revisionDatetime")
    if rev is not None and (not isinstance(rev, str) or not rev.strip()):
        errors.append("'revisionDatetime' must be an ISO 8601 formatted string (e.g. '2020-01-21T18:32:02Z')")

    # softwareVersion (optional string)
    version = content.get("softwareVersion")
    if version is not None and not isinstance(version, str):
        errors.append("'softwareVersion' must be a string (e.g. '15.1.0')")

    # signatures (required array)
    sigs = content.get("signatures")
    if sigs is None:
        errors.append("Missing required 'signatures' array")
    elif not isinstance(sigs, list):
        errors.append("'signatures' must be an array")
    else:
        seen_names = set()
        for idx, sig in enumerate(sigs):
            ctx = f"Signature #{idx+1}"
            if not isinstance(sig, dict):
                errors.append(f"{ctx} must be an object")
                continue

            name = sig.get("name")
            if not name or not isinstance(name, str) or not name.strip():
                errors.append(f"{ctx} is missing required non-empty 'name'")
            else:
                name_clean = name.strip()
                if name_clean in seen_names:
                    errors.append(f"Duplicate signature name '{name_clean}' in file (names must be unique within tag)")
                seen_names.add(name_clean)
                ctx = f"Signature '{name_clean}'"

            rule = sig.get("rule")
            if not rule or not isinstance(rule, str) or not rule.strip():
                errors.append(f"{ctx} is missing required 'rule' (Snort syntax)")
            else:
                s_valid, s_errs, s_warns, _ = validate_snort_rule(rule)
                for err in s_errs:
                    errors.append(f"{ctx} Snort rule error: {err}")
                for warn in s_warns:
                    warnings.append(f"{ctx} Snort rule warning: {warn}")


            sig_type = sig.get("signatureType", "request")
            if sig_type not in ("request", "response"):
                errors.append(f"{ctx} 'signatureType' must be 'request' or 'response'")

            risk = sig.get("risk", "medium")
            if risk not in ("low", "medium", "high"):
                errors.append(f"{ctx} 'risk' must be 'low', 'medium', or 'high'")

            accuracy = sig.get("accuracy", "medium")
            if accuracy not in ("low", "medium", "high"):
                errors.append(f"{ctx} 'accuracy' must be 'low', 'medium', or 'high'")

            attack_type = sig.get("attackType")
            if attack_type is not None:
                if isinstance(attack_type, dict):
                    if not attack_type.get("name") or not isinstance(attack_type["name"], str):
                        errors.append(f"{ctx} 'attackType.name' must be a non-empty string")
                elif isinstance(attack_type, str):
                    if not attack_type.strip():
                        errors.append(f"{ctx} 'attackType' must be a non-empty string")
                else:
                    errors.append(f"{ctx} 'attackType' must be an object with 'name' or a string")

            systems = sig.get("systems")
            if systems is not None:
                if not isinstance(systems, list):
                    errors.append(f"{ctx} 'systems' must be an array")
                else:
                    for s_idx, sys_item in enumerate(systems):
                        if isinstance(sys_item, dict):
                            if not sys_item.get("name") or not isinstance(sys_item["name"], str):
                                errors.append(f"{ctx} systems item #{s_idx+1} must contain a 'name' string")
                        elif not isinstance(sys_item, str) or not sys_item.strip():
                            errors.append(f"{ctx} systems item #{s_idx+1} must be an object with 'name' or a string")

    is_valid = len(errors) == 0
    return is_valid, errors, warnings, parsed

