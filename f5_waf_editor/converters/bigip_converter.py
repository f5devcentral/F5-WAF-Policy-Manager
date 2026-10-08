"""
BIG-IP WAF Policy Converter.
Converts BIG-IP ASM / Advanced WAF exported policies (JSON format) into F5 WAF for NGINX declarative JSON policies.
Follows the official F5 converter specification (https://docs.nginx.com/waf/configure/converters/).
"""

from __future__ import annotations
import gzip
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from ..schemas.validator import validate_policy_json
from ..schemas.waf_schema import (
    VIOLATIONS_CATALOG,
    SERVER_TECHNOLOGIES,
    STANDARD_SIGNATURE_SETS,
    ENFORCEMENT_MODES,
    SIGNATURE_SET_NAME_ALIASES,
    OFFICIAL_SIGNATURE_SET_NAMES,
    OFFICIAL_SERVER_TECHNOLOGIES,
    OFFICIAL_SERVER_TECHNOLOGY_LOOKUP,
    SERVER_TECHNOLOGY_ALIASES,
    NON_CONFIGURABLE_VIOLATIONS,
)

logger = logging.getLogger(__name__)

# Standard ASM violations that are unsupported in F5 WAF for NGINX
UNSUPPORTED_ASM_VIOLATIONS = {
    "VIOL_ASM_COOKIE_HIJACKING",
    "VIOL_BLOCKING_CONDITION",
    "VIOL_BRUTE_FORCE",
    "VIOL_CONVICTION",
    "VIOL_CROSS_ORIGIN_REQUEST",
    "VIOL_CSRF",
    "VIOL_CSRF_EXPIRED",
    "VIOL_DYNAMIC_SESSION",
    "VIOL_FLOW",
    "VIOL_FLOW_DISALLOWED_INPUT",
    "VIOL_FLOW_ENTRY_POINT",
    "VIOL_FLOW_MANDATORY_PARAMS",
    "VIOL_GEOLOCATION",
    "VIOL_GWT_FORMAT",
    "VIOL_GWT_MALFORMED",
    "VIOL_HOSTNAME_MISMATCH",
    "VIOL_LOGIN_URL_BYPASSED",
    "VIOL_LOGIN_URL_EXPIRED",
    "VIOL_MALICIOUS_DEVICE",
    "VIOL_MALICIOUS_IP",
    "VIOL_PARAMETER_DYNAMIC_VALUE",
    "VIOL_PLAINTEXT_FORMAT",
    "VIOL_REDIRECT",
    "VIOL_SESSION_AWARENESS",
    "VIOL_VIRUS",
    "VIOL_WEBSOCKET_BAD_REQUEST",
    "VIOL_WEBSOCKET_BINARY_MESSAGE_LENGTH",
    "VIOL_WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED",
    "VIOL_WEBSOCKET_EXTENSION",
    "VIOL_WEBSOCKET_FRAME_MASKING",
    "VIOL_WEBSOCKET_FRAMING_PROTOCOL",
    "VIOL_WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED",
}

# Unsupported BIG-IP ASM JSON features mapping to warnings
UNSUPPORTED_ASM_JSON_KEYS = [
    ("trafficLearning", "Traffic learning, staging, and policy building are unsupported in declarative F5 WAF for NGINX."),
    ("traffic-learning", "Traffic learning, staging, and policy building are unsupported in declarative F5 WAF for NGINX."),
    ("traffic_learning", "Traffic learning, staging, and policy building are unsupported in declarative F5 WAF for NGINX."),
    ("policyBuilding", "Policy building configuration is unsupported in declarative F5 WAF for NGINX."),
    ("policy-building", "Policy building configuration is unsupported in declarative F5 WAF for NGINX."),
    ("bruteForceProtection", "Brute-force protection module is unsupported in F5 WAF for NGINX."),
    ("brute_force_protection", "Brute-force protection module is unsupported in F5 WAF for NGINX."),
    ("bruteForce", "Brute-force protection module is unsupported in F5 WAF for NGINX."),
    ("brute-force", "Brute-force protection module is unsupported in F5 WAF for NGINX."),
    ("csrfProtection", "Cross-Site Request Forgery (CSRF) protection is unsupported in F5 WAF for NGINX."),
    ("csrf_protection", "Cross-Site Request Forgery (CSRF) protection is unsupported in F5 WAF for NGINX."),
    ("csrf", "Cross-Site Request Forgery (CSRF) protection is unsupported in F5 WAF for NGINX."),
    ("antivirus", "Antivirus inspection module is unsupported in F5 WAF for NGINX."),
    ("websocketUrls", "WebSocket URLs configuration is unsupported in F5 WAF for NGINX."),
    ("websocket-urls", "WebSocket URLs configuration is unsupported in F5 WAF for NGINX."),
    ("redirectionProtection", "Redirection protection is unsupported in F5 WAF for NGINX."),
    ("redirection-protection", "Redirection protection is unsupported in F5 WAF for NGINX."),
    ("plainTextProfiles", "Plain text profiles are unsupported in F5 WAF for NGINX."),
    ("plain-text-profiles", "Plain text profiles are unsupported in F5 WAF for NGINX."),
    ("gwtProfiles", "GWT profiles are unsupported in F5 WAF for NGINX."),
    ("gwt-profiles", "GWT profiles are unsupported in F5 WAF for NGINX."),
    ("eventCorrelation", "Event correlation is unsupported in F5 WAF for NGINX."),
    ("sessionAwareness", "Session awareness is unsupported in F5 WAF for NGINX."),
]


class BigIpPolicyConverter:
    """Orchestrates conversion of BIG-IP exported policies into F5 WAF for NGINX declarative JSON."""

    def __init__(self, converter_bin: Optional[str] = None):
        self.converter_bin = converter_bin or os.environ.get("WAF_CONVERTER_BIN")
        if not self.converter_bin:
            found = shutil.which("convert-policy")
            if found:
                self.converter_bin = found
            elif os.path.isfile("/opt/app_protect/bin/convert-policy") and os.access("/opt/app_protect/bin/convert-policy", os.X_OK):
                self.converter_bin = "/opt/app_protect/bin/convert-policy"

    def is_cli_available(self) -> bool:
        """Check if official convert-policy CLI is executable."""
        return bool(self.converter_bin and os.path.exists(self.converter_bin))

    def convert(
        self,
        content: bytes | str | dict,
        target_name: Optional[str] = None,
        full_export: bool = True,
        keep_full_configuration: bool = False,
        include_all_signatures: bool = False,
    ) -> Dict[str, Any]:
        """Convert a BIG-IP policy export (JSON) to an F5 WAF for NGINX declarative policy."""
        # 1. If convert-policy CLI is available and input is raw bytes/string, attempt CLI conversion
        if self.is_cli_available() and not isinstance(content, dict):
            try:
                cli_res = self._convert_via_cli(
                    content,
                    target_name=target_name,
                    full_export=full_export,
                    keep_full_configuration=keep_full_configuration,
                    include_all_signatures=include_all_signatures,
                )
                if cli_res.get("success"):
                    return cli_res
                logger.warning("convert-policy CLI failed: %s. Using built-in engine.", cli_res.get("error"))
            except Exception as e:
                logger.warning("Exception running convert-policy CLI: %s. Using built-in engine.", e)

        # 2. Built-in converter engine
        return self._convert_built_in(
            content,
            target_name=target_name,
            full_export=full_export,
            keep_full_configuration=keep_full_configuration,
            include_all_signatures=include_all_signatures,
        )

    def _convert_via_cli(
        self,
        content: bytes | str,
        target_name: Optional[str] = None,
        full_export: bool = True,
        keep_full_configuration: bool = False,
        include_all_signatures: bool = False,
    ) -> Dict[str, Any]:
        """Execute the official convert-policy CLI binary."""
        if not self.converter_bin:
            return {"success": False, "error": "convert-policy binary not found"}

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "bigip_policy.json")
            output_file = os.path.join(tmpdir, "policy.json")

            data = content if isinstance(content, bytes) else content.encode("utf-8")
            with open(input_file, "wb") as f:
                f.write(data)

            cmd = [self.converter_bin, "-i", input_file, "-o", output_file]
            if full_export:
                cmd.append("-full-export")
            if keep_full_configuration:
                cmd.append("-keep-full-configuration")
            if include_all_signatures:
                cmd.append("-include-all-signatures")

            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if proc.returncode != 0 or not os.path.exists(output_file):
                return {
                    "success": False,
                    "error": proc.stderr or proc.stdout or f"convert-policy exited with code {proc.returncode}",
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                }

            with open(output_file, "r", encoding="utf-8") as f:
                converted_policy = json.load(f)

            policy_body = converted_policy.get("policy", converted_policy)
            if target_name:
                policy_body["name"] = target_name
                converted_policy["policy"] = policy_body

            warnings = []
            if proc.stderr:
                for line in proc.stderr.splitlines():
                    if "warn" in line.lower() or "unsupported" in line.lower():
                        warnings.append(line.strip())

            return {
                "success": True,
                "policy_name": policy_body.get("name", target_name or "bigip_policy"),
                "policy": converted_policy if "policy" in converted_policy else {"policy": converted_policy},
                "warnings": warnings,
                "engine": "convert-policy-cli",
            }

    def _convert_built_in(
        self,
        content: bytes | str | dict,
        target_name: Optional[str] = None,
        full_export: bool = True,
        keep_full_configuration: bool = False,
        include_all_signatures: bool = False,
    ) -> Dict[str, Any]:
        """Built-in pure-Python converter engine for BIG-IP exported policies."""
        warnings: List[str] = []

        # Parse JSON input
        parsed_json: Optional[Dict[str, Any]] = None
        if isinstance(content, dict):
            parsed_json = content
        else:
            raw_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            # Handle gzipped payload if present
            if raw_bytes[:2] == b"\x1f\x8b":
                try:
                    raw_bytes = gzip.decompress(raw_bytes)
                except Exception as e:
                    return {"success": False, "error": f"Failed to decompress gzip content: {e}"}

            raw_str = raw_bytes.decode("utf-8", errors="replace").strip()

            # Check if user accidentally uploaded XML, and parse XML if so
            if raw_str.startswith("<") or "<?xml" in raw_str[:20]:
                return self._convert_xml_fallback(raw_str, target_name)

            try:
                parsed_json = json.loads(raw_str)
            except json.JSONDecodeError as jde:
                return {
                    "success": False,
                    "error": f"Invalid JSON policy format: {jde.msg} (line {jde.lineno}, col {jde.colno})",
                }

        if not isinstance(parsed_json, dict):
            return {"success": False, "error": "Policy root must be a JSON object"}

        # Extract root policy dictionary
        # BIG-IP exports may wrap in "policy": {...} or provide root-level keys
        policy_dict: Dict[str, Any] = parsed_json.get("policy", parsed_json)
        if not isinstance(policy_dict, dict):
            policy_dict = parsed_json

        # 1. Policy Name & Description
        extracted_name = policy_dict.get("name") or parsed_json.get("name") or "bigip_policy"
        final_name = target_name or extracted_name
        description = policy_dict.get("description") or f"Converted from BIG-IP WAF policy ({extracted_name})"

        # 2. Enforcement Mode
        raw_mode = str(policy_dict.get("enforcementMode") or policy_dict.get("enforcement_mode") or "blocking").lower()
        enforcement_mode = "transparent" if "trans" in raw_mode or raw_mode in ("0", "false") else "blocking"

        # 3. Application Language
        app_lang = str(policy_dict.get("applicationLanguage") or policy_dict.get("application_language") or "utf-8").lower()
        if app_lang not in ("utf-8", "iso-8859-1", "windows-1252", "shift_jis", "euc-jp", "big5"):
            app_lang = "utf-8"

        # 4. Check for unsupported BIG-IP ASM features and record warnings
        for key, msg in UNSUPPORTED_ASM_JSON_KEYS:
            if key in policy_dict or key in parsed_json:
                warnings.append(msg)

        # 5. Server Technologies
        server_technologies: List[Dict[str, str]] = []
        raw_techs = policy_dict.get("server-technologies") or policy_dict.get("serverTechnologies") or policy_dict.get("server_technologies") or []
        if isinstance(raw_techs, list):
            for item in raw_techs:
                t_name = ""
                if isinstance(item, str):
                    t_name = item.strip()
                elif isinstance(item, dict):
                    t_name = (item.get("serverTechnologyName") or item.get("name") or "").strip()
                if not t_name:
                    continue
                t_lower = t_name.lower()
                canonical = None
                if t_lower in SERVER_TECHNOLOGY_ALIASES:
                    canonical = SERVER_TECHNOLOGY_ALIASES[t_lower]
                elif t_lower in OFFICIAL_SERVER_TECHNOLOGY_LOOKUP:
                    canonical = OFFICIAL_SERVER_TECHNOLOGY_LOOKUP[t_lower]

                if canonical:
                    if not any(st["serverTechnologyName"] == canonical for st in server_technologies):
                        server_technologies.append({"serverTechnologyName": canonical})
                else:
                    warnings.append(
                        f"Server technology '{t_name}' is not recognized in F5 WAF for NGINX catalog and was omitted to prevent SQLite NOT NULL constraint failures."
                    )

        # 6. Signature Sets
        signature_sets: List[Dict[str, Any]] = []
        raw_sig_sets = policy_dict.get("signature-sets") or policy_dict.get("signatureSets") or policy_dict.get("signature_sets") or []
        if isinstance(raw_sig_sets, list):
            for sset in raw_sig_sets:
                if isinstance(sset, dict):
                    s_name = (sset.get("name") or "").strip()
                    if not s_name:
                        continue

                    # Threat Campaigns in F5 WAF for NGINX is a violation, not a signature set
                    if s_name.lower() in ("threat campaigns", "threat-campaigns", "threat campaign"):
                        tc_viol = next((v for v in violations if v.get("name") == "VIOL_THREAT_CAMPAIGN"), None)
                        if tc_viol:
                            tc_viol["alarm"] = bool(sset.get("alarm", True))
                            tc_viol["block"] = bool(sset.get("block", True))
                        else:
                            violations.append({
                                "name": "VIOL_THREAT_CAMPAIGN",
                                "alarm": bool(sset.get("alarm", True)),
                                "block": bool(sset.get("block", True)),
                            })
                        warnings.append("Threat Campaigns signature set converted to 'VIOL_THREAT_CAMPAIGN' violation in blocking-settings.")
                        continue

                    # Rewrite aliases
                    if s_name.lower() in SIGNATURE_SET_NAME_ALIASES:
                        canonical = SIGNATURE_SET_NAME_ALIASES[s_name.lower()]
                        warnings.append(f"Signature set '{s_name}' normalized to official F5 WAF name '{canonical}'.")
                        s_name = canonical
                    elif "signatureSet" not in sset and s_name not in OFFICIAL_SIGNATURE_SET_NAMES:
                        warnings.append(
                            f"Signature set '{s_name}' omitted: not recognized as an official predefined F5 WAF set and has no custom definition."
                        )
                        continue

                    # If custom signatureSet is present, ensure valid definition
                    if "signatureSet" in sset and isinstance(sset["signatureSet"], dict):
                        cs = sset["signatureSet"]
                        if not cs.get("type"):
                            if "filter" in cs:
                                cs["type"] = "filter-based"
                            elif "signatures" in cs:
                                cs["type"] = "manual"
                        if not cs.get("filter") and not cs.get("signatures"):
                            warnings.append(f"Signature set '{s_name}' omitted: custom definition has no filter or signatures.")
                            continue

                    set_obj: Dict[str, Any] = {
                        "name": s_name,
                        "alarm": bool(sset.get("alarm", True)),
                        "block": bool(sset.get("block", True)),
                    }
                    if "signatureSet" in sset and isinstance(sset["signatureSet"], dict):
                        set_obj["signatureSet"] = sset["signatureSet"]
                    signature_sets.append(set_obj)

        # 7. Individual Signatures
        signatures: List[Dict[str, Any]] = []
        raw_sigs = policy_dict.get("signatures") or []
        if isinstance(raw_sigs, list):
            for sig in raw_sigs:
                if isinstance(sig, dict):
                    sig_id = sig.get("signatureId") or sig.get("signature_id") or sig.get("id")
                    if sig_id is not None:
                        try:
                            sid_int = int(sig_id)
                            sig_entry: Dict[str, Any] = {
                                "signatureId": sid_int,
                                "enabled": bool(sig.get("enabled", True)),
                            }
                            if "tag" in sig and sig["tag"]:
                                sig_entry["tag"] = str(sig["tag"])
                            signatures.append(sig_entry)
                        except (ValueError, TypeError):
                            pass

        # 8. URLs
        urls: List[Dict[str, Any]] = []
        raw_urls = policy_dict.get("urls") or []
        if isinstance(raw_urls, list):
            for u in raw_urls:
                if isinstance(u, dict):
                    u_name = u.get("name") or ""
                    if u_name:
                        u_type = u.get("type", "explicit")
                        if u_type not in ("explicit", "wildcard"):
                            u_type = "wildcard" if "*" in u_name else "explicit"
                        proto = str(u.get("protocol", "http")).lower()
                        if proto not in ("http", "https", "all"):
                            proto = "http"
                        url_entry: Dict[str, Any] = {
                            "name": u_name,
                            "type": u_type,
                            "protocol": proto,
                        }
                        if "method" in u and u["method"]:
                            url_entry["method"] = str(u["method"]).upper()
                        urls.append(url_entry)

        # 9. Parameters
        parameters: List[Dict[str, Any]] = []
        raw_params = policy_dict.get("parameters") or []
        if isinstance(raw_params, list):
            for p in raw_params:
                if isinstance(p, dict):
                    p_name = p.get("name") or ""
                    if p_name:
                        p_type = p.get("type", "explicit")
                        if p_type not in ("explicit", "wildcard"):
                            p_type = "wildcard" if "*" in p_name else "explicit"
                        param_entry: Dict[str, Any] = {
                            "name": p_name,
                            "type": p_type,
                            "valueType": p.get("valueType") or p.get("value_type") or "user-input",
                        }
                        if "parameterLocation" in p or "parameter_location" in p:
                            loc = p.get("parameterLocation") or p.get("parameter_location")
                            if loc in ("query", "cookie", "header", "path", "any"):
                                param_entry["parameterLocation"] = loc
                        parameters.append(param_entry)

        # 10. Blocking Settings & Violations
        blocking_settings: Dict[str, Any] = {}
        violations: List[Dict[str, Any]] = []
        raw_bs = policy_dict.get("blocking-settings") or policy_dict.get("blockingSettings") or policy_dict.get("blocking_settings") or {}
        raw_viols = raw_bs.get("violations") if isinstance(raw_bs, dict) else []
        if isinstance(raw_viols, list):
            valid_viol_names = {v["name"] for v in VIOLATIONS_CATALOG}
            for v in raw_viols:
                if isinstance(v, dict):
                    v_name = v.get("name") or ""
                    if not v_name:
                        continue
                    if v_name in UNSUPPORTED_ASM_VIOLATIONS or v_name not in valid_viol_names:
                        warnings.append(
                            f"Violation '{v_name}' is a BIG-IP ASM-specific violation not supported in F5 WAF for NGINX (removed)."
                        )
                        continue
                    violations.append({
                        "name": v_name,
                        "alarm": bool(v.get("alarm", True)),
                        "block": bool(v.get("block", True)),
                    })
        if violations:
            blocking_settings["violations"] = violations

        # 11. Whitelist IPs
        whitelist_ips: List[Dict[str, Any]] = []
        raw_ips = policy_dict.get("whitelist-ips") or policy_dict.get("whitelistIps") or policy_dict.get("whitelist_ips") or []
        if isinstance(raw_ips, list):
            for ip in raw_ips:
                if isinstance(ip, dict) and (ip.get("ipAddress") or ip.get("ip_address") or ip.get("ip")):
                    whitelist_ips.append({
                        "ipAddress": ip.get("ipAddress") or ip.get("ip_address") or ip.get("ip"),
                        "ipMask": ip.get("ipMask") or ip.get("ip_mask") or "255.255.255.255",
                        "block": bool(ip.get("block", False)),
                    })

        # 12. OpenAPI Files (ensure no forbidden basicAuth)
        open_api_files: List[Dict[str, Any]] = []
        raw_oas = policy_dict.get("open-api-files") or policy_dict.get("openApiFiles") or policy_dict.get("open_api_files") or []
        if isinstance(raw_oas, list):
            for oas in raw_oas:
                if isinstance(oas, dict) and "link" in oas:
                    open_api_files.append({"link": oas["link"]})
                elif isinstance(oas, dict) and "basicAuth" in oas:
                    warnings.append("Stripped 'basicAuth' from open-api-files (F5 WAF for NGINX declarative policies require 'link' only).")
                    if "link" in oas:
                        open_api_files.append({"link": oas["link"]})

        # Assemble final F5 WAF for NGINX declarative policy
        final_policy_body: Dict[str, Any] = {
            "name": final_name,
            "description": description,
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": enforcement_mode,
            "applicationLanguage": app_lang,
        }

        if server_technologies:
            final_policy_body["server-technologies"] = server_technologies
        if signature_sets:
            final_policy_body["signature-sets"] = signature_sets
        if signatures:
            final_policy_body["signatures"] = signatures
        if urls:
            final_policy_body["urls"] = urls
        if parameters:
            final_policy_body["parameters"] = parameters
        if blocking_settings:
            final_policy_body["blocking-settings"] = blocking_settings
        if whitelist_ips:
            final_policy_body["whitelist-ips"] = whitelist_ips
        if open_api_files:
            final_policy_body["open-api-files"] = open_api_files

        full_doc = {"policy": final_policy_body}

        # Normalize and validate with standard F5 WAF validator
        is_valid, val_errs, val_warns, validated = validate_policy_json(full_doc)
        warnings.extend(val_warns)

        if not is_valid:
            warnings.extend([f"Schema notice: {e}" for e in val_errs])

        return {
            "success": True,
            "policy_name": final_name,
            "policy": validated if validated else full_doc,
            "warnings": warnings,
            "engine": "built-in-json-converter",
        }

    def _convert_xml_fallback(self, xml_str: str, target_name: Optional[str] = None) -> Dict[str, Any]:
        """Fallback parser if user provided XML instead of JSON."""
        warnings: List[str] = ["Input was detected as XML format; converted using built-in XML parser."]
        try:
            root = ET.fromstring(xml_str)
        except Exception as e:
            return {"success": False, "error": f"Failed to parse XML: {e}"}

        policy_elem = root if "policy" in root.tag.lower() else (root.find(".//policy") or root)

        def _find(elem, *names, default=""):
            for n in names:
                if n in elem.attrib and elem.attrib[n]:
                    return elem.attrib[n].strip()
                for k, v in elem.attrib.items():
                    if k.lower() == n.lower() and v:
                        return v.strip()
                c = elem.find(n)
                if c is not None and c.text:
                    return c.text.strip()
            return default

        p_name = target_name or _find(policy_elem, "name", default="bigip_policy")
        p_desc = _find(policy_elem, "description", default="Converted from BIG-IP policy")
        raw_mode = _find(policy_elem, "enforcement_mode", "enforcementMode", default="blocking").lower()
        mode = "transparent" if "trans" in raw_mode or raw_mode in ("0", "false") else "blocking"

        urls = []
        for u in policy_elem.findall(".//url"):
            u_name = _find(u, "name")
            if u_name:
                urls.append({
                    "name": u_name,
                    "type": _find(u, "type", default="explicit"),
                    "protocol": _find(u, "protocol", default="http"),
                })

        params = []
        for p in policy_elem.findall(".//parameter"):
            p_name = _find(p, "name")
            if p_name:
                params.append({
                    "name": p_name,
                    "type": _find(p, "type", default="explicit"),
                    "valueType": _find(p, "value_type", "valueType", default="user-input"),
                })

        techs = []
        seen_techs = set()
        for t in policy_elem.findall(".//technology"):
            t_name = _find(t, "name")
            if t_name:
                t_lower = t_name.strip().lower()
                canonical = None
                if t_lower in SERVER_TECHNOLOGY_ALIASES:
                    canonical = SERVER_TECHNOLOGY_ALIASES[t_lower]
                elif t_lower in OFFICIAL_SERVER_TECHNOLOGY_LOOKUP:
                    canonical = OFFICIAL_SERVER_TECHNOLOGY_LOOKUP[t_lower]
                if canonical and canonical not in seen_techs:
                    seen_techs.add(canonical)
                    techs.append({"serverTechnologyName": canonical})

        doc = {
            "policy": {
                "name": p_name,
                "description": p_desc,
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": mode,
                "urls": urls,
                "parameters": params,
                "server-technologies": techs,
            }
        }
        return {
            "success": True,
            "policy_name": p_name,
            "policy": doc,
            "warnings": warnings,
            "engine": "built-in-xml-fallback",
        }


def convert_bigip_policy(
    content: bytes | str | dict,
    target_name: Optional[str] = None,
    full_export: bool = True,
    keep_full_configuration: bool = False,
    include_all_signatures: bool = False,
) -> Dict[str, Any]:
    """Convenience helper function to convert BIG-IP policy exports (JSON format)."""
    converter = BigIpPolicyConverter()
    return converter.convert(
        content=content,
        target_name=target_name,
        full_export=full_export,
        keep_full_configuration=keep_full_configuration,
        include_all_signatures=include_all_signatures,
    )


# Alias for backwards compatibility
convert_bigip_policy_xml = convert_bigip_policy
convert_bigip_policy_json = convert_bigip_policy
