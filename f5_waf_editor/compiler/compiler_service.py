"""
F5 WAF for NGINX Compiler Testing Service.
Executes policy and logging profile compilation against the official apcompile CLI,
Docker container, or built-in compiler verification engine.
Follows the official F5 documentation (https://docs.nginx.com/waf/configure/compiler/).
"""

from __future__ import annotations
import copy
import datetime
import hashlib
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ..schemas.validator import validate_policy_json, POLICY_NAME_REGEX
from ..schemas.logging_validator import validate_logging_profile_json
from ..schemas.waf_schema import (
    VIOLATIONS_CATALOG,
    SERVER_TECHNOLOGIES,
    STANDARD_SIGNATURE_SETS,
    sanitize_waf_policy,
)

logger = logging.getLogger(__name__)

# In-memory bundle store for downloads (keyed by bundle_id)
COMPILED_BUNDLES_CACHE: Dict[str, Dict[str, Any]] = {}
MAX_CACHED_BUNDLES = 10
BUNDLE_TTL_SECONDS = 1800  # 30 minutes


def _kill_process_group_and_descendants(pid: int):
    """Aggressively terminate and kill a process group and any lingering child processes."""
    if not pid or pid <= 0:
        return

    # 1. Kill process group on POSIX
    if sys.platform != "win32":
        try:
            pgid = os.getpgid(pid)
            try:
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            time.sleep(0.05)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # 2. Sweep /proc on Linux to catch and kill any orphan compiler/helper processes (apcompile, bd, perl)
    if sys.platform.startswith("linux"):
        try:
            current_pid = os.getpid()
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                p = int(entry)
                if p in (1, current_pid):
                    continue
                try:
                    with open(f"/proc/{p}/cmdline", "rb") as f:
                        cmdline = f.read().decode("utf-8", errors="ignore").replace("\x00", " ")
                    # If this is an apcompile, perl, bd, or app_protect worker process, kill it
                    if any(target in cmdline.lower() for target in ("apcompile", "bd ", "bd_daemon", "bdt", "perl", "app_protect")):
                        logger.warning("Terminating leftover compiler helper process (PID: %d, CMD: %s)", p, cmdline[:80])
                        try:
                            os.kill(p, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
        except Exception as e:
            logger.debug("Error during process sweep: %s", e)


# Official F5 Compiler Remediation Database (from docs.nginx.com/waf/configure/compiler/)
REMEDIATION_MAP = {
    "Expected declarative policy": "Ensure the JSON of the policy is well-formed with a top-level 'policy' key and valid syntax.",
    "Policy Bundles version is older than the local version": "You must recompile all your bundles from scratch when installing security updates.",
    "Policy Bundles version is newer than the local version": "You must recompile all your bundles from scratch when installing security updates.",
    "Found mixed content of compiled and raw configuration": "Only pre-compiled bundles can be used in NGINX configuration: compile JSON to bundles first.",
    "Compiler is required, but not installed: Missing /opt/app_protect/bin/config_set_compiler": "The compiler binary is missing. Use pre-compiled bundles or deploy the F5 WAF compiler container.",
    "Policy Bundles have differing global states": "Recompile all of your bundles from scratch with your custom compiler. Bundles must be compiled with the same compiler: you cannot mix default and custom bundles.",
    "Policy Bundles have differing cookie seeds": "Recompile all of your bundles from scratch with a unified cookie protection seed in global_settings.json.",
    "Duplicate policy name found": "Don't compile multiple policies with the same name, or one policy to multiple bundles. Each policy can be compiled once but a bundle can be re-used.",
    "Duplicate logging profile name found": "Don't compile the same logging profile to multiple bundles. Each profile can be compiled once but a bundle can be re-used.",
    "Timeout waiting for enforcer": "Internal timeout waiting for enforcer engine. Verify system resources or restart the container.",
    "PLC.NEGSIG_SET_SIGNATURES": "One or more signature sets in '/policy/signature-sets' have unknown names or invalid custom definitions. In F5 WAF for NGINX, predefined sets must match official names (e.g. 'Path Traversal Signatures' instead of 'Directory Traversal Signatures'), and 'Threat Campaigns' must be configured via VIOL_THREAT_CAMPAIGN in blocking-settings.",
    "signature-sets' element": "One or more signature sets in '/policy/signature-sets' failed SQLite import. Ensure signature set names match official F5 WAF for NGINX predefined names or provide valid 'signatureSet' objects.",
    "FOREIGN KEY constraint failed": "A referenced signature, signature set, or server technology was not found in the compiler database. Ensure valid official names and IDs are used.",
    "PL_SERVER_TECHNOLOGIES": "One or more server technologies in '/policy/server-technologies' are unrecognized. In F5 WAF for NGINX, predefined server technologies must match official names (e.g. 'Apache/NCSA HTTP Server' instead of 'Apache', 'IIS' instead of 'Microsoft IIS').",
    "server-technologies' element": "One or more server technologies in '/policy/server-technologies' failed SQLite import. Ensure server technology names match official F5 WAF for NGINX predefined names.",
    "server_technology_id": "Failed lookup for server technology ID. In F5 WAF for NGINX, server technologies must match official predefined names (e.g. 'Apache/NCSA HTTP Server' instead of 'Apache', 'IIS' instead of 'Microsoft IIS').",
    "cannot be configured": "Violations such as 'VIOL_ATTACK_SIGNATURE' (governed by signature sets) and 'VIOL_BOT_CLIENT' (governed by bot defense) cannot be configured directly under '/blocking-settings/violations' in F5 WAF for NGINX.",
    "Unknown path 'custom-signatures'": "In F5 WAF for NGINX, user-defined custom signatures cannot be embedded directly in policy.json under 'custom-signatures'. They must be passed as an external user-defined signatures file via '-s' to apcompile.",
    "custom-signatures": "User-defined signatures cannot be embedded directly in policy.json. In F5 WAF for NGINX, they must be supplied via an external JSON file with '-s' flag and referenced by tag in '/policy/signature-requirements'.",
    "signature-requirements' element": "One or more tags in '/policy/signature-requirements' failed verification. Ensure each referenced tag is defined in an accompanying user-defined signatures file passed via '-s' to apcompile.",
    "tag does not exist": "The tag referenced in '/policy/signature-requirements' does not exist in any provided user-defined signature files. Ensure a user-defined signature file for this tag is supplied via '-s' to apcompile.",
}


class WafCompilerService:
    """Service to test compilation of WAF policies and logging profiles into .tgz bundles."""

    def __init__(
        self,
        compiler_bin: Optional[str] = None,
        compiler_service_url: Optional[str] = None,
    ):
        self.compiler_service_url = (
            compiler_service_url
            if compiler_service_url is not None
            else os.environ.get("COMPILER_SERVICE_URL", "")
        )
        self.compiler_bin = compiler_bin or os.environ.get("WAF_COMPILER_BIN")
        if not self.compiler_bin:
            # Look for apcompile or config_set_compiler in PATH or standard F5 directory
            for candidate in ("apcompile", "config_set_compiler"):
                found = shutil.which(candidate)
                if found:
                    self.compiler_bin = found
                    break
            if not self.compiler_bin:
                for path in (
                    "/opt/app_protect/bin/apcompile",
                    "/opt/app_protect/bin/config_set_compiler",
                ):
                    if os.path.isfile(path) and os.access(path, os.X_OK):
                        self.compiler_bin = path
                        break

    def is_cli_available(self) -> bool:
        """Check if official apcompile CLI binary is executable."""
        return bool(self.compiler_bin and os.path.exists(self.compiler_bin))

    def _prepare_user_signatures_and_policy(
        self,
        content: Any,
        user_signatures: Optional[Any] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]]]:
        """
        Extract user-defined signatures, load missing required tags from storage,
        normalize signatures by tag, and strip custom-signatures from policy.json so that
        the declarative policy adheres strictly to F5 schema without 'Unknown path custom-signatures'.

        Returns:
            (clean_policy, sigs_by_tag)
        """
        policy_doc = copy.deepcopy(content) if isinstance(content, dict) else {}
        had_wrapper = "policy" in policy_doc and isinstance(policy_doc["policy"], dict)
        pol_body = policy_doc["policy"] if had_wrapper else policy_doc

        raw_sigs: List[Dict[str, Any]] = []

        # 1. Signatures embedded in policy document
        if isinstance(pol_body, dict):
            cs_embedded = pol_body.pop("custom-signatures", None) or pol_body.pop("user-defined-signatures", None) or []
            if isinstance(cs_embedded, list):
                raw_sigs.extend(cs_embedded)
            elif isinstance(cs_embedded, dict):
                raw_sigs.append(cs_embedded)

        # 2. Signatures passed explicitly as argument
        if user_signatures:
            if isinstance(user_signatures, dict):
                if "signatures" in user_signatures and isinstance(user_signatures["signatures"], list):
                    tag = user_signatures.get("tag") or "custom"
                    for s in user_signatures["signatures"]:
                        if isinstance(s, dict):
                            s_copy = copy.deepcopy(s)
                            if not s_copy.get("tag"):
                                s_copy["tag"] = tag
                            raw_sigs.append(s_copy)
                else:
                    raw_sigs.append(user_signatures)
            elif isinstance(user_signatures, list):
                for item in user_signatures:
                    if isinstance(item, dict):
                        if "signatures" in item and isinstance(item["signatures"], list):
                            tag = item.get("tag") or "custom"
                            for s in item["signatures"]:
                                if isinstance(s, dict):
                                    s_copy = copy.deepcopy(s)
                                    if not s_copy.get("tag"):
                                        s_copy["tag"] = tag
                                    raw_sigs.append(s_copy)
                        else:
                            raw_sigs.append(item)

        # Group signatures by tag
        sigs_by_tag: Dict[str, List[Dict[str, Any]]] = {}
        for sig in raw_sigs:
            if not isinstance(sig, dict):
                continue
            tag = sig.get("tag") or "custom"
            sigs_by_tag.setdefault(tag, []).append(sig)

        # 3. Inspect signature-requirements in policy
        if isinstance(pol_body, dict):
            sig_reqs = pol_body.get("signature-requirements")
            if isinstance(sig_reqs, list):
                storage = None
                try:
                    from ..storage import get_custom_signatures_storage

                    storage = get_custom_signatures_storage()
                except Exception:
                    pass

                for req in sig_reqs:
                    if isinstance(req, dict) and req.get("tag"):
                        req_tag = req["tag"]
                        if req_tag not in sigs_by_tag:
                            if storage:
                                try:
                                    file_data = storage.get_signature_file(req_tag)
                                    if file_data and isinstance(file_data.get("signatures"), list):
                                        sigs_by_tag[req_tag] = file_data.get("signatures", [])
                                except Exception:
                                    pass
                            # If still not found, provide empty signature set for this tag so apcompile registers it
                            if req_tag not in sigs_by_tag:
                                sigs_by_tag[req_tag] = []

            # Ensure all tags that have custom signatures are present in signature-requirements
            if sigs_by_tag:
                current_reqs = pol_body.setdefault("signature-requirements", [])
                existing_tags = {r.get("tag") for r in current_reqs if isinstance(r, dict) and r.get("tag")}
                for tag in sigs_by_tag:
                    if tag not in existing_tags:
                        current_reqs.append({"tag": tag})
                        existing_tags.add(tag)

        # 4. Clean policy: ensure NO custom-signatures or user-defined-signatures
        clean_policy = copy.deepcopy(policy_doc)
        if isinstance(clean_policy, dict):
            pol_root = clean_policy.get("policy", clean_policy)
            if isinstance(pol_root, dict):
                pol_root.pop("custom-signatures", None)
                pol_root.pop("user-defined-signatures", None)
            if had_wrapper and "policy" not in clean_policy:
                clean_policy = {"policy": clean_policy}

        return clean_policy, sigs_by_tag

    def _compile_via_service(
        self,
        target_type: str,
        content: Dict[str, Any],
        target_name: Optional[str],
        include_source: bool,
        full_export: bool,
        global_settings: Optional[Dict[str, Any]],
        start_time: float,
        user_signatures: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Dispatch compilation request to the apcompile service container."""
        import urllib.request
        import urllib.error
        import base64

        clean_policy = content
        user_sig_docs: List[Dict[str, Any]] = []

        if target_type == "policy":
            clean_policy, sigs_by_tag = self._prepare_user_signatures_and_policy(content, user_signatures)
            clean_policy = sanitize_waf_policy(clean_policy, for_compilation=True)
            for tag, sigs in sigs_by_tag.items():
                user_sig_docs.append({
                    "softwareVersion": "15.1.0",
                    "tag": tag,
                    "signatures": sigs,
                })
        else:
            clean_policy = sanitize_waf_policy(copy.deepcopy(content)) if isinstance(content, dict) else content

        primary_user_sig = user_sig_docs if len(user_sig_docs) > 1 else (user_sig_docs[0] if user_sig_docs else None)

        req_data = {
            "target_type": target_type,
            "content": clean_policy,
            "target_name": target_name,
            "include_source": include_source,
            "full_export": full_export,
            "global_settings": global_settings,
        }
        if primary_user_sig:
            req_data["user_signatures"] = primary_user_sig
            req_data["user-signatures"] = primary_user_sig

        url = f"{self.compiler_service_url.rstrip('/')}/compile"
        json_bytes = json.dumps(req_data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=json_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "f5-waf-editor"},
            method="POST",
        )

        resp_data = None
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as he:
            # Fallback for containers exposing /v1/compile/policy if /compile returned 404
            if he.code == 404 and target_type == "policy":
                try:
                    v1_url = f"{self.compiler_service_url.rstrip('/')}/v1/compile/policy"
                    v1_data = {
                        "policy": clean_policy,
                        "user-signatures": primary_user_sig,
                        "globalsettings": global_settings,
                        "target_name": target_name,
                    }
                    v1_req = urllib.request.Request(
                        v1_url,
                        data=json.dumps(v1_data).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "f5-waf-editor"},
                        method="POST",
                    )
                    with urllib.request.urlopen(v1_req, timeout=30) as resp:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                except Exception as v1_e:
                    logger.warning("Failed fallback to /v1/compile/policy at %s: %s", self.compiler_service_url, v1_e)

            if resp_data is None:
                try:
                    resp_data = json.loads(he.read().decode("utf-8"))
                except Exception:
                    logger.warning("Failed to invoke apcompile service container at %s: %s", url, he)
                    return None
        except Exception as e:
            logger.warning("Failed to invoke apcompile service container at %s: %s", url, e)
            return None

        if not isinstance(resp_data, dict):
            return None

        # If bundle_base64 or bundle is present, cache it in local COMPILED_BUNDLES_CACHE for instant download
        bundle_b64 = resp_data.get("bundle_base64") or resp_data.get("bundle")
        bundle_id = resp_data.get("bundle_id") or str(uuid.uuid4())
        if bundle_b64:
            try:
                bundle_bytes = base64.b64decode(bundle_b64)
                bundle_name = resp_data.get("bundle_name") or f"{target_name or 'compiled'}.tgz"
                COMPILED_BUNDLES_CACHE[bundle_id] = {
                    "bundle_id": bundle_id,
                    "bundle_name": bundle_name,
                    "bundle_size": len(bundle_bytes),
                    "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
                    "target_type": target_type,
                    "target_name": target_name,
                    "bytes": bundle_bytes,
                    "created_at": time.time(),
                }
                resp_data["bundle_id"] = bundle_id
                resp_data["bundle_name"] = bundle_name
                resp_data["bundle_size"] = len(bundle_bytes)
                resp_data["bundle_sha256"] = hashlib.sha256(bundle_bytes).hexdigest()
            except Exception:
                pass

        # Normalize success flag
        if "completed_successfully" in resp_data:
            resp_data["success"] = bool(resp_data["completed_successfully"])
        elif "status" in resp_data:
            resp_data["success"] = resp_data["status"] == "success"
        elif "success" in resp_data:
            resp_data["success"] = bool(resp_data["success"])
        else:
            resp_data["success"] = False

        if not resp_data["success"]:
            err_text = (
                resp_data.get("error_message")
                or resp_data.get("output")
                or resp_data.get("message")
                or resp_data.get("stderr")
                or ""
            )
            if not resp_data.get("errors"):
                err_lines = [l.strip() for l in err_text.splitlines() if l.strip()]
                resp_data["errors"] = [self._format_cli_error(l) for l in err_lines] if err_lines else [self._format_cli_error(err_text)] if err_text else []
            if not resp_data.get("stderr"):
                resp_data["stderr"] = err_text

        # Format any raw string errors into structured error objects with path & remediation
        if resp_data.get("errors"):
            formatted_errors = []
            for err in resp_data["errors"]:
                if isinstance(err, str):
                    formatted_errors.append(self._format_cli_error(err))
                elif isinstance(err, dict):
                    if not err.get("solution"):
                        err["solution"] = self.get_remediation(err.get("message", ""))
                    if not err.get("path") or err.get("path") == "/":
                        msg = err.get("message", "")
                        if "custom-signatures" in msg or "signature-requirements" in msg or "tag does not exist" in msg:
                            err["path"] = "/policy/signature-requirements"
                    formatted_errors.append(err)
            resp_data["errors"] = formatted_errors

        # Strip bundle_base64 and bundle so huge base64 payloads are never sent in API responses
        resp_data.pop("bundle_base64", None)
        resp_data.pop("bundle", None)
        if "compiler_engine" not in resp_data:
            resp_data["compiler_engine"] = "apcompile-service"
        return resp_data

    def test_compilation(
        self,
        target_type: str,  # 'policy' or 'log_profile'
        content: Any,
        target_name: Optional[str] = None,
        include_source: bool = False,
        full_export: bool = False,
        global_settings: Optional[Dict[str, Any]] = None,
        user_signatures: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Test compilation of policy or logging profile and return detailed diagnostics."""
        start_time = time.time()

        # Parse string content if JSON string was supplied
        if isinstance(content, str):
            try:
                parsed_content = json.loads(content)
            except Exception as e:
                compile_ms = int((time.time() - start_time) * 1000)
                return {
                    "success": False,
                    "target_type": target_type,
                    "target_name": target_name or "unknown",
                    "compiler_engine": "syntax_checker",
                    "stdout": "",
                    "stderr": f"JSON Syntax Error: {str(e)}",
                    "errors": [
                        {
                            "code": "ERR_INVALID_JSON_SYNTAX",
                            "title": "Invalid JSON Syntax",
                            "path": "/",
                            "message": f"Document could not be parsed as JSON: {str(e)}",
                            "solution": REMEDIATION_MAP["Expected declarative policy"],
                        }
                    ],
                    "warnings": [],
                    "diagnostics": {
                        "compile_time_ms": compile_ms,
                        "schema_valid": False,
                    },
                }
        else:
            parsed_content = content

        # 1. Try compiler service container first if configured
        if self.compiler_service_url:
            service_result = self._compile_via_service(
                target_type=target_type,
                content=parsed_content,
                target_name=target_name,
                include_source=include_source,
                full_export=full_export,
                global_settings=global_settings,
                start_time=start_time,
                user_signatures=user_signatures,
            )
            if service_result is not None:
                return service_result

        # 2. Execute using official CLI if available locally
        if self.is_cli_available():
            try:
                return self._compile_via_cli(
                    target_type=target_type,
                    content=parsed_content,
                    target_name=target_name,
                    include_source=include_source,
                    full_export=full_export,
                    global_settings=global_settings,
                    start_time=start_time,
                    user_signatures=user_signatures,
                )
            except Exception as e:
                logger.warning("CLI compilation invocation failed (%s), falling back to built-in compiler engine", e)

        # 3. Fallback to built-in deep verification compiler engine
        return self._compile_built_in(
            target_type=target_type,
            content=parsed_content,
            target_name=target_name,
            include_source=include_source,
            full_export=full_export,
            global_settings=global_settings,
            start_time=start_time,
            user_signatures=user_signatures,
        )

    def _compile_via_cli(
        self,
        target_type: str,
        content: Dict[str, Any],
        target_name: Optional[str],
        include_source: bool,
        full_export: bool,
        global_settings: Optional[Dict[str, Any]],
        start_time: float,
        user_signatures: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Execute compilation using the official apcompile CLI."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_name = "policy.json" if target_type == "policy" else "logging_profile.json"
            bundle_name = f"{target_name or 'compiled'}.tgz"
            input_path = os.path.join(tmp_dir, input_name)
            output_path = os.path.join(tmp_dir, bundle_name)

            user_sig_paths: List[str] = []
            if target_type == "policy":
                clean_policy, sigs_by_tag = self._prepare_user_signatures_and_policy(content, user_signatures)
                content_to_dump = sanitize_waf_policy(clean_policy, for_compilation=True)
                if isinstance(content_to_dump, dict):
                    if "policy" not in content_to_dump or not isinstance(content_to_dump.get("policy"), dict):
                        content_to_dump = {"policy": content_to_dump}
                with open(input_path, "w", encoding="utf-8") as f:
                    json.dump(content_to_dump, f, indent=2)

                # Write separate user-defined signature files for each tag
                for tag, sigs in sigs_by_tag.items():
                    safe_tag = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in tag)
                    sig_file_name = f"user_signatures_{safe_tag}.json"
                    sig_file_path = os.path.join(tmp_dir, sig_file_name)
                    sig_doc = {
                        "softwareVersion": "15.1.0",
                        "tag": tag,
                        "signatures": sigs,
                    }
                    with open(sig_file_path, "w", encoding="utf-8") as f:
                        json.dump(sig_doc, f, indent=2)
                    user_sig_paths.append(sig_file_path)
            else:
                content_to_dump = content
                with open(input_path, "w", encoding="utf-8") as f:
                    json.dump(content_to_dump, f, indent=2)

            cmd = [self.compiler_bin]
            if target_type == "policy":
                cmd.extend(["-p", input_path])
                for sig_path in user_sig_paths:
                    cmd.extend(["-s", sig_path])
            else:
                cmd.extend(["-l", input_path])

            cmd.extend(["-o", output_path])

            if include_source:
                cmd.append("-include-source")
            if full_export:
                cmd.append("-full-export")

            if global_settings:
                global_path = os.path.join(tmp_dir, "global_settings.json")
                with open(global_path, "w", encoding="utf-8") as f:
                    json.dump(global_settings, f, indent=2)
                cmd.extend(["-g", global_path])

            kwargs: Dict[str, Any] = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "cwd": tmp_dir,
            }
            if sys.platform != "win32":
                kwargs["start_new_session"] = True

            proc = subprocess.Popen(cmd, **kwargs)
            try:
                stdout_data, stderr_data = proc.communicate(timeout=90)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
                stdout_data, stderr_data = proc.communicate()
                returncode = -1
                stderr_data = (stderr_data or "") + "\nCompilation timed out after 90 seconds."
            finally:
                _kill_process_group_and_descendants(proc.pid)

            compile_ms = int((time.time() - start_time) * 1000)
            success = returncode == 0 and os.path.exists(output_path)

            errors: List[Dict[str, Any]] = []
            warnings: List[str] = []

            # Parse stderr / stdout for diagnostics
            output_combined = (stderr_data or "") + "\n" + (stdout_data or "")
            for line in output_combined.splitlines():
                line_str = line.strip()
                if not line_str:
                    continue
                if "error" in line_str.lower():
                    errors.append(self._format_cli_error(line_str))
                elif "warn" in line_str.lower():
                    warnings.append(line_str)

            if not success and not errors:
                errors.append({
                    "code": "ERR_COMPILER_EXIT_NONZERO",
                    "title": f"Compiler Exited with Status {returncode}",
                    "path": "/",
                    "message": stderr_data or stdout_data or "Compiler execution terminated with non-zero exit code.",
                    "solution": "Review policy configuration for invalid options or missing references.",
                })

            bundle_info = None
            if success:
                bundle_bytes = open(output_path, "rb").read()
                bundle_info = self._store_bundle(
                    bundle_name=bundle_name,
                    bundle_bytes=bundle_bytes,
                    target_type=target_type,
                    target_name=target_name,
                )

            stdout_result = stdout_data
            if not stdout_result or not stdout_result.strip():
                cli_out = {
                    "completed_successfully": success,
                    "bundle_name": bundle_info["bundle_name"] if bundle_info else None,
                    "bundle_size": bundle_info["bundle_size"] if bundle_info else 0,
                    "bundle_sha256": bundle_info["bundle_sha256"] if bundle_info else None,
                    "compile_time_ms": compile_ms,
                    "warnings": warnings,
                }
                if errors:
                    cli_out["errors"] = [e.get("message", str(e)) for e in errors]
                stdout_result = json.dumps(cli_out, indent=2)

            return {
                "success": success,
                "target_type": target_type,
                "target_name": target_name or "unnamed",
                "compiler_engine": "apcompile",
                "bundle_name": bundle_info["bundle_name"] if bundle_info else None,
                "bundle_size": bundle_info["bundle_size"] if bundle_info else 0,
                "bundle_sha256": bundle_info["bundle_sha256"] if bundle_info else None,
                "bundle_id": bundle_info["bundle_id"] if bundle_info else None,
                "stdout": stdout_result,
                "stderr": stderr_data or "",
                "errors": errors,
                "warnings": warnings,
                "diagnostics": {
                    "compile_time_ms": compile_ms,
                    "schema_valid": success,
                    "compiler_version": "apcompile",
                },
            }

    def _compile_built_in(
        self,
        target_type: str,
        content: Dict[str, Any],
        target_name: Optional[str],
        include_source: bool,
        full_export: bool,
        global_settings: Optional[Dict[str, Any]],
        start_time: float,
        user_signatures: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Built-in compiler engine performing rigorous multi-phase F5 compilation checks."""
        errors: List[Dict[str, Any]] = []
        warnings: List[str] = []
        diagnostics: Dict[str, Any] = {}

        if not isinstance(content, dict):
            errors.append({
                "code": "ERR_INVALID_ROOT",
                "title": "Invalid Document Root",
                "path": "/",
                "message": "Top-level configuration must be a JSON object",
                "solution": REMEDIATION_MAP["Expected declarative policy"],
            })
            return self._build_failure_response(target_type, target_name, errors, warnings, start_time)

        clean_policy = None
        sigs_by_tag = None

        # -------------------------------------------------------------
        # Phase 1: Policy Compilation Checks
        # -------------------------------------------------------------
        if target_type == "policy":
            clean_policy, sigs_by_tag = self._prepare_user_signatures_and_policy(content, user_signatures)
            content_to_validate = clean_policy
            is_valid, val_errs, val_warns, validated = validate_policy_json(content_to_validate)
            warnings.extend(val_warns)

            if not is_valid:
                for err in val_errs:
                    errors.append(self._format_validation_error(err))

            policy_body = clean_policy.get("policy", {}) if isinstance(clean_policy.get("policy"), dict) else {}
            effective_name = target_name or policy_body.get("name", "unnamed_policy")

            # Check duplicate URLs
            urls = policy_body.get("urls", [])
            seen_urls = set()
            for idx, u in enumerate(urls):
                if isinstance(u, dict):
                    u_key = (u.get("name", "").strip(), u.get("protocol", "http").lower())
                    if u_key in seen_urls:
                        errors.append({
                            "code": "ERR_DUPLICATE_URL",
                            "title": "Duplicate URL Endpoint",
                            "path": f"/policy/urls/{idx}",
                            "message": f"URL '{u.get('name')}' with protocol '{u.get('protocol')}' is defined multiple times.",
                            "solution": "Remove duplicate URL entries or ensure distinct URL names and protocols.",
                        })
                    seen_urls.add(u_key)

            # Check duplicate Parameters (scope-aware)
            params = policy_body.get("parameters", [])
            seen_params = set()
            for idx, p in enumerate(params):
                if isinstance(p, dict):
                    level = p.get("level", "global").lower()
                    p_name = p.get("name", "").strip()
                    loc = p.get("parameterLocation", "any").lower()
                    if level == "url":
                        u_obj = p.get("url") if isinstance(p.get("url"), dict) else {}
                        u_name = u_obj.get("name", "").strip()
                        u_method = u_obj.get("method", "*").strip().upper()
                        u_proto = u_obj.get("protocol", "http").strip().lower()
                        p_key = ("url", p_name, loc, u_name, u_method, u_proto)
                    else:
                        p_key = ("global", p_name, loc)

                    if p_key in seen_params:
                        scope_str = f"on URL '{u_name}' ({u_method})" if level == "url" else "in global scope"
                        errors.append({
                            "code": "ERR_DUPLICATE_PARAMETER",
                            "title": "Duplicate Parameter",
                            "path": f"/policy/parameters/{idx}",
                            "message": f"Parameter '{p.get('name')}' in location '{loc}' is defined multiple times {scope_str}.",
                            "solution": "Ensure each parameter name within a location and URL scope is unique.",
                        })
                    seen_params.add(p_key)

            # Check duplicate Violations
            violations = policy_body.get("blocking-settings", {}).get("violations", []) if isinstance(policy_body.get("blocking-settings"), dict) else []
            seen_viols = set()
            for idx, v in enumerate(violations):
                if isinstance(v, dict):
                    v_name = v.get("name", "")
                    if v_name in seen_viols:
                        errors.append({
                            "code": "ERR_DUPLICATE_VIOLATION",
                            "title": "Duplicate Violation Setting",
                            "path": f"/policy/blocking-settings/violations/{idx}",
                            "message": f"Violation '{v_name}' is declared more than once in blocking-settings.",
                            "solution": "Consolidate multiple declarations of the same violation into a single entry.",
                        })
                    seen_viols.add(v_name)

            # Check for forbidden basicAuth in OpenAPI
            open_api_files = policy_body.get("open-api-files", [])
            for idx, item in enumerate(open_api_files):
                if isinstance(item, dict) and "basicAuth" in item:
                    errors.append({
                        "code": "ERR_OPENAPI_BASICAUTH_FORBIDDEN",
                        "title": "Unsupported 'basicAuth' in OpenAPI Reference",
                        "path": f"/policy/open-api-files/{idx}/basicAuth",
                        "message": "OpenAPI files must only contain 'link'. 'basicAuth' is forbidden in declarative policies.",
                        "solution": "Remove the 'basicAuth' property. Declarative policies compiled by F5 WAF only allow 'link'.",
                    })

            # Check global settings cookie seed if provided
            if global_settings and isinstance(global_settings, dict):
                cookie_seed = global_settings.get("waf-settings", {}).get("cookie-protection", {}).get("seed")
                if not cookie_seed:
                    warnings.append("Global settings supplied without cookie protection seed.")

            # Check signature-requirements against custom signatures
            sig_reqs = policy_body.get("signature-requirements", [])
            custom_sig_storage = None
            try:
                from ..storage import get_custom_signatures_storage

                custom_sig_storage = get_custom_signatures_storage()
            except Exception:
                pass

            for idx, req in enumerate(sig_reqs):
                if isinstance(req, dict):
                    req_tag = req.get("tag")
                    if req_tag:
                        has_in_sig_map = bool(sigs_by_tag and req_tag in sigs_by_tag and sigs_by_tag[req_tag])
                        has_in_storage = bool(
                            custom_sig_storage and custom_sig_storage.get_signature_file(req_tag)
                        )
                        if not has_in_sig_map and not has_in_storage:
                            warnings.append(
                                f"Signature requirement tag '{req_tag}' is not found in defined custom signatures. "
                                f"Ensure the user-defined signature file for tag '{req_tag}' is provided to the compiler or deployed alongside the policy."
                            )

            total_custom_sigs = sum(len(sigs) for sigs in (sigs_by_tag or {}).values())
            diagnostics = {
                "urls_count": len(urls),
                "parameters_count": len(params),
                "violations_count": len(violations),
                "server_technologies_count": len(policy_body.get("server-technologies", [])),
                "signature_sets_count": len(policy_body.get("signature-sets", [])),
                "signatures_count": len(policy_body.get("signatures", [])),
                "custom_signatures_count": total_custom_sigs,
                "signature_requirements_count": len(sig_reqs),
            }

        # -------------------------------------------------------------
        # Phase 2: Logging Profile Compilation Checks
        # -------------------------------------------------------------
        else:
            is_valid, val_errs, val_warns, validated = validate_logging_profile_json(content)
            warnings.extend(val_warns)

            if not is_valid:
                for err in val_errs:
                    errors.append(self._format_validation_error(err))

            filter_obj = content.get("filter", {}) if isinstance(content.get("filter"), dict) else {}
            content_obj = content.get("content", {}) if isinstance(content.get("content"), dict) else {}
            effective_name = target_name or "logging_profile"

            req_type = filter_obj.get("request_type")
            if req_type not in ("all", "illegal", "blocked"):
                errors.append({
                    "code": "ERR_INVALID_REQUEST_TYPE",
                    "title": "Invalid Filter Request Type",
                    "path": "/filter/request_type",
                    "message": f"request_type '{req_type}' is invalid. Must be 'all', 'illegal', or 'blocked'.",
                    "solution": "Update filter.request_type to one of: 'all', 'illegal', or 'blocked'.",
                })

            log_fmt = content_obj.get("format")
            if log_fmt not in ("default", "splunk", "arcsight", "user-defined"):
                errors.append({
                    "code": "ERR_INVALID_LOG_FORMAT",
                    "title": "Invalid Logging Format",
                    "path": "/content/format",
                    "message": f"Format '{log_fmt}' is invalid. Must be 'default', 'splunk', 'arcsight', or 'user-defined'.",
                    "solution": "Set content.format to one of 'default', 'splunk', 'arcsight', or 'user-defined'.",
                })

            diagnostics = {
                "request_type": req_type,
                "format": log_fmt,
                "max_message_size": content_obj.get("max_message_size"),
                "max_request_size": content_obj.get("max_request_size"),
            }

        compile_ms = int((time.time() - start_time) * 1000)

        # -------------------------------------------------------------
        # Phase 3: Result & Bundle Packaging
        # -------------------------------------------------------------
        if errors:
            compiler_output = {
                "completed_successfully": False,
                "errors": [e.get("message", str(e)) for e in errors],
                "warnings": warnings,
                "compile_time_ms": compile_ms,
                "compiler_version": "5.15.0",
            }
            return {
                "success": False,
                "target_type": target_type,
                "target_name": effective_name,
                "compiler_engine": "built-in-f5-compiler",
                "bundle_name": None,
                "bundle_size": 0,
                "bundle_sha256": None,
                "bundle_id": None,
                "stdout": json.dumps(compiler_output, indent=2),
                "stderr": f"Compilation failed: {len(errors)} error(s) detected.",
                "errors": errors,
                "warnings": warnings,
                "diagnostics": {
                    "compile_time_ms": compile_ms,
                    "schema_valid": False,
                    **diagnostics,
                },
            }

        # Successful compilation -> Create .tgz bundle package
        bundle_name = f"{effective_name}_compiled.tgz"
        bundle_bytes = self._package_tgz_bundle(
            target_type=target_type,
            name=effective_name,
            content=content,
            include_source=include_source,
            full_export=full_export,
            global_settings=global_settings,
            clean_policy=clean_policy,
            sigs_by_tag=sigs_by_tag,
        )

        bundle_info = self._store_bundle(
            bundle_name=bundle_name,
            bundle_bytes=bundle_bytes,
            target_type=target_type,
            target_name=effective_name,
        )

        compiler_output = {
            "completed_successfully": True,
            "bundle_name": bundle_name,
            "bundle_size": len(bundle_bytes),
            "bundle_sha256": bundle_info["bundle_sha256"],
            "compile_time_ms": compile_ms,
            "compiler_version": "5.15.0",
            "warnings": warnings,
        }
        stdout_msg = json.dumps(compiler_output, indent=2)

        return {
            "success": True,
            "target_type": target_type,
            "target_name": effective_name,
            "compiler_engine": "built-in-f5-compiler",
            "bundle_name": bundle_name,
            "bundle_size": len(bundle_bytes),
            "bundle_sha256": bundle_info["bundle_sha256"],
            "bundle_id": bundle_info["bundle_id"],
            "stdout": stdout_msg,
            "stderr": "",
            "errors": [],
            "warnings": warnings,
            "diagnostics": {
                "compile_time_ms": compile_ms,
                "schema_valid": True,
                "compiler_version": "5.15.0",
                "bundle_format": "tgz",
                **diagnostics,
            },
        }

    def _package_tgz_bundle(
        self,
        target_type: str,
        name: str,
        content: Dict[str, Any],
        include_source: bool,
        full_export: bool,
        global_settings: Optional[Dict[str, Any]],
        clean_policy: Optional[Dict[str, Any]] = None,
        sigs_by_tag: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> bytes:
        """Create a standard F5 WAF .tgz bundle containing manifest and policy/profile JSON."""
        tar_buf = io.BytesIO()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        manifest = {
            "format_version": "2.0",
            "bundle_type": "policy" if target_type == "policy" else "logging_profile",
            "name": name,
            "compiler": "F5 WAF for NGINX Compiler (WafCompilerService)",
            "compiler_version": "5.15.0",
            "compiled_at": now_iso,
            "include_source": include_source,
            "full_export": full_export,
            "has_global_settings": bool(global_settings),
        }

        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            # Add manifest.json
            manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            m_info = tarfile.TarInfo(name="manifest.json")
            m_info.size = len(manifest_bytes)
            m_info.mtime = int(time.time())
            tar.addfile(m_info, io.BytesIO(manifest_bytes))

            # Add payload (policy.json or logging_profile.json)
            payload_filename = "policy.json" if target_type == "policy" else "logging_profile.json"
            if target_type == "policy":
                content_to_pack = clean_policy if clean_policy is not None else sanitize_waf_policy(copy.deepcopy(content), for_compilation=True)
            else:
                content_to_pack = content
            content_bytes = json.dumps(content_to_pack, indent=2).encode("utf-8")
            p_info = tarfile.TarInfo(name=payload_filename)
            p_info.size = len(content_bytes)
            p_info.mtime = int(time.time())
            tar.addfile(p_info, io.BytesIO(content_bytes))

            # Add global_settings.json if present
            if global_settings:
                gs_bytes = json.dumps(global_settings, indent=2).encode("utf-8")
                gs_info = tarfile.TarInfo(name="global_settings.json")
                gs_info.size = len(gs_bytes)
                gs_info.mtime = int(time.time())
                tar.addfile(gs_info, io.BytesIO(gs_bytes))

            # Add user-defined signature files for each tag
            if target_type == "policy":
                resolved_sigs_by_tag = copy.deepcopy(sigs_by_tag) if sigs_by_tag else {}
                if not resolved_sigs_by_tag:
                    policy_body = content.get("policy", {}) if isinstance(content.get("policy"), dict) else {}
                    custom_sigs = (
                        policy_body.get("custom-signatures")
                        or policy_body.get("user-defined-signatures")
                        or []
                    )
                    if custom_sigs:
                        for cs in custom_sigs:
                            if isinstance(cs, dict):
                                t = cs.get("tag") or "custom"
                                resolved_sigs_by_tag.setdefault(t, []).append(cs)

                first_tag = None
                for tag, sigs in resolved_sigs_by_tag.items():
                    if first_tag is None:
                        first_tag = tag
                    safe_tag = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in tag)
                    cs_doc = {
                        "softwareVersion": "15.1.0",
                        "tag": tag,
                        "signatures": sigs,
                    }
                    cs_bytes = json.dumps(cs_doc, indent=2).encode("utf-8")
                    cs_info = tarfile.TarInfo(name=f"user_defined_signatures_{safe_tag}.json")
                    cs_info.size = len(cs_bytes)
                    cs_info.mtime = int(time.time())
                    tar.addfile(cs_info, io.BytesIO(cs_bytes))

                if first_tag:
                    cs_doc_first = {
                        "softwareVersion": "15.1.0",
                        "tag": first_tag,
                        "signatures": resolved_sigs_by_tag[first_tag],
                    }
                    cs_bytes_first = json.dumps(cs_doc_first, indent=2).encode("utf-8")
                    cs_info_first = tarfile.TarInfo(name="user_defined_signatures.json")
                    cs_info_first.size = len(cs_bytes_first)
                    cs_info_first.mtime = int(time.time())
                    tar.addfile(cs_info_first, io.BytesIO(cs_bytes_first))

        return tar_buf.getvalue()

    def _store_bundle(
        self,
        bundle_name: str,
        bundle_bytes: bytes,
        target_type: str,
        target_name: Optional[str],
    ) -> Dict[str, Any]:
        """Cache bundle in-memory for download."""
        bundle_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(bundle_bytes).hexdigest()

        # Evict expired bundles
        now = time.time()
        expired = [k for k, v in COMPILED_BUNDLES_CACHE.items() if now - v.get("created_at", 0) > BUNDLE_TTL_SECONDS]
        for k in expired:
            COMPILED_BUNDLES_CACHE.pop(k, None)

        # Evict oldest if cache limit reached
        while len(COMPILED_BUNDLES_CACHE) >= MAX_CACHED_BUNDLES:
            oldest_key = next(iter(COMPILED_BUNDLES_CACHE))
            del COMPILED_BUNDLES_CACHE[oldest_key]

        info = {
            "bundle_id": bundle_id,
            "bundle_name": bundle_name,
            "bundle_size": len(bundle_bytes),
            "bundle_sha256": sha256,
            "target_type": target_type,
            "target_name": target_name,
            "bytes": bundle_bytes,
            "created_at": now,
        }
        COMPILED_BUNDLES_CACHE[bundle_id] = info
        return info

    def get_bundle(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored bundle by ID for download."""
        if bundle_id in COMPILED_BUNDLES_CACHE:
            return COMPILED_BUNDLES_CACHE[bundle_id]

        # If not in local cache, check if apcompile service has it
        if self.compiler_service_url:
            try:
                import urllib.request
                url = f"{self.compiler_service_url.rstrip('/')}/download/{bundle_id}"
                req = urllib.request.Request(url, headers={"User-Agent": "f5-waf-editor"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    bundle_bytes = resp.read()
                    bundle_name = f"bundle_{bundle_id[:8]}.tgz"
                    disp = resp.headers.get("Content-Disposition", "")
                    if "filename=" in disp:
                        bundle_name = disp.split("filename=")[-1].strip('"')
                    sha256 = resp.headers.get("X-Bundle-SHA256") or hashlib.sha256(bundle_bytes).hexdigest()
                    info = {
                        "bundle_id": bundle_id,
                        "bundle_name": bundle_name,
                        "bundle_size": len(bundle_bytes),
                        "bundle_sha256": sha256,
                        "target_type": "policy",
                        "target_name": bundle_name,
                        "bytes": bundle_bytes,
                        "created_at": time.time(),
                    }
                    COMPILED_BUNDLES_CACHE[bundle_id] = info
                    return info
            except Exception as e:
                logger.debug("Failed to fetch bundle from compiler service: %s", e)

        return None

    def get_status(self) -> Dict[str, Any]:
        """Return status of compiler service, CLI, or built-in engine."""
        if self.compiler_service_url:
            try:
                import urllib.request
                url = f"{self.compiler_service_url.rstrip('/')}/status"
                req = urllib.request.Request(url, headers={"User-Agent": "f5-waf-editor"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    data["service_connected"] = True
                    data["service_url"] = self.compiler_service_url
                    return data
            except Exception as e:
                logger.debug("Compiler service unreachable at %s: %s", self.compiler_service_url, e)

        cli_avail = self.is_cli_available()
        return {
            "status": "ready",
            "cli_available": cli_avail,
            "compiler_bin": self.compiler_bin if cli_avail else None,
            "engine": "apcompile-cli" if cli_avail else "built-in-f5-compiler",
            "version": "5.15.0",
            "service_connected": False,
            "service_url": self.compiler_service_url or None,
            "supported_targets": ["policy", "log_profile"],
        }

    @classmethod
    def get_remediation(cls, error_msg: str) -> str:
        """Return recommended remediation message based on compiler error output."""
        for key, sol in REMEDIATION_MAP.items():
            if key.lower() in error_msg.lower():
                return sol
        return "Review policy configuration for invalid options or missing references."

    def _format_cli_error(self, line: str) -> Dict[str, Any]:
        """Convert raw CLI error line into structured error object."""
        path = "/"
        code = "ERR_COMPILER_DIAGNOSTIC"
        if "signature-sets" in line or "PLC.NEGSIG" in line:
            path = "/policy/signature-sets"
        elif "server-technologies" in line or "PL_SERVER_TECHNOLOGIES" in line or "server_technology_id" in line:
            path = "/policy/server-technologies"
        elif "cannot be configured" in line or "/blocking-settings/violations" in line:
            path = "/blocking-settings/violations"
        elif "custom-signatures" in line or "signature-requirements" in line or "tag does not exist" in line:
            path = "/policy/signature-requirements"
            code = "ERR_COMPILER_CUSTOM_SIGNATURES"

        solution = self.get_remediation(line)

        return {
            "code": code,
            "title": "Compiler Error",
            "path": path,
            "message": line,
            "solution": solution,
        }

    def _format_validation_error(self, err_msg: str) -> Dict[str, Any]:
        """Derive structured error from validator error message."""
        title = "Schema Validation Error"
        code = "ERR_SCHEMA_VALIDATION"
        path = "/"
        solution = "Correct the property according to F5 WAF for NGINX declarative schema."

        if "signature set" in err_msg.lower() or "threat campaigns" in err_msg.lower():
            title = "Invalid Signature Set Configuration"
            code = "ERR_INVALID_SIGNATURE_SET"
            path = "/policy/signature-sets"
            solution = "Ensure signature sets use official F5 WAF for NGINX names (e.g. 'Path Traversal Signatures') and custom sets have valid 'signatureSet' definitions."
        elif "violation" in err_msg.lower():
            title = "Unsupported or Invalid Violation"
            code = "ERR_UNSUPPORTED_VIOLATION"
            path = "/policy/blocking-settings/violations"
            solution = "Remove unsupported ASM violation or use standard F5 WAF for NGINX violations."
        elif "basicauth" in err_msg.lower():
            title = "Forbidden basicAuth Property"
            code = "ERR_OPENAPI_BASICAUTH_FORBIDDEN"
            path = "/policy/open-api-files"
            solution = "Remove 'basicAuth' from policy JSON; declarative policies only support 'link'."
        elif "name" in err_msg.lower():
            title = "Invalid Policy Name"
            code = "ERR_INVALID_NAME"
            path = "/policy/name"
            solution = "Policy names must match ^[a-zA-Z0-9_\\-.:]+$ and not start with 'log:'."
        elif "enforcementmode" in err_msg.lower():
            title = "Invalid Enforcement Mode"
            code = "ERR_INVALID_MODE"
            path = "/policy/enforcementMode"
            solution = "Set enforcementMode to 'blocking' or 'transparent'."
        elif "url" in err_msg.lower():
            title = "Invalid URL Syntax"
            code = "ERR_INVALID_URL"
            path = "/policy/urls"
            solution = "Ensure URL paths start with '/' or are wildcard patterns '*'."

        return {
            "code": code,
            "title": title,
            "path": path,
            "message": err_msg,
            "solution": solution,
        }

    def _build_failure_response(
        self,
        target_type: str,
        target_name: Optional[str],
        errors: List[Dict[str, Any]],
        warnings: List[str],
        start_time: float,
    ) -> Dict[str, Any]:
        """Helper to build standardized failure response."""
        compile_ms = int((time.time() - start_time) * 1000)
        compiler_output = {
            "completed_successfully": False,
            "errors": [e.get("message", str(e)) for e in errors],
            "warnings": warnings,
            "compile_time_ms": compile_ms,
            "compiler_version": "5.15.0",
        }
        return {
            "success": False,
            "target_type": target_type,
            "target_name": target_name or "unknown",
            "compiler_engine": "built-in-f5-compiler",
            "bundle_name": None,
            "bundle_size": 0,
            "bundle_sha256": None,
            "bundle_id": None,
            "stdout": json.dumps(compiler_output, indent=2),
            "stderr": f"Compilation failed: {len(errors)} error(s) detected.",
            "errors": errors,
            "warnings": warnings,
            "diagnostics": {
                "compile_time_ms": compile_ms,
                "schema_valid": False,
            },
        }


def compile_target(
    target_type: str,
    content: Any,
    target_name: Optional[str] = None,
    include_source: bool = False,
    full_export: bool = False,
    global_settings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience functional wrapper for compiler testing."""
    service = WafCompilerService()
    return service.test_compilation(
        target_type=target_type,
        content=content,
        target_name=target_name,
        include_source=include_source,
        full_export=full_export,
        global_settings=global_settings,
    )
