"""
F5 WAF apcompile Service Container Server.
Runs as a dedicated microservice / pod inside the compiler container.
Exposes REST endpoints to compile policies and logging profiles into .tgz bundles.
Fully compatible with the F5 WAF Policy Manager frontend UI.
"""

from __future__ import annotations
import argparse
import base64
import datetime
import io
import json
import logging
import os
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, Optional
import uvicorn
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .compiler_service import (
    WafCompilerService,
    COMPILED_BUNDLES_CACHE,
    compile_target,
    _kill_process_group_and_descendants,
)

logger = logging.getLogger("apcompile_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = FastAPI(
    title="F5 WAF apcompile Service",
    description="Dedicated compiler service container executing apcompile for F5 WAF for NGINX",
    version="5.15.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

compiler_service = WafCompilerService()


def _decode_or_parse_payload(val: Any) -> Any:
    """Helper to handle either raw JSON objects, raw JSON strings, or base64 encoded strings."""
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        # Try base64 decoding first
        try:
            decoded_bytes = base64.b64decode(val)
            decoded_str = decoded_bytes.decode("utf-8")
            return json.loads(decoded_str)
        except Exception:
            # Try raw JSON string
            try:
                return json.loads(val)
            except Exception:
                return val
    return val


class CompilePayload(BaseModel):
    target_type: str = Field("policy", description="'policy' or 'log_profile'")
    content: Any = Field(..., description="JSON object or string of the policy or logging profile")
    target_name: Optional[str] = Field(None, description="Optional target name")
    include_source: bool = Field(False, description="Embed source in compiled bundle")
    full_export: bool = Field(True, description="Export all configuration properties")
    global_settings: Optional[Dict[str, Any]] = Field(None, description="Global settings (cookie seeds, etc.)")
    user_signatures: Optional[Any] = Field(None, alias="user-signatures", description="Optional user signatures JSON or base64")


class V1PolicyCompilePayload(BaseModel):
    policy: Any = Field(..., description="JSON object or base64-encoded string of the security policy")
    user_signatures: Optional[Any] = Field(None, alias="user-signatures", description="Optional user signatures JSON or base64")
    globalsettings: Optional[Any] = Field(None, alias="globalsettings", description="Optional global settings JSON or base64")
    target_name: Optional[str] = Field(None, description="Optional bundle file name")


class V1LogProfileCompilePayload(BaseModel):
    logprofile: Any = Field(..., alias="logprofile", description="JSON object or base64-encoded string of the logging profile")
    target_name: Optional[str] = Field(None, description="Optional bundle file name")


class V1BundleInfoPayload(BaseModel):
    bundle: str = Field(..., description="Base64-encoded compiled .tgz bundle")


@app.get("/health")
def healthcheck():
    """Liveness and readiness probe for Docker / Kubernetes."""
    return {"status": "ok", "service": "apcompile", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}


@app.get("/status")
def status_endpoint():
    """Report compiler binary status, version, and execution environment."""
    cli_avail = compiler_service.is_cli_available()
    return {
        "status": "ready",
        "service": "apcompile",
        "container": os.getenv("HOSTNAME", "f5-waf-apcompile"),
        "compiler_bin": compiler_service.compiler_bin or "/opt/app_protect/bin/apcompile",
        "cli_available": cli_avail,
        "engine": "apcompile-cli" if cli_avail else "built-in-f5-compiler",
        "version": "5.15.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


@app.post("/compile")
def compile_endpoint(req: CompilePayload):
    """Compile a security policy or logging profile inside the apcompile container."""
    try:
        parsed_content = _decode_or_parse_payload(req.content)
        parsed_global = _decode_or_parse_payload(req.global_settings)
        parsed_user_sigs = _decode_or_parse_payload(req.user_signatures)

        result = compiler_service.test_compilation(
            target_type=req.target_type,
            content=parsed_content,
            target_name=req.target_name,
            include_source=req.include_source,
            full_export=req.full_export,
            global_settings=parsed_global,
            user_signatures=parsed_user_sigs,
        )

        # Include base64 bundle if compiled successfully
        bundle_id = result.get("bundle_id")
        if bundle_id and bundle_id in COMPILED_BUNDLES_CACHE:
            bundle_data = COMPILED_BUNDLES_CACHE[bundle_id]["bytes"]
            result["bundle_base64"] = base64.b64encode(bundle_data).decode("ascii")

        return result
    except Exception as e:
        logger.exception("Compilation error inside apcompile container")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compiler container error: {str(e)}",
        )


@app.post("/v1/compile/policy")
def v1_compile_policy(payload: V1PolicyCompilePayload):
    """
    NAP-Compiler-REST-API compatible policy compilation endpoint.
    Accepts direct JSON or base64-encoded policy, user-signatures, and globalsettings.
    """
    try:
        policy_data = _decode_or_parse_payload(payload.policy)
        user_sigs = _decode_or_parse_payload(payload.user_signatures)
        global_settings = _decode_or_parse_payload(payload.globalsettings)

        target_name = payload.target_name
        if not target_name and isinstance(policy_data, dict):
            target_name = policy_data.get("policy", {}).get("name", "compiled_policy")

        result = compiler_service.test_compilation(
            target_type="policy",
            content=policy_data,
            target_name=target_name,
            include_source=True,
            full_export=True,
            global_settings=global_settings,
            user_signatures=user_sigs,
        )

        bundle_b64 = ""
        bundle_id = result.get("bundle_id")
        if bundle_id and bundle_id in COMPILED_BUNDLES_CACHE:
            bundle_bytes = COMPILED_BUNDLES_CACHE[bundle_id]["bytes"]
            bundle_b64 = base64.b64encode(bundle_bytes).decode("ascii")

        return {
            "status": "success" if result["success"] else "error",
            "bundle": bundle_b64,
            "message": "Policy compiled successfully" if result["success"] else "Policy compilation failed",
            "output": result.get("stdout") or result.get("stderr") or "",
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "bundle_id": bundle_id,
            "diagnostics": result.get("diagnostics", {}),
        }
    except Exception as e:
        logger.exception("v1/compile/policy error")
        return {
            "status": "error",
            "bundle": "",
            "message": f"Compilation failed: {str(e)}",
            "output": str(e),
            "errors": [{"code": "ERR_COMPILATION_EXCEPTION", "message": str(e)}],
        }


@app.post("/v1/compile/logprofile")
def v1_compile_logprofile(payload: V1LogProfileCompilePayload):
    """
    NAP-Compiler-REST-API compatible log profile compilation endpoint.
    Accepts direct JSON or base64-encoded logging profile.
    """
    try:
        log_data = _decode_or_parse_payload(payload.logprofile)
        target_name = payload.target_name or "compiled_logprofile"

        result = compiler_service.test_compilation(
            target_type="log_profile",
            content=log_data,
            target_name=target_name,
            include_source=True,
            full_export=True,
        )

        bundle_b64 = ""
        bundle_id = result.get("bundle_id")
        if bundle_id and bundle_id in COMPILED_BUNDLES_CACHE:
            bundle_bytes = COMPILED_BUNDLES_CACHE[bundle_id]["bytes"]
            bundle_b64 = base64.b64encode(bundle_bytes).decode("ascii")

        return {
            "status": "success" if result["success"] else "error",
            "bundle": bundle_b64,
            "message": "Log profile compiled successfully" if result["success"] else "Log profile compilation failed",
            "output": result.get("stdout") or result.get("stderr") or "",
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "bundle_id": bundle_id,
            "diagnostics": result.get("diagnostics", {}),
        }
    except Exception as e:
        logger.exception("v1/compile/logprofile error")
        return {
            "status": "error",
            "bundle": "",
            "message": f"Compilation failed: {str(e)}",
            "output": str(e),
            "errors": [{"code": "ERR_COMPILATION_EXCEPTION", "message": str(e)}],
        }


@app.post("/v1/bundle/info")
def v1_bundle_info(payload: V1BundleInfoPayload):
    """
    NAP-Compiler-REST-API compatible bundle inspection endpoint.
    Accepts base64-encoded .tgz bundle and extracts bundle contents / dump info.
    """
    try:
        raw_bytes = base64.b64decode(payload.bundle)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 bundle encoding: {str(e)}",
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "bundle.tgz")
        with open(bundle_path, "wb") as f:
            f.write(raw_bytes)

        # If official apcompile CLI is available, run apcompile -dump -bundle
        dump_output = ""
        if compiler_service.is_cli_available():
            dump_proc = None
            try:
                kwargs: Dict[str, Any] = {
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE,
                    "text": True,
                    "cwd": tmp_dir,
                }
                if sys.platform != "win32":
                    kwargs["start_new_session"] = True
                dump_proc = subprocess.Popen(
                    [compiler_service.compiler_bin, "-dump", "-bundle", bundle_path],
                    **kwargs,
                )
                stdout_d, stderr_d = dump_proc.communicate(timeout=30)
                dump_output = stdout_d or stderr_d
            except Exception as e:
                dump_output = f"CLI dump error: {str(e)}"
            finally:
                if dump_proc:
                    _kill_process_group_and_descendants(dump_proc.pid)

        # Also inspect tar archive members and manifest
        members = []
        manifest = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tar:
                members = tar.getnames()
                if "manifest.json" in members:
                    mf = tar.extractfile("manifest.json")
                    if mf:
                        manifest = json.loads(mf.read().decode("utf-8"))
        except Exception as e:
            logger.warning("Could not parse tar members: %s", e)

        return {
            "status": "success",
            "bundle_info": dump_output,
            "manifest": manifest,
            "files": members,
            "size_bytes": len(raw_bytes),
        }


@app.get("/download/{bundle_id}")
def download_bundle_endpoint(bundle_id: str):
    """Serve compiled .tgz bundle from container cache."""
    bundle = COMPILED_BUNDLES_CACHE.get(bundle_id)
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Compiled bundle '{bundle_id}' not found in container cache.",
        )

    headers = {
        "Content-Disposition": f'attachment; filename="{bundle["bundle_name"]}"',
        "Content-Type": "application/gzip",
        "X-Bundle-SHA256": bundle.get("bundle_sha256", ""),
        "X-Compiler-Service": "apcompile",
    }
    return Response(content=bundle["bytes"], media_type="application/gzip", headers=headers)


def main():
    parser = argparse.ArgumentParser(description="F5 WAF apcompile Service Container")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("COMPILER_PORT", "9000")), help="Bind port (default: 9000)")
    args = parser.parse_args()

    logger.info("Starting apcompile service container on %s:%d", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
