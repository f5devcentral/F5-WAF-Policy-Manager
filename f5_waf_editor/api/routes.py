"""
FastAPI REST API routes for F5 WAF Policy Manager.
Provides CRUD operations, validation, template instantiations, import/export,
and Redis connection management.
"""

import json
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Response, status
from pydantic import BaseModel, Field

import logging

from ..storage import (
    get_storage,
    get_logging_storage,
    get_custom_signatures_storage,
    init_storage,
    init_github_storage,
    get_storage_health,
    get_storage_backend_type,
    push_policy_to_github,
    pull_from_github,
    get_pull_conflicts,
    get_github_status,
    is_github_configured,
    summarize_policy_changes,
    summarize_log_profile_changes,
    summarize_custom_signatures_changes,
)
from ..converters.bigip_converter import (
    convert_bigip_policy,
    convert_bigip_policy_json,
    convert_bigip_policy_xml,
    BigIpPolicyConverter,
)
from ..compiler.compiler_service import WafCompilerService, compile_target

logger = logging.getLogger(__name__)
from ..schemas.validator import validate_policy_json, POLICY_NAME_REGEX
from ..schemas.waf_schema import (
    VIOLATIONS_CATALOG,
    VIOLATION_CATEGORIES,
    SERVER_TECHNOLOGIES,
    STANDARD_SIGNATURE_SETS,
    BASE_TEMPLATES,
    ENFORCEMENT_MODES,
    SUPPORTED_METHODS,
    SUPPORTED_ENCODINGS,
    OPENAPI_RECOMMENDED_VIOLATIONS,
    GRPC_RECOMMENDED_VIOLATIONS,
    ATTACK_SIGNATURES_CATALOG,
    get_signatures_for_set,
    extract_policy_metadata,
    sanitize_waf_policy,
)
from ..templates_catalog import list_templates, get_template_json

router = APIRouter(prefix="/api", tags=["policies"])


# --- Request/Response Models ---

class CreatePolicyRequest(BaseModel):
    name: str = Field(..., description="Unique policy name")
    template_id: Optional[str] = Field(None, description="Optional built-in template ID to seed from")
    description: Optional[str] = Field(None, description="Optional policy description")
    content: Optional[Dict[str, Any]] = Field(None, description="Direct policy JSON content")


class UpdatePolicyRequest(BaseModel):
    content: Dict[str, Any] = Field(..., description="Updated policy JSON content")
    original_name: Optional[str] = Field(None, description="Original policy name if policy was renamed")


class RenamePolicyRequest(BaseModel):
    new_name: str = Field(..., description="Target name for renamed policy")


class ClonePolicyRequest(BaseModel):
    new_name: str = Field(..., description="Target name for duplicated policy")


class ValidatePolicyRequest(BaseModel):
    content: Any = Field(..., description="Policy JSON string or object to validate")


class TestCompilerRequest(BaseModel):
    target_type: str = Field("policy", description="Target type: 'policy' or 'log_profile'")
    target_name: Optional[str] = Field(None, description="Name of policy or log profile in storage, or custom name")
    content: Optional[Dict[str, Any]] = Field(None, description="Optional raw JSON content; if omitted, retrieved from storage using target_name")
    include_source: bool = Field(False, description="Include raw JSON source in compiled .tgz bundle")
    full_export: bool = Field(False, description="Export all base settings in compiled bundle")
    global_settings: Optional[Dict[str, Any]] = Field(None, description="Optional global settings JSON (e.g. cookie seed)")



class TestOpenApiLinkRequest(BaseModel):
    link: str = Field(..., description="OpenAPI specification URL or file path")
    allowSelfSigned: bool = Field(False, description="Allow invalid / self-signed TLS/SSL server certificates")
    authType: str = Field("none", description="Authentication type: 'none', 'basic', 'bearer', or 'mtls'")
    basicAuth: Optional[Dict[str, str]] = Field(None, description="Optional Basic Auth credentials")
    bearerToken: Optional[str] = Field(None, description="Optional Bearer token")
    clientCert: Optional[str] = Field(None, description="Optional client certificate in PEM format for mTLS")
    clientKey: Optional[str] = Field(None, description="Optional client private key in PEM format for mTLS")


class TestGrpcIdlRequest(BaseModel):
    link: str = Field(..., description="gRPC IDL specification URL or file path (.proto, .tar, .tgz)")
    primaryIdlFileName: Optional[str] = Field(None, description="Entry-point .proto file name inside archive")


class RedisConfigRequest(BaseModel):
    host: str = Field("localhost", description="Redis hostname or IP")
    port: int = Field(6379, description="Redis port")
    db: int = Field(0, description="Redis database index")
    password: Optional[str] = Field(None, description="Redis password (optional)")
    ssl: bool = Field(False, description="Use SSL for Redis connection")
    key_prefix: str = Field("", description="Key prefix (optional)")
    force_memory: bool = Field(False, description="Force In-Memory fallback")


class GitHubConfigRequest(BaseModel):
    owner: str = Field(..., description="GitHub Organization or Username")
    repo: str = Field(..., description="GitHub Repository name")
    token: str = Field(..., description="GitHub Personal Access Token (PAT)")
    branch: Optional[str] = Field("main", description="Target Git branch")
    api_url: Optional[str] = Field("https://api.github.com", description="GitHub API base URL")
    verify_ssl: Optional[bool] = Field(None, description="Verify server SSL/TLS certificates. Set to False for self-signed certificates.")
    disable_ssl_verify: Optional[bool] = Field(None, description="Disable server SSL/TLS certificate verification (self-signed certs).")
    policies_path: Optional[str] = Field("policies", description="Repository folder path for policies")
    log_profiles_path: Optional[str] = Field("log-profiles", description="Repository folder path for log profiles")
    custom_sigs_path: Optional[str] = Field("custom-signatures", description="Repository folder path for custom signatures")


class StorageConfigRequest(BaseModel):
    backend: str = Field("redis", description="Storage backend: 'redis', 'github', or 'memory'")
    github: Optional[GitHubConfigRequest] = None
    redis: Optional[RedisConfigRequest] = None


class GitHubPushRequest(BaseModel):
    message: Optional[str] = Field(None, description="Optional custom Git commit message")


class GitHubPullRequest(BaseModel):
    resolutions: Optional[Dict[str, Any]] = Field(None, description="Conflict resolutions mapping items to 'keep_local' or 'keep_github'")


class GitHubCommitPreviewRequest(BaseModel):
    type: str = Field(..., description="Item type: 'policy', 'logging', or 'custom_signatures'")
    name: str = Field(..., description="Name or identifier of the item")
    content: Optional[Union[Dict[str, Any], str]] = Field(None, description="Optional working draft content from editor")


# --- Policy Management Endpoints ---

@router.get("/policies", response_model=List[Dict[str, Any]])
def list_policies():
    """List all WAF policies in Redis backend with metadata."""
    storage = get_storage()
    return storage.list_policies()


@router.get("/policies/{name}")
def get_policy(name: str):
    """Retrieve full JSON specification for a specific policy."""
    storage = get_storage()
    raw = storage.get_raw_policy(name)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{name}' not found in storage",
        )
    return Response(content=raw, media_type="application/json")


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def create_policy(req: CreatePolicyRequest):
    """Create a new WAF security policy in Redis."""
    if req.name.startswith("log:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy name cannot start with reserved prefix 'log:' (reserved for logging profiles)",
        )

    storage = get_storage()
    if storage.policy_exists(req.name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy with name '{req.name}' already exists",
        )

    # Determine initial policy content
    policy_data: Dict[str, Any]
    if req.template_id:
        template_content = get_template_json(req.template_id)
        if not template_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid template ID '{req.template_id}'",
            )
        policy_data = template_content
    elif req.content:
        policy_data = req.content
    else:
        # Default blank baseline
        policy_data = {
            "policy": {
                "name": req.name,
                "description": "Custom F5 WAF Security Policy",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "applicationLanguage": "utf-8",
                "enforcementMode": "blocking",
            }
        }

    # Ensure name matches
    if "policy" in policy_data and isinstance(policy_data["policy"], dict):
        policy_data["policy"]["name"] = req.name
        if req.description is not None:
            policy_data["policy"]["description"] = req.description

    try:
        meta = storage.save_policy(req.name, policy_data)
        return {"message": "Policy created successfully", "metadata": meta}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.put("/policies/{name}")
def update_policy(name: str, req: UpdatePolicyRequest):
    """Update an existing WAF security policy JSON, supporting rename and description edits."""
    storage = get_storage()

    # Determine source policy name (existing policy in storage)
    source_name = name.strip()
    if not storage.policy_exists(source_name) and req.original_name:
        orig = req.original_name.strip()
        if storage.policy_exists(orig):
            source_name = orig

    if not storage.policy_exists(source_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{name}' not found",
        )

    # Determine target policy name
    body_name = None
    if isinstance(req.content, dict) and "policy" in req.content and isinstance(req.content["policy"], dict):
        raw_name = req.content["policy"].get("name")
        if isinstance(raw_name, str) and raw_name.strip():
            body_name = raw_name.strip()

    target_name = body_name or (name.strip() if name.strip() != source_name else source_name)

    # If target_name is different from source_name, it's a rename operation
    if target_name != source_name:
        if target_name.startswith("log:"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Policy name cannot start with reserved prefix 'log:'",
            )
        if not POLICY_NAME_REGEX.match(target_name):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid 'policy.name': '{target_name}'. Allowed characters are alphanumeric, dot, dash, colon, and underscore.",
            )
        if storage.policy_exists(target_name):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot rename policy: a policy with name '{target_name}' already exists",
            )
        try:
            meta = storage.rename_policy(source_name, target_name, req.content)
            return {
                "message": f"Policy '{source_name}' successfully renamed to '{target_name}' and updated",
                "metadata": meta,
                "renamed": True,
                "old_name": source_name,
                "new_name": target_name,
            }
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
        except FileExistsError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # Standard update
    try:
        meta = storage.save_policy(source_name, req.content)
        return {
            "message": "Policy updated successfully",
            "metadata": meta,
            "renamed": False,
            "name": source_name,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post("/policies/{name}/rename")
def rename_policy_endpoint(name: str, req: RenamePolicyRequest):
    """Rename an existing policy to a new name."""
    storage = get_storage()
    source_name = name.strip()
    target_name = req.new_name.strip()

    if not storage.policy_exists(source_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{source_name}' not found",
        )
    if target_name.startswith("log:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy name cannot start with reserved prefix 'log:'",
        )
    if not POLICY_NAME_REGEX.match(target_name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid 'policy.name': '{target_name}'. Allowed characters are alphanumeric, dot, dash, colon, and underscore.",
        )
    if source_name == target_name:
        pol = storage.get_policy(source_name)
        meta = storage.save_policy(source_name, pol)
        return {"message": "Policy name unchanged", "metadata": meta, "name": source_name}

    if storage.policy_exists(target_name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot rename policy: a policy with name '{target_name}' already exists",
        )

    try:
        meta = storage.rename_policy(source_name, target_name)
        return {
            "message": f"Policy '{source_name}' successfully renamed to '{target_name}'",
            "metadata": meta,
            "renamed": True,
            "old_name": source_name,
            "new_name": target_name,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except FileExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/policies/{name}")
def delete_policy(name: str):
    """Delete a WAF security policy from Redis."""
    storage = get_storage()
    success = storage.delete_policy(name)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{name}' not found",
        )
    return {"message": f"Policy '{name}' deleted successfully"}


@router.post("/policies/{name}/clone")
def clone_policy(name: str, req: ClonePolicyRequest):
    """Duplicate an existing policy with a new name."""
    if req.new_name.startswith("log:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target policy name cannot start with reserved prefix 'log:'",
        )
    storage = get_storage()
    if not storage.policy_exists(name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source policy '{name}' not found",
        )
    if storage.policy_exists(req.new_name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target policy '{req.new_name}' already exists",
        )

    try:
        meta = storage.clone_policy(name, req.new_name)
        return {"message": f"Policy '{name}' cloned to '{req.new_name}'", "metadata": meta}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/policies/{name}/export")
def export_policy(name: str):
    """Download policy as a formatted JSON attachment."""
    storage = get_storage()
    raw = storage.get_raw_policy(name)
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{name}' not found")

    return Response(
        content=raw,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}.json"'},
    )


@router.post("/policies/{name}/github-push")
def push_policy_to_github_endpoint(name: str, req: GitHubPushRequest = GitHubPushRequest()):
    """Commit and push an edited WAF policy from Redis to GitHub."""
    try:
        commit_info = push_policy_to_github(name=name, message=req.message)
        return {
            "message": f"Policy '{name}' successfully committed to GitHub (Commit {commit_info.get('short_sha')})",
            "commit": commit_info,
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Failed to commit policy '%s' to GitHub: %s", name, e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub commit failed: {str(e)}",
        )


@router.post("/policies/{name}/github-revert")
def revert_policy_from_github_endpoint(name: str):
    """Discard local intermediate Redis changes and reset policy to GitHub version."""
    storage = get_storage()
    if hasattr(storage, "revert_from_github"):
        try:
            return storage.revert_from_github(name)
        except FileNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Revert only supported in GitHub GitOps mode")


@router.post("/policies/import")
async def import_policy(file: UploadFile = File(...)):
    """Upload and import an F5 WAF policy JSON file into Redis."""
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8")
        parsed = json.loads(content_str)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read/decode JSON file: {str(e)}",
        )

    is_valid, errors, warnings, validated_dict = validate_policy_json(parsed)
    if not is_valid or not validated_dict:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation failed: {'; '.join(errors)}",
        )

    policy_name = validated_dict.get("policy", {}).get("name")
    if not policy_name:
        # Fallback to filename without extension
        policy_name = file.filename.rsplit(".", 1)[0]
        validated_dict["policy"]["name"] = policy_name

    if policy_name.startswith("log:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy name cannot start with reserved prefix 'log:'",
        )

    # Sanitize policy JSON (migrate Threat Campaigns, normalize signature-set aliases, drop invalid sets)
    validated_dict = sanitize_waf_policy(validated_dict)

    storage = get_storage()
    meta = storage.save_policy(policy_name, validated_dict, pre_validated=True)
    return {
        "message": f"Policy '{policy_name}' imported successfully",
        "metadata": meta,
        "warnings": warnings,
    }


@router.post("/policies/{name}/sanitize")
def sanitize_policy_endpoint(name: str):
    """Sanitize and normalize an existing policy (e.g. migrate Threat Campaigns, normalize signature sets)."""
    storage = get_storage()
    policy_data = storage.get_policy(name)
    if not policy_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{name}' not found")

    sanitized = sanitize_waf_policy(policy_data)
    meta = storage.save_policy(name, sanitized, pre_validated=True)
    return {
        "success": True,
        "message": f"Policy '{name}' successfully sanitized and normalized",
        "metadata": meta,
        "policy": sanitized,
    }


@router.post("/policies/validate")
def validate_policy_endpoint(req: ValidatePolicyRequest):
    """Validate arbitrary WAF policy JSON against F5 specifications."""
    is_valid, errors, warnings, parsed = validate_policy_json(req.content)
    meta = extract_policy_metadata(parsed) if parsed else None
    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "metadata": meta,
    }


@router.post("/policies/test-openapi-link")
def test_openapi_link(req: TestOpenApiLinkRequest):
    """Test and inspect an OpenAPI specification link (URL or local file reference)."""
    import base64
    import os
    import urllib.request
    import urllib.error
    import yaml

    link = req.link.strip()
    if not link:
        return {"success": False, "error": "Empty link provided"}

    content_str = None
    detected_scheme = None

    if link.startswith("file://"):
        detected_scheme = "file"
        file_path = link[7:]
        # On Windows, handle file:///C:/...
        if file_path.startswith("/") and len(file_path) > 2 and file_path[2] == ":":
            file_path = file_path[1:]
        if not os.path.exists(file_path):
            return {
                "success": False,
                "scheme": "file",
                "link": link,
                "error": f"Local file not found on disk: {file_path}",
            }
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content_str = f.read()
        except Exception as e:
            return {
                "success": False,
                "scheme": "file",
                "link": link,
                "error": f"Error reading local file: {str(e)}",
            }
    elif link.startswith(("http://", "https://")):
        detected_scheme = "url"
        temp_cert_file = None
        temp_key_file = None
        try:
            req_headers = {"User-Agent": "F5-WAF-Policy-Manager/1.0"}
            auth_type = req.authType.lower() if req.authType else "none"

            user = ""
            pwd_clear = ""
            if req.basicAuth:
                user = (req.basicAuth.get("user") or "").strip()
                pwd_clear = req.basicAuth.get("password") or ""
                pwd_b64 = req.basicAuth.get("passwordBase64") or ""
                if not pwd_clear and pwd_b64:
                    try:
                        pwd_clear = base64.b64decode(pwd_b64.strip()).decode("utf-8", errors="replace")
                    except Exception:
                        pwd_clear = pwd_b64.strip()

            if auth_type == "bearer" and req.bearerToken:
                token = req.bearerToken.strip()
                req_headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "basic" or user or pwd_clear:
                if user or pwd_clear:
                    user_pass = f"{user}:{pwd_clear}"
                    auth_header = base64.b64encode(user_pass.encode("utf-8")).decode("ascii")
                    req_headers["Authorization"] = f"Basic {auth_header}"

            ssl_ctx = None
            if link.startswith("https://"):
                import ssl
                import tempfile
                ssl_ctx = ssl.create_default_context()
                if req.allowSelfSigned:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE

                if auth_type == "mtls" and req.clientCert and req.clientKey:
                    # Write temporary cert and key files securely for mTLS handshake
                    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as cf:
                        cf.write(req.clientCert)
                        temp_cert_file = cf.name
                    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as kf:
                        kf.write(req.clientKey)
                        temp_key_file = kf.name
                    ssl_ctx.load_cert_chain(certfile=temp_cert_file, keyfile=temp_key_file)

            # Build opener with SSL and Basic Auth handlers
            handlers = []
            if ssl_ctx is not None:
                handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))

            if user or pwd_clear:
                # Add HTTPPasswordMgr for RFC 7617 challenge/realm response and redirect handling
                pass_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pass_mgr.add_password(None, link, user, pwd_clear)
                handlers.append(urllib.request.HTTPBasicAuthHandler(pass_mgr))

            opener = urllib.request.build_opener(*handlers)
            http_req = urllib.request.Request(link, headers=req_headers)
            try:
                with opener.open(http_req, timeout=15) as resp:
                    MAX_SPEC_SIZE = 50 * 1024 * 1024  # 50MB max
                    chunks = []
                    total_bytes = 0
                    chunk_size = 64 * 1024
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > MAX_SPEC_SIZE:
                            return {
                                "success": False,
                                "scheme": "url",
                                "link": link,
                                "error": f"OpenAPI specification exceeds the maximum supported size of {MAX_SPEC_SIZE // (1024 * 1024)}MB. Download was stopped to prevent parsing truncated content.",
                            }
                        chunks.append(chunk)
                    raw_bytes = b"".join(chunks)

                    # Decompress gzip if compressed
                    if raw_bytes.startswith(b"\x1f\x8b"):
                        import gzip
                        try:
                            raw_bytes = gzip.decompress(raw_bytes)
                        except Exception:
                            pass

                    content_str = raw_bytes.decode("utf-8", errors="replace")
            finally:
                # Clean up transient mTLS certificate files immediately
                if temp_cert_file and os.path.exists(temp_cert_file):
                    try:
                        os.remove(temp_cert_file)
                    except Exception:
                        pass
                if temp_key_file and os.path.exists(temp_key_file):
                    try:
                        os.remove(temp_key_file)
                    except Exception:
                        pass
        except urllib.error.HTTPError as e:
            msg = f"HTTP Error {e.code}: {e.reason}"
            if e.code == 401:
                msg += " - Server rejected credentials or requires authentication. Check username, password, or auth realm."
            elif e.code == 403:
                msg += " - Access forbidden. Check permissions or token authorization."
            elif e.code == 404:
                msg += " - Specification URL path not found."
            return {
                "success": False,
                "scheme": "url",
                "link": link,
                "error": f"Failed to retrieve URL: {msg}",
            }
        except Exception as e:
            return {
                "success": False,
                "scheme": "url",
                "link": link,
                "error": f"Failed to retrieve URL: {str(e)}",
            }
    else:
        return {
            "success": False,
            "error": "Unsupported URI scheme. Must start with http://, https://, or file:///",
        }

    # Parse content as JSON or YAML
    parsed_spec = None
    spec_format = None

    # Try JSON first
    try:
        parsed_spec = json.loads(content_str)
        spec_format = "json"
    except Exception:
        pass

    if parsed_spec is None:
        try:
            parsed_spec = yaml.safe_load(content_str)
            spec_format = "yaml"
        except Exception as e:
            return {
                "success": False,
                "scheme": detected_scheme,
                "link": link,
                "error": f"File could not be parsed as JSON or YAML: {str(e)}",
            }

    if not isinstance(parsed_spec, dict):
        return {
            "success": False,
            "scheme": detected_scheme,
            "link": link,
            "error": "Parsed document is not a valid JSON/YAML dictionary",
        }

    # Extract OpenAPI / Swagger metadata
    is_openapi = "openapi" in parsed_spec or "swagger" in parsed_spec
    openapi_version = parsed_spec.get("openapi") or parsed_spec.get("swagger") or "unknown"
    info = parsed_spec.get("info", {}) if isinstance(parsed_spec.get("info"), dict) else {}
    title = info.get("title", "Untitled API")
    version = info.get("version", "1.0.0")
    description = info.get("description", "")
    paths = parsed_spec.get("paths", {}) if isinstance(parsed_spec.get("paths"), dict) else {}
    paths_count = len(paths)

    components = parsed_spec.get("components", {}) if isinstance(parsed_spec.get("components"), dict) else {}
    schemas = components.get("schemas", {}) if isinstance(components.get("schemas"), dict) else parsed_spec.get("definitions", {})
    schemas_count = len(schemas) if isinstance(schemas, dict) else 0

    return {
        "success": True,
        "validSpec": is_openapi,
        "scheme": detected_scheme,
        "format": spec_format,
        "link": link,
        "title": title,
        "version": str(version),
        "description": description[:200] if description else "",
        "openApiVersion": str(openapi_version),
        "pathsCount": paths_count,
        "schemasCount": schemas_count,
        "samplePaths": list(paths.keys())[:5],
    }


def parse_grpc_idl_content(
    raw_bytes: bytes,
    filename_or_link: str,
    primary_idl_file_name: Optional[str] = None,
    detected_scheme: str = "file",
) -> Dict[str, Any]:
    """Parse raw bytes of a .proto file or .tar/.tgz archive bundle and extract IDL metadata."""
    import io
    import os
    import re
    import tarfile

    lower_link = filename_or_link.lower().split("?")[0]
    is_archive_ext = any(lower_link.endswith(ext) for ext in [".tar", ".tgz", ".tar.gz"])

    is_archive = False
    tar_members = []
    proto_files = []
    primary_proto_content = None
    primary_name = primary_idl_file_name.strip() if primary_idl_file_name else None

    # Check if archive either by extension or tar magic / gzip header
    if is_archive_ext or raw_bytes[:2] == b"\x1f\x8b" or (len(raw_bytes) > 260 and b"ustar" in raw_bytes[:512]):
        try:
            tar_stream = io.BytesIO(raw_bytes)
            with tarfile.open(fileobj=tar_stream, mode="r:*") as tar:
                is_archive = True
                tar_members = [m.name for m in tar.getmembers() if not m.isdir()]
                proto_files = [m for m in tar_members if m.lower().endswith(".proto")]

                # Resolve primary file
                target_file = None
                if primary_name:
                    for m in proto_files:
                        if m == primary_name or os.path.basename(m) == os.path.basename(primary_name):
                            target_file = m
                            break
                elif proto_files:
                    target_file = proto_files[0]
                    primary_name = target_file

                if target_file:
                    fobj = tar.extractfile(target_file)
                    if fobj:
                        primary_proto_content = fobj.read().decode("utf-8", errors="replace")
        except Exception as e:
            if is_archive_ext:
                return {
                    "success": False,
                    "scheme": detected_scheme,
                    "link": filename_or_link,
                    "error": f"Corrupt or invalid tar/tgz archive: {str(e)}",
                }

    # If not an archive, treat as .proto text file
    if not is_archive:
        try:
            primary_proto_content = raw_bytes.decode("utf-8", errors="replace")
            primary_name = os.path.basename(lower_link)
        except Exception as e:
            return {
                "success": False,
                "scheme": detected_scheme,
                "link": filename_or_link,
                "error": f"Failed to decode .proto file as UTF-8 text: {str(e)}",
            }

    # Parse protobuf text for syntax, services, RPCs, messages
    proto_syntax = None
    package_name = None
    services = []
    messages = []

    if primary_proto_content:
        # Check syntax
        syntax_match = re.search(r'syntax\s*=\s*["\']([^"\']+)["\'];', primary_proto_content)
        if syntax_match:
            proto_syntax = syntax_match.group(1)

        # Check package
        pkg_match = re.search(r'package\s+([a-zA-Z0-9_\.]+);', primary_proto_content)
        if pkg_match:
            package_name = pkg_match.group(1)

        # Extract services and their RPC methods
        service_blocks = re.finditer(r'service\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\}', primary_proto_content, re.MULTILINE)
        for sb in service_blocks:
            svc_name = sb.group(1)
            svc_body = sb.group(2)
            rpc_methods = re.findall(r'rpc\s+([a-zA-Z0-9_]+)\s*\(', svc_body)
            services.append({
                "name": svc_name,
                "methods": rpc_methods
            })

        # Extract message names
        messages = re.findall(r'message\s+([a-zA-Z0-9_]+)\s*\{', primary_proto_content)

    is_proto3 = (proto_syntax == "proto3")
    warning_msg = None
    if proto_syntax and not is_proto3:
        warning_msg = f"Detected syntax '{proto_syntax}'. F5 WAF for NGINX strictly requires Protocol Buffers v3 (syntax = \"proto3\";)."

    return {
        "success": True,
        "scheme": detected_scheme,
        "link": filename_or_link,
        "fileType": "archive" if is_archive else "proto",
        "isArchive": is_archive,
        "syntax": proto_syntax or "unknown",
        "isProto3": is_proto3,
        "warning": warning_msg,
        "packageName": package_name,
        "primaryIdlFileName": primary_name,
        "services": services,
        "servicesCount": len(services),
        "messages": messages[:20],
        "messagesCount": len(messages),
        "archiveMembers": tar_members if is_archive else None,
        "protoFiles": proto_files if is_archive else None,
        "sizeBytes": len(raw_bytes),
    }


@router.post("/policies/test-grpc-idl")
def test_grpc_idl(req: TestGrpcIdlRequest):
    """Test and inspect a gRPC Interface Definition Language (IDL) file or archive bundle."""
    import os
    import urllib.request
    import urllib.error

    link = req.link.strip()
    if not link:
        return {"success": False, "error": "Empty link provided"}

    raw_bytes = None
    detected_scheme = None

    if link.startswith("file://"):
        detected_scheme = "file"
        file_path = link[7:]
        # On Windows, handle file:///C:/...
        if file_path.startswith("/") and len(file_path) > 2 and file_path[2] == ":":
            file_path = file_path[1:]
        if not os.path.exists(file_path):
            return {
                "success": False,
                "scheme": "file",
                "link": link,
                "error": f"Local file not found on disk: {file_path}",
            }
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            return {
                "success": False,
                "scheme": "file",
                "link": link,
                "error": f"Error reading local file: {str(e)}",
            }
    elif link.startswith(("http://", "https://")):
        detected_scheme = "url"
        try:
            req_headers = {"User-Agent": "F5-WAF-Policy-Manager/1.0"}
            http_req = urllib.request.Request(link, headers=req_headers)
            with urllib.request.urlopen(http_req, timeout=8) as resp:
                raw_bytes = resp.read(10 * 1024 * 1024)  # 10MB max buffer limit
        except Exception as e:
            return {
                "success": False,
                "scheme": "url",
                "link": link,
                "error": f"Failed to retrieve URL: {str(e)}",
            }
    else:
        return {
            "success": False,
            "error": "Unsupported URI scheme. Must start with http://, https://, or file:///",
        }

    return parse_grpc_idl_content(
        raw_bytes=raw_bytes,
        filename_or_link=link,
        primary_idl_file_name=req.primaryIdlFileName,
        detected_scheme=detected_scheme,
    )


@router.post("/policies/inspect-grpc-upload")
async def inspect_grpc_upload(
    file: UploadFile = File(...),
    primaryIdlFileName: Optional[str] = Form(None),
):
    """Temporarily upload and inspect gRPC IDL (.proto or .tar/.tgz) in-memory for containerized environments.
    
    The file is inspected directly from memory and discarded immediately; no persistent copy is retained.
    """
    filename = file.filename or "uploaded_idl"
    lower_name = filename.lower()
    if not any(lower_name.endswith(ext) for ext in [".proto", ".tar", ".tgz", ".tar.gz"]):
        return {
            "success": False,
            "error": f"Unsupported file type for '{filename}'. Allowed formats: .proto, .tar, .tgz, .tar.gz",
        }

    raw_bytes = await file.read(10 * 1024 * 1024 + 1)
    if len(raw_bytes) > 10 * 1024 * 1024:
        return {
            "success": False,
            "error": "Uploaded file exceeds the 10MB buffer limit for F5 WAF gRPC IDL inspection.",
        }

    res = parse_grpc_idl_content(
        raw_bytes=raw_bytes,
        filename_or_link=filename,
        primary_idl_file_name=primaryIdlFileName,
        detected_scheme="upload",
    )
    res["fileName"] = filename
    return res


# --- Reference Catalogs & Templates ---

@router.get("/templates")
def get_templates():
    """List reference starter templates."""
    return list_templates()


@router.get("/templates/{template_id}")
def get_template(template_id: str):
    """Retrieve JSON for a specific starter template."""
    content = get_template_json(template_id)
    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    return content


@router.get("/catalog")
def get_schema_catalog():
    """Retrieve full catalog of violations, signature sets, server technologies, encodings, and methods."""
    return {
        "categories": VIOLATION_CATEGORIES,
        "violations": VIOLATIONS_CATALOG,
        "openApiRecommendedViolations": OPENAPI_RECOMMENDED_VIOLATIONS,
        "grpcRecommendedViolations": GRPC_RECOMMENDED_VIOLATIONS,
        "signatureSets": STANDARD_SIGNATURE_SETS,
        "attackSignatures": ATTACK_SIGNATURES_CATALOG,
        "serverTechnologies": SERVER_TECHNOLOGIES,
        "baseTemplates": BASE_TEMPLATES,
        "enforcementModes": ENFORCEMENT_MODES,
        "supportedMethods": SUPPORTED_METHODS,
        "supportedEncodings": SUPPORTED_ENCODINGS,
        "grpcSamples": [
            {
                "name": "Example gRPC Service Proto (Single .proto)",
                "link": "file:///examples/grpc/album.proto",
                "fileType": "proto",
                "isPrimary": True,
                "description": "Individual proto3 file defining Example gRPC service with RPC methods",
            },
            {
                "name": "Example gRPC Service Bundle (Tarball .tgz)",
                "link": "file:///examples/grpc/album_service_files.tgz",
                "fileType": "archive",
                "primaryIdlFileName": "album_service.proto",
                "description": "Packaged .tgz archive containing multiple protos with dependency imports",
            },
            {
                "name": "RouteGuide Service Proto (Remote URL)",
                "link": "https://raw.githubusercontent.com/grpc/grpc/master/examples/protos/route_guide.proto",
                "fileType": "proto",
                "isPrimary": True,
                "description": "Standard official gRPC sample service loaded over HTTPS",
            },
        ],
    }


@router.get("/signature-sets/{set_name}/signatures")
def get_signature_set_signatures(
    set_name: str,
    search: Optional[str] = None,
    accuracy: Optional[str] = None,
    risk: Optional[str] = None,
):
    """Retrieve all attack signatures included in a standard or custom signature set."""
    sigs = get_signatures_for_set(set_name)
    if search:
        s = search.lower().strip()
        sigs = [
            sig for sig in sigs
            if s in str(sig.get("signatureId"))
            or s in sig.get("name", "").lower()
            or s in sig.get("description", "").lower()
            or s in (sig.get("cve") or "").lower()
            or s in sig.get("attackType", "").lower()
            or any(s in sys.lower() for sys in sig.get("systems", []))
        ]
    if accuracy and accuracy.lower() != "all":
        sigs = [sig for sig in sigs if sig.get("accuracy", "").lower() == accuracy.lower()]
    if risk and risk.lower() != "all":
        sigs = [sig for sig in sigs if sig.get("risk", "").lower() == risk.lower()]

    return {
        "setName": set_name,
        "total": len(sigs),
        "signatures": sigs,
    }



# --- Storage Connection Health & Backend Configuration (Redis, GitHub, In-Memory) ---

@router.get("/storage/status")
@router.get("/redis/status")
def get_storage_status_endpoint():
    """Check status, connection health, and active backend (Redis, GitHub, or In-Memory)."""
    return get_storage_health()


@router.get("/github/status")
def get_github_status_endpoint():
    """Retrieve current GitHub configuration and repository connection status."""
    return get_github_status()


@router.get("/github/pull/conflicts")
def get_github_pull_conflicts_endpoint():
    """Check for conflicts between GitHub repository files and local Redis draft copies."""
    try:
        return get_pull_conflicts()
    except Exception as e:
        logger.error("Failed to check GitHub pull conflicts: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check GitHub pull conflicts: {str(e)}",
        )


@router.post("/github/pull")
def pull_github_endpoint(req: Optional[GitHubPullRequest] = None):
    """Retrieve policies and log profiles from configured GitHub repository into Redis."""
    try:
        resolutions = req.resolutions if req else None
        res = pull_from_github(resolutions=resolutions)
        return res
    except Exception as e:
        logger.error("Failed to pull from GitHub: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to retrieve files from GitHub: {str(e)}",
        )


@router.post("/github/commit-preview")
def commit_preview_endpoint(req: GitHubCommitPreviewRequest):
    """Generate a verbose Git commit description highlighting changes made to a policy, log profile, or signatures."""
    try:
        if req.type == "policy":
            store = get_storage()
            new_data = req.content
            if not new_data:
                new_data = store.get_raw_policy(req.name)

            remote_content = None
            if hasattr(store, "client") and store.client:
                file_path = store._file_path_for(req.name)
                try:
                    remote_content, _ = store.client.get_file(file_path)
                except Exception:
                    remote_content = None
            elif hasattr(store, "_sha_content_cache"):
                existing_sha = getattr(store, "_name_to_sha", {}).get(req.name)
                if existing_sha:
                    remote_content = store._sha_content_cache.get(existing_sha)

            commit_msg = summarize_policy_changes(remote_content, new_data, req.name)
            return {"type": req.type, "name": req.name, "commit_message": commit_msg}

        elif req.type == "logging":
            store = get_logging_storage()
            new_data = req.content
            if not new_data:
                new_data = store.get_raw_profile(req.name)

            remote_content = None
            if hasattr(store, "client") and store.client:
                file_path = store._file_path_for(req.name)
                try:
                    remote_content, _ = store.client.get_file(file_path)
                except Exception:
                    remote_content = None
            elif hasattr(store, "_sha_content_cache"):
                existing_sha = getattr(store, "_name_to_sha", {}).get(req.name)
                if existing_sha:
                    remote_content = store._sha_content_cache.get(existing_sha)

            commit_msg = summarize_log_profile_changes(remote_content, new_data, req.name)
            return {"type": req.type, "name": req.name, "commit_message": commit_msg}

        elif req.type in ("signatures", "custom_signatures"):
            store = get_custom_signatures_storage()
            new_data = req.content
            if not new_data:
                new_data = store.get_raw_set(req.name)

            remote_content = None
            if hasattr(store, "client") and store.client:
                file_path = store._file_path_for(req.name)
                try:
                    remote_content, _ = store.client.get_file(file_path)
                except Exception:
                    remote_content = None

            commit_msg = summarize_custom_signatures_changes(remote_content, new_data, req.name)
            return {"type": req.type, "name": req.name, "commit_message": commit_msg}

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported item type '{req.type}'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to generate commit preview: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate commit preview: {str(e)}",
        )


@router.post("/github/connect")
def connect_github_endpoint(req: GitHubConfigRequest):
    """Test connection, configure GitHub GitOps remote, and pull repository policies into Redis."""
    try:
        init_github_storage(
            owner=req.owner,
            repo=req.repo,
            token=req.token,
            branch=req.branch,
            api_url=req.api_url,
            verify_ssl=req.verify_ssl,
            disable_ssl_verify=req.disable_ssl_verify,
            policies_path=req.policies_path,
            log_profiles_path=req.log_profiles_path,
            custom_sigs_path=req.custom_sigs_path,
            auto_pull=True,
        )
        health = get_storage_health()
        gh_info = health.get("github", {})
        return {
            "message": f"Successfully connected to GitHub repository '{req.owner}/{req.repo}' (branch: {gh_info.get('branch', 'main')})",
            "health": health,
        }
    except Exception as e:
        logger.error("GitHub connection error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to GitHub: {str(e)}",
        )


@router.post("/redis/connect")
def connect_redis(req: RedisConfigRequest):
    """Test connection or switch Redis backend settings dynamically."""
    try:
        new_storage = init_storage(
            host=req.host,
            port=req.port,
            db=req.db,
            password=req.password,
            ssl=req.ssl,
            key_prefix=req.key_prefix,
            force_memory=req.force_memory,
        )
        health = get_storage_health()
        return {
            "message": "Storage backend reconfigured successfully",
            "health": health,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to connect to Redis: {str(e)}",
        )


@router.post("/storage/switch")
def switch_storage_endpoint(req: StorageConfigRequest):
    """Switch active storage engine between GitHub, Redis, and In-Memory."""
    try:
        target = req.backend.lower()
        if target == "github":
            if not req.github:
                raise ValueError("GitHub endpoint configuration (owner, repo, token) is required")
            init_github_storage(
                owner=req.github.owner,
                repo=req.github.repo,
                token=req.github.token,
                branch=req.github.branch,
                api_url=req.github.api_url,
                verify_ssl=req.github.verify_ssl,
                disable_ssl_verify=req.github.disable_ssl_verify,
                policies_path=req.github.policies_path,
                log_profiles_path=req.github.log_profiles_path,
                custom_sigs_path=req.github.custom_sigs_path,
            )
        elif target == "memory":
            init_storage(force_memory=True)
        else:
            r = req.redis or RedisConfigRequest()
            init_storage(
                host=r.host,
                port=r.port,
                db=r.db,
                password=r.password,
                ssl=r.ssl,
                key_prefix=r.key_prefix,
                force_memory=r.force_memory,
            )

        health = get_storage_health()
        return {
            "message": f"Storage backend switched to {target.upper()}",
            "health": health,
        }
    except Exception as e:
        logger.error("Storage switch error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to switch storage: {str(e)}",
        )


# --- BIG-IP WAF Policy Converter Endpoints ---

@router.post("/policies/convert-bigip")
async def convert_bigip_endpoint(
    file: UploadFile = File(...),
    target_name: Optional[str] = Form(None),
    full_export: bool = Form(True),
    keep_full_configuration: bool = Form(False),
    include_all_signatures: bool = Form(False),
    save_to_storage: bool = Form(True),
):
    """Upload and convert a BIG-IP WAF policy export (JSON format) into an F5 WAF for NGINX declarative JSON policy.

    If save_to_storage is True, the converted policy is immediately saved to the storage backend
    and becomes managed by the WAF policy editor.
    """
    try:
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded policy file is empty.",
            )

        if len(file_bytes) > 50 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded policy file exceeds maximum size limit of 50MB.",
            )

        result = convert_bigip_policy(
            content=file_bytes,
            target_name=target_name.strip() if target_name else None,
            full_export=full_export,
            keep_full_configuration=keep_full_configuration,
            include_all_signatures=include_all_signatures,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=result.get("error", "Failed to convert BIG-IP policy"),
            )

        policy_dict = result["policy"]
        policy_name = result["policy_name"]

        meta = None
        if save_to_storage:
            storage = get_storage()
            meta = storage.save_policy(policy_name, policy_dict, pre_validated=True)

        return {
            "success": True,
            "message": f"BIG-IP policy successfully converted{' and saved as ' + policy_name if save_to_storage else ''}",
            "policy_name": policy_name,
            "engine": result.get("engine", "built-in-json-converter"),
            "warnings": result.get("warnings", []),
            "file_size": len(file_bytes),
            "policy": policy_dict if (not save_to_storage or len(file_bytes) < 1024 * 1024) else None,
            "saved": save_to_storage,
            "metadata": meta,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to convert BIG-IP policy")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"BIG-IP policy conversion failed: {str(e)}",
        )


# --- Policy & Logging Profile Compiler Testing Endpoints ---

@router.post("/compiler/test")
def test_compiler_endpoint(req: TestCompilerRequest):
    """Test compilation of a security policy or logging profile using apcompile or the built-in compiler.

    Returns compilation status, bundle information on success, or structured, formatted diagnostics
    with actionable remediation instructions on failure.
    """
    target_type = req.target_type.lower()
    if target_type not in ("policy", "log_profile"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target_type '{req.target_type}'. Must be 'policy' or 'log_profile'.",
        )

    content = req.content
    effective_name = req.target_name

    if content is None:
        if not effective_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'content' or 'target_name' must be provided for compilation test.",
            )
        if target_type == "policy":
            storage = get_storage()
            content = storage.get_policy(effective_name)
            if content is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Security policy '{effective_name}' not found in storage.",
                )
        else:
            log_storage = get_logging_storage()
            content = log_storage.get_profile(effective_name)
            if content is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Logging profile '{effective_name}' not found in storage.",
                )

    if not effective_name and isinstance(content, dict):
        if target_type == "policy":
            effective_name = content.get("policy", {}).get("name", "unnamed_policy")
        else:
            effective_name = "unnamed_profile"

    service = WafCompilerService()
    result = service.test_compilation(
        target_type=target_type,
        content=content,
        target_name=effective_name,
        include_source=req.include_source,
        full_export=req.full_export,
        global_settings=req.global_settings,
    )
    return result


@router.get("/compiler/status")
def get_compiler_status():
    """Retrieve compiler capability and engine status."""
    service = WafCompilerService()
    return service.get_status()


@router.get("/compiler/download/{bundle_id}")
def download_compiled_bundle(bundle_id: str):
    """Download compiled .tgz bundle by bundle ID."""
    service = WafCompilerService()
    bundle_info = service.get_bundle(bundle_id)
    if not bundle_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compiled bundle expired or not found. Please re-run compilation.",
        )
    return Response(
        content=bundle_info["bytes"],
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{bundle_info["bundle_name"]}"',
            "X-Bundle-SHA256": bundle_info["bundle_sha256"],
        },
    )

