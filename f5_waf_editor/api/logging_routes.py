"""
REST API routes for F5 WAF Logging Profiles CRUD, validation, import/export.
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field

from f5_waf_editor.schemas.logging_schema import (
    LOG_ATTRIBUTES,
    LOG_FORMATS,
    REQUEST_TYPES,
)
from f5_waf_editor.schemas.logging_validator import validate_logging_profile_json
from f5_waf_editor.storage import get_logging_storage
from f5_waf_editor.templates_catalog.logging import (
    get_logging_template_dict,
    get_logging_template_json,
    list_logging_templates,
)

router = APIRouter(prefix="/api", tags=["Logging Profiles"])


class CreateLoggingProfileRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    template_id: Optional[str] = "log_default"
    content: Optional[Dict[str, Any]] = None


class UpdateLoggingProfileRequest(BaseModel):
    content: Dict[str, Any]


class CloneLoggingProfileRequest(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=128)


class ValidateLoggingRequest(BaseModel):
    content: Any


class GitHubPushRequest(BaseModel):
    message: Optional[str] = Field(None, description="Optional custom Git commit message")


# --------------------------------------------------------------------------
# CRUD Endpoints
# --------------------------------------------------------------------------


@router.get("/log-profiles", response_model=List[Dict[str, Any]])
def list_logging_profiles():
    """List all logging profiles stored in Redis with metadata."""
    storage = get_logging_storage()
    return storage.list_profiles()


@router.get("/log-profiles/{name}")
def get_logging_profile(name: str):
    """Retrieve full JSON logging profile document."""
    storage = get_logging_storage()
    data = storage.get_profile(name)
    if data is None:
        raise HTTPException(status_code=404, detail=f"Logging profile '{name}' not found")
    return data


@router.post("/log-profiles", status_code=status.HTTP_201_CREATED)
def create_logging_profile(req: CreateLoggingProfileRequest):
    """Create a new logging profile in Redis from template or provided JSON."""
    storage = get_logging_storage()
    name = req.name.strip()

    if storage.profile_exists(name):
        raise HTTPException(
            status_code=409, detail=f"Logging profile with name '{name}' already exists"
        )

    if req.content:
        content = req.content
    elif req.template_id:
        tmpl = get_logging_template_dict(req.template_id)
        if not tmpl:
            raise HTTPException(
                status_code=400, detail=f"Template '{req.template_id}' not found"
            )
        content = tmpl
    else:
        content = get_logging_template_dict("log_default")

    is_valid, errors, warnings, parsed = validate_logging_profile_json(content)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid logging profile schema", "errors": errors},
        )

    try:
        metadata = storage.save_profile(name, parsed)
        return {
            "message": f"Logging profile '{name}' created successfully",
            "metadata": metadata,
            "warnings": warnings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/log-profiles/{name}")
def update_logging_profile(name: str, req: UpdateLoggingProfileRequest):
    """Update an existing logging profile in Redis."""
    storage = get_logging_storage()
    if not storage.profile_exists(name):
        raise HTTPException(status_code=404, detail=f"Logging profile '{name}' not found")

    is_valid, errors, warnings, parsed = validate_logging_profile_json(req.content)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid logging profile schema", "errors": errors},
        )

    try:
        metadata = storage.save_profile(name, parsed)
        return {
            "message": f"Logging profile '{name}' updated successfully",
            "metadata": metadata,
            "warnings": warnings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/log-profiles/{name}")
def delete_logging_profile(name: str):
    """Delete a logging profile from Redis."""
    storage = get_logging_storage()
    if not storage.profile_exists(name):
        raise HTTPException(status_code=404, detail=f"Logging profile '{name}' not found")

    storage.delete_profile(name)
    return {"message": f"Logging profile '{name}' deleted successfully"}


@router.post("/log-profiles/{name}/clone")
def clone_logging_profile(name: str, req: CloneLoggingProfileRequest):
    """Clone an existing logging profile under a new name."""
    storage = get_logging_storage()
    target_name = req.new_name.strip()

    if not storage.profile_exists(name):
        raise HTTPException(status_code=404, detail=f"Source profile '{name}' not found")
    if storage.profile_exists(target_name):
        raise HTTPException(
            status_code=409, detail=f"Target profile '{target_name}' already exists"
        )

    try:
        metadata = storage.clone_profile(name, target_name)
        return {
            "message": f"Profile '{name}' successfully cloned to '{target_name}'",
            "metadata": metadata,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Import / Export / Validation
# --------------------------------------------------------------------------


@router.get("/log-profiles/{name}/export")
def export_logging_profile(name: str):
    """Download logging profile as a formatted JSON attachment."""
    storage = get_logging_storage()
    raw = storage.get_raw_profile(name)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"Logging profile '{name}' not found")

    return Response(
        content=raw,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}.json"'},
    )


@router.post("/log-profiles/{name}/github-push")
def push_logging_profile_to_github_endpoint(name: str, req: GitHubPushRequest = GitHubPushRequest()):
    """Commit and push an edited logging profile from Redis to GitHub."""
    try:
        from ..storage import push_log_profile_to_github
        commit_info = push_log_profile_to_github(name=name, message=req.message)
        return {
            "message": f"Logging profile '{name}' successfully committed to GitHub (Commit {commit_info.get('short_sha')})",
            "commit": commit_info,
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Failed to commit logging profile '%s' to GitHub: %s", name, e)
        raise HTTPException(status_code=502, detail=f"GitHub commit failed: {str(e)}")


@router.post("/log-profiles/{name}/github-revert")
def revert_logging_profile_from_github_endpoint(name: str):
    """Discard local intermediate Redis changes and reset logging profile to GitHub version."""
    storage = get_logging_storage()
    if hasattr(storage, "revert_from_github"):
        try:
            return storage.revert_from_github(name)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    raise HTTPException(status_code=400, detail="Revert only supported in GitHub GitOps mode")


@router.post("/log-profiles/import")
async def import_logging_profile(file: UploadFile = File(...), override_name: Optional[str] = None):
    """Upload and import an F5 WAF logging profile JSON file."""
    storage = get_logging_storage()
    content_bytes = await file.read()
    try:
        raw_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")

    is_valid, errors, warnings, parsed = validate_logging_profile_json(raw_str)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid logging profile file", "errors": errors},
        )

    if override_name:
        profile_name = override_name.strip()
    else:
        profile_name = file.filename.replace(".json", "") if file.filename else "imported_log_profile"

    try:
        metadata = storage.save_profile(profile_name, parsed)
        return {
            "message": f"Logging profile '{profile_name}' imported successfully",
            "metadata": metadata,
            "warnings": warnings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/log-profiles/validate")
def validate_logging_profile_endpoint(req: ValidateLoggingRequest):
    """Validate arbitrary logging profile payload."""
    is_valid, errors, warnings, parsed = validate_logging_profile_json(req.content)
    return {"valid": is_valid, "errors": errors, "warnings": warnings}


# --------------------------------------------------------------------------
# Templates & Catalog
# --------------------------------------------------------------------------


@router.get("/log-templates")
def get_log_templates():
    """List available reference logging profile templates."""
    return list_logging_templates()


@router.get("/log-templates/{template_id}")
def get_log_template_content(template_id: str):
    """Retrieve raw template JSON for starter logging profiles."""
    tmpl = get_logging_template_dict(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return tmpl


@router.get("/log-catalog")
def get_log_catalog():
    """Retrieve reference catalog of request types, formats, and placeholder attributes."""
    return {
        "request_types": REQUEST_TYPES,
        "formats": LOG_FORMATS,
        "attributes": LOG_ATTRIBUTES,
    }
