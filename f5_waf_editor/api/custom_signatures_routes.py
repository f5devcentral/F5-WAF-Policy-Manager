"""
REST API routes for F5 WAF User-Defined Signatures (Custom Signatures) CRUD, catalog, validation, import/export.
Follows official documentation: https://docs.nginx.com/waf/policies/user-signatures/#signatures
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field

from f5_waf_editor.schemas.waf_schema import (
    DEFAULT_USER_SIGNATURE_DEFINITIONS,
    SNORT_RULE_TEMPLATES,
    CUSTOM_SIGNATURE_ATTACK_TYPES,
    SERVER_TECHNOLOGIES,
)
from f5_waf_editor.schemas.validator import validate_user_defined_signatures_file
from f5_waf_editor.schemas.snort_validator import validate_snort_rule, evaluate_snort_rule
from f5_waf_editor.storage import get_custom_signatures_storage


router = APIRouter(prefix="/api", tags=["User-Defined Signatures"])


class CreateCustomSignaturesRequest(BaseModel):
    tag: str = Field(..., min_length=1, max_length=128)
    content: Optional[Dict[str, Any]] = None


class UpdateCustomSignaturesRequest(BaseModel):
    content: Dict[str, Any]


class ValidateCustomSignaturesRequest(BaseModel):
    content: Any


# --------------------------------------------------------------------------
# Catalog & Helper Endpoints
# --------------------------------------------------------------------------


@router.get("/custom-signatures-catalog")
def get_custom_signatures_catalog():
    """Returns available Snort templates, standard attack types, and systems for user-defined signatures."""
    return {
        "snortTemplates": SNORT_RULE_TEMPLATES,
        "attackTypes": CUSTOM_SIGNATURE_ATTACK_TYPES,
        "systems": [t["name"] for t in SERVER_TECHNOLOGIES],
        "defaultTemplate": DEFAULT_USER_SIGNATURE_DEFINITIONS,
    }


# --------------------------------------------------------------------------
# CRUD Endpoints
# --------------------------------------------------------------------------


@router.get("/custom-signatures", response_model=List[Dict[str, Any]])
def list_custom_signature_files():
    """List all user-defined signature definition files with metadata."""
    storage = get_custom_signatures_storage()
    return storage.list_signature_files()


@router.get("/custom-signatures/all", response_model=List[Dict[str, Any]])
def list_all_custom_signatures():
    """List all flattened custom signatures across all tags with their respective tag and source."""
    storage = get_custom_signatures_storage()
    return storage.get_all_signatures()


@router.get("/custom-signatures/{tag}")
def get_custom_signatures_file(tag: str):
    """Retrieve full JSON custom signature definition file for a tag."""
    storage = get_custom_signatures_storage()
    data = storage.get_signature_file(tag)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-defined signature file for tag '{tag}' not found",
        )
    return data


@router.post("/custom-signatures", status_code=status.HTTP_201_CREATED)
def create_custom_signatures_file(payload: CreateCustomSignaturesRequest):
    """Create or overwrite a custom signatures definition file."""
    storage = get_custom_signatures_storage()
    tag = payload.tag.strip()

    content = payload.content
    if content is None:
        content = {
            "softwareVersion": "15.1.0",
            "tag": tag,
            "revisionDatetime": "2026-10-01T12:00:00Z",
            "signatures": [],
        }
    else:
        content["tag"] = tag

    try:
        result = storage.save_signature_file(tag, content)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.put("/custom-signatures/{tag}")
def update_custom_signatures_file(tag: str, payload: UpdateCustomSignaturesRequest):
    """Update custom signatures definition file for a tag."""
    storage = get_custom_signatures_storage()
    try:
        result = storage.save_signature_file(tag, payload.content)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.delete("/custom-signatures/{tag}")
def delete_custom_signatures_file(tag: str):
    """Delete a user-defined signature definition file."""
    storage = get_custom_signatures_storage()
    success = storage.delete_signature_file(tag)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-defined signature file for tag '{tag}' not found",
        )
    return {"deleted": True, "tag": tag}


# --------------------------------------------------------------------------
# Validation, Export & Import Endpoints
# --------------------------------------------------------------------------


@router.post("/custom-signatures/validate")
def validate_custom_signatures(payload: ValidateCustomSignaturesRequest):
    """Validate user-defined signature definition JSON without persisting."""
    is_valid, errors, warnings, parsed = validate_user_defined_signatures_file(payload.content)
    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "parsed": parsed if is_valid else None,
    }


@router.get("/custom-signatures/{tag}/export")
def export_custom_signatures_file(tag: str):
    """Download custom signature definition file as formatted JSON."""
    storage = get_custom_signatures_storage()
    raw = storage.get_raw_signature_file(tag)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-defined signature file for tag '{tag}' not found",
        )
    return Response(
        content=raw,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="signatures_{tag}.json"'},
    )


class GitHubPushCustomSigsRequest(BaseModel):
    message: Optional[str] = Field(None, description="Optional custom Git commit message")


@router.post("/custom-signatures/{tag}/github-push")
def push_custom_signatures_to_github_endpoint(tag: str, req: GitHubPushCustomSigsRequest = GitHubPushCustomSigsRequest()):
    """Commit and push an edited custom signature set from Redis to GitHub."""
    try:
        from ..storage import push_custom_signatures_to_github
        commit_info = push_custom_signatures_to_github(tag=tag, message=req.message)
        return {
            "message": f"Custom signature set '{tag}' successfully committed to GitHub (Commit {commit_info.get('short_sha')})",
            "commit": commit_info,
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub commit failed: {str(e)}")


@router.post("/custom-signatures/import")
async def import_custom_signatures_file(file: UploadFile = File(...)):
    """Upload and import a user-defined signature definition JSON file."""
    if not file.filename.endswith((".json", ".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a .json or .txt file containing JSON",
        )

    try:
        raw_bytes = await file.read()
        raw_text = raw_bytes.decode("utf-8")
        parsed = json.loads(raw_text)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse uploaded JSON file: {exc}",
        )

    is_valid, errors, warnings, validated_data = validate_user_defined_signatures_file(parsed)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation failed: {'; '.join(errors)}",
        )

    tag = validated_data.get("tag")
    if not tag:
        tag = file.filename.rsplit(".", 1)[0].replace("signatures_", "").replace("user_defined_signatures_", "")
        if not tag:
            tag = "imported-signatures"
        validated_data["tag"] = tag

    storage = get_custom_signatures_storage()
    result = storage.save_signature_file(tag, validated_data)
    return {
        "imported": True,
        "tag": tag,
        "metadata": result.get("metadata"),
        "warnings": warnings,
    }


class ValidateSnortRulePayload(BaseModel):
    rule: str


class TestSnortRulePayload(BaseModel):
    rule: str
    context: Dict[str, Any] = Field(default_factory=dict)


@router.post("/custom-signatures/validate-snort-rule")
def validate_snort_rule_endpoint(payload: ValidateSnortRulePayload):
    """Validate a Snort rule string according to F5 WAF syntax specification."""
    is_valid, errors, warnings, parsed_info = validate_snort_rule(payload.rule)
    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "parsed": parsed_info,
    }


@router.post("/custom-signatures/test-snort-rule")
def test_snort_rule_endpoint(payload: TestSnortRulePayload):
    """Test a Snort rule against a simulated HTTP request context."""
    return evaluate_snort_rule(payload.rule, payload.context)

