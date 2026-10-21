"""
FastAPI REST API routes for ClickHouse Security Event Violation Browsing,
3-Table Correlation (by support_id), and WAF Policy Signature Fine-Tuning.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..storage.clickhouse_service import (
    get_clickhouse_service,
    V4_SECURITY_EVENTS_SCHEMA,
    V4_VIOLATION_DATA_SCHEMA,
    V4_SIGNATURES_DATA_SCHEMA,
    V4_SECURITY_EVENTS_COLUMNS,
    V4_VIOLATION_DATA_COLUMNS,
    V4_SIGNATURES_DATA_COLUMNS,
    SUPPORTED_FILTER_OPERATORS,
)

router = APIRouter(prefix="/api/clickhouse", tags=["ClickHouse Violations & Policy Tuning"])


class ClickHouseConfigRequest(BaseModel):
    host: str = Field(..., description="ClickHouse IP address or hostname (running in NGINX Instance Manager)")
    port: int = Field(default=8123, description="ClickHouse HTTP/HTTPS port (default 8123 or 8443)")
    username: str = Field(default="default", description="ClickHouse username")
    password: Optional[str] = Field(default="", description="ClickHouse password")
    database: str = Field(default="nms", description="ClickHouse database name (e.g. nms or default)")
    ssl: bool = Field(default=False, description="Use HTTPS for ClickHouse connection")
    verify_ssl: bool = Field(default=True, description="Verify TLS certificate when SSL is enabled")
    test_on_save: bool = Field(default=True, description="Test connection immediately after saving")


class ClickHouseTestRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None
    ssl: Optional[bool] = None
    verify_ssl: Optional[bool] = None


class FieldFilterItem(BaseModel):
    field: Optional[str] = Field(default=None, description="Column name from v4_security_events")
    column: Optional[str] = Field(default=None, description="Column name alias from v4_security_events")
    operator: str = Field(default="contains", description="Comparison operator")
    value: Optional[Any] = Field(default="", description="Filter value")


class SecurityEventsSearchRequest(BaseModel):
    global_search: Optional[str] = Field(default=None, description="Search string across all 53 columns of v4_security_events")
    field_filters: List[FieldFilterItem] = Field(default_factory=list, description="Per-column filter clauses across any of the 53 columns")
    filters: List[FieldFilterItem] = Field(default_factory=list, description="Per-column filter clauses alias")
    exact_columns: Dict[str, Any] = Field(default_factory=dict, description="Quick column filters")
    start_time: Optional[str] = Field(default=None, description="Minimum timestamp filter")
    end_time: Optional[str] = Field(default=None, description="Maximum timestamp filter")
    sort_by: str = Field(default="timestamp", description="Column to sort by")
    sort_order: Optional[str] = Field(default=None, description="Sort direction: ASC or DESC")
    sort_dir: Optional[str] = Field(default=None, description="Sort direction alias: ASC or DESC")
    limit: int = Field(default=50, ge=1, le=500, description="Maximum rows to return")
    offset: int = Field(default=0, ge=0, description="Pagination row offset")
    include_correlations: bool = Field(default=False, description="Also batch-correlate the 3 tables by support_id for returned events")


class BatchCorrelateRequest(BaseModel):
    support_ids: List[str] = Field(..., description="List of support_id values to correlate across the 3 tables")
    target_policy_name: Optional[str] = Field(default=None, description="Optional WAF policy name to check signature states against")


class TuneSignatureRequest(BaseModel):
    policy_name: str = Field(..., description="Target WAF policy name in F5 WAF Policy Manager")
    signature_id: Any = Field(..., description="Attack signature_id from v4_security_events_signatures_data")
    enabled: Optional[bool] = Field(default=None, description="True to enable (tighten), False to disable (relax), None to remove override")
    signature_name: Optional[str] = Field(default=None, description="Human-readable signature_name from ClickHouse")
    support_id: Optional[str] = Field(default=None, description="Correlated support_id for audit trail in policy tag")
    tag: Optional[str] = Field(default=None, description="Optional custom tag/comment for the signature override")
    action: str = Field(default="set", description="'set' to enable/disable or 'remove' to revert to default")


class BulkTuneSignaturesRequest(BaseModel):
    policy_name: str = Field(..., description="Target WAF policy name in F5 WAF Policy Manager")
    signatures: List[Dict[str, Any]] = Field(..., description="List of signature tuning actions")
    support_id: Optional[str] = Field(default=None, description="Optional support_id for audit trail")


class SavePolicyToRedisRequest(BaseModel):
    policy_name: str = Field(..., description="Target WAF policy name in F5 WAF Policy Manager")
    signatures: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional list of signature overrides to apply before saving to Redis")
    support_id: Optional[str] = Field(default=None, description="Optional support_id for audit trail")


@router.get("/schema")
async def get_clickhouse_schema():
    """Return full schema metadata for the 3 correlated ClickHouse tables and filter operators."""
    return {
        "common_key": "support_id",
        "correlation_key": "support_id",
        "tables": {
            "v4_security_events": {
                "name": "v4_security_events",
                "description": "Primary security event log table (all 53 fields searchable)",
                "column_count": len(V4_SECURITY_EVENTS_SCHEMA),
                "columns": V4_SECURITY_EVENTS_SCHEMA,
                "column_names": V4_SECURITY_EVENTS_COLUMNS,
            },
            "v4_security_events_violation_data": {
                "name": "v4_security_events_violation_data",
                "description": "Per-violation breakdown table correlated by support_id",
                "column_count": len(V4_VIOLATION_DATA_SCHEMA),
                "columns": V4_VIOLATION_DATA_SCHEMA,
                "column_names": V4_VIOLATION_DATA_COLUMNS,
            },
            "v4_security_events_signatures_data": {
                "name": "v4_security_events_signatures_data",
                "description": "Per-signature match breakdown table correlated by support_id (contains signature_id for policy fine-tuning)",
                "column_count": len(V4_SIGNATURES_DATA_SCHEMA),
                "columns": V4_SIGNATURES_DATA_SCHEMA,
                "column_names": V4_SIGNATURES_DATA_COLUMNS,
            },
        },
        "operators": SUPPORTED_FILTER_OPERATORS,
    }


@router.get("/status")
async def get_clickhouse_status(
    live: bool = Query(default=False, description="Perform live connectivity check"),
    ping: bool = Query(default=False, description="Perform live connectivity check alias"),
):
    """Get current ClickHouse configuration, Redis persistence status, and connection health."""
    svc = get_clickhouse_service()
    return svc.get_status(check_live=bool(live or ping))


@router.post("/config")
@router.put("/config")
async def configure_clickhouse(payload: ClickHouseConfigRequest):
    """
    Save ClickHouse connection parameters (IP/host, port, username, password, database, SSL)
    and persist them in Redis so they survive application/container reboots.
    """
    svc = get_clickhouse_service()
    saved_cfg = svc.save_config(
        {
            "host": payload.host,
            "port": payload.port,
            "username": payload.username,
            "password": payload.password,
            "database": payload.database,
            "ssl": payload.ssl,
            "verify_ssl": payload.verify_ssl,
        },
        persist_to_redis=True,
    )
    status = svc.test_connection() if payload.test_on_save else svc.get_status(check_live=False)
    return {
        "saved": True,
        "configured": status.get("configured", True),
        "connected": status.get("connected", False),
        "version": status.get("version", ""),
        "error": status.get("error"),
        "tables": status.get("tables", {}),
        "persisted_in_redis": saved_cfg.get("persisted_in_redis", False),
        "config": saved_cfg,
        "connection": status,
    }


@router.post("/test")
async def test_clickhouse_connection(payload: ClickHouseTestRequest):
    """Test connectivity to ClickHouse using either provided parameters or saved configuration."""
    svc = get_clickhouse_service()
    override = {k: v for k, v in payload.model_dump().items() if v is not None}
    return svc.test_connection(override_config=override if override else None)


@router.post("/events/search")
async def search_clickhouse_security_events(payload: SecurityEventsSearchRequest):
    """
    Search and filter WAF security violation logs across all 53 fields of v4_security_events.
    """
    svc = get_clickhouse_service()
    try:
        combined_filters = list(payload.field_filters) + list(payload.filters)
        filters_dicts = [
            {
                "field": f.field or f.column or "",
                "operator": f.operator,
                "value": f.value,
            }
            for f in combined_filters
        ]
        effective_sort_order = payload.sort_order or payload.sort_dir or "DESC"
        return svc.search_security_events(
            global_search=payload.global_search,
            field_filters=filters_dicts,
            exact_columns=payload.exact_columns,
            start_time=payload.start_time,
            end_time=payload.end_time,
            sort_by=payload.sort_by,
            sort_order=effective_sort_order,
            limit=payload.limit,
            offset=payload.offset,
            include_correlations=payload.include_correlations,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/events/{support_id}/correlate")
async def correlate_event_by_support_id(
    support_id: str,
    policy_name: Optional[str] = Query(default=None, description="Target WAF policy name to check signature states"),
):
    """
    Correlate v4_security_events, v4_security_events_violation_data, and
    v4_security_events_signatures_data by support_id.
    """
    svc = get_clickhouse_service()
    try:
        return svc.get_correlated_event(support_id=support_id, target_policy_name=policy_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/events/correlate-batch")
async def correlate_events_batch(payload: BatchCorrelateRequest):
    """Batch correlate multiple support_ids across the 3 ClickHouse tables."""
    svc = get_clickhouse_service()
    try:
        correlations = svc.batch_correlate_events(
            support_ids=payload.support_ids,
            target_policy_name=payload.target_policy_name,
        )
        return {"correlations": correlations}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/policy/{policy_name}/signature-states")
async def get_policy_signature_states_endpoint(
    policy_name: str,
    signature_ids: Optional[str] = Query(default=None, description="Comma-separated signature IDs to check"),
):
    """Return all signature override states (enabled/disabled) for a given WAF policy."""
    svc = get_clickhouse_service()
    matched = svc._find_matching_policy_name(policy_name)
    req_ids = [s.strip() for s in signature_ids.split(",") if s.strip()] if signature_ids else None
    states = svc.get_policy_signature_states(policy_name, requested_signature_ids=req_ids)
    return {
        "requested_policy": policy_name,
        "matched_policy": matched,
        "found": matched is not None,
        "states": states,
        "signature_states": states,
    }


@router.post("/policy/tune-signature")
async def tune_policy_signature_endpoint(payload: TuneSignatureRequest):
    """
    Enable, disable, or reset a signature_id (from v4_security_events_signatures_data)
    in the specified WAF policy.
    """
    svc = get_clickhouse_service()
    try:
        return svc.tune_policy_signature(
            policy_name=payload.policy_name,
            signature_id=payload.signature_id,
            enabled=payload.enabled,
            signature_name=payload.signature_name,
            support_id=payload.support_id,
            tag=payload.tag,
            action=payload.action,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policy/tune-signatures-bulk")
async def bulk_tune_policy_signatures_endpoint(payload: BulkTuneSignaturesRequest):
    """
    Bulk enable, disable, or reset multiple signature_ids in the specified WAF policy.
    """
    svc = get_clickhouse_service()
    try:
        return svc.bulk_tune_policy_signatures(
            policy_name=payload.policy_name,
            signatures=payload.signatures,
            support_id=payload.support_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policy/save-to-redis")
async def save_tuned_policy_to_redis_endpoint(payload: SavePolicyToRedisRequest):
    """
    Explicitly save the fine-tuned WAF policy to Redis (and mark it as modified / uncommitted)
    so it can be committed to GitHub from the WAF Policies page.
    """
    svc = get_clickhouse_service()
    try:
        return svc.save_tuned_policy_to_redis(
            policy_name=payload.policy_name,
            signatures=payload.signatures,
            support_id=payload.support_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policy/{policy_name}/save-to-redis")
async def save_tuned_policy_by_name_to_redis_endpoint(policy_name: str):
    """
    Explicitly save the named WAF policy to Redis (and mark it as modified / uncommitted)
    so it can be committed to GitHub from the WAF Policies page.
    """
    svc = get_clickhouse_service()
    try:
        return svc.save_tuned_policy_to_redis(policy_name=policy_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
