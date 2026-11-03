"""
NGINX One Console Security Events & WAF Policy Fine-Tuning Service.

Provides:
1. Runtime-configurable NGINX One Console REST API connection settings
   (tenant_cname / base_url, namespace, api_token, verify_ssl)
   with automatic persistence in Redis under `__nginx_one__:config` so
   credentials survive container restarts.
2. Querying WAF security violation events via the official NGINX One Console REST API:
   - `listSecurityEvents`:
     `GET https://{tenant_cname}.console.ves.volterra.io/api/nginx/one/namespaces/{namespace}/app-protect/events`
   - `getSecurityEvent`:
     `GET https://{tenant_cname}.console.ves.volterra.io/api/nginx/one/namespaces/{namespace}/app-protect/events/{id}`
3. Event correlation by `support_id` that normalizes the `SecurityEvent` payload
   (`http`, `signatures`, `violations`, `request`, `threat_campaign_names`, etc.)
   into the unified 3-tab correlation inspector structure (`security_events`,
   `violation_data`, `signatures_data`, `unique_signatures`, `policy_signature_states`).
4. Direct WAF policy fine-tuning: enable, disable, or reset specific `signature_id`
   entries inside a target WAF policy stored in Redis/GitHub/Memory based on
   correlated NGINX One Console violation events.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx

from ..config import settings
from .clickhouse_service import (
    SUPPORTED_FILTER_OPERATORS,
    V4_SECURITY_EVENTS_COLUMNS,
    V4_SECURITY_EVENTS_SCHEMA,
    V4_SIGNATURES_DATA_COLUMNS,
    V4_SIGNATURES_DATA_SCHEMA,
    V4_VIOLATION_DATA_COLUMNS,
    V4_VIOLATION_DATA_SCHEMA,
    get_clickhouse_service,
)

# Reserved Redis key used to persist NGINX One Console connection settings across restarts
NGINX_ONE_CONFIG_REDIS_KEY = "__nginx_one__:config"
REDIS_NGINX_ONE_CONFIG_KEY = NGINX_ONE_CONFIG_REDIS_KEY
NGINX_ONE_SUPPORTED_OPERATORS = SUPPORTED_FILTER_OPERATORS

# Official AnalyticsFilterField enum values from the NGINX One Console OpenAPI specification
NGINX_ONE_ANALYTICS_FILTER_FIELDS: List[Dict[str, str]] = [
    {"name": "support_id", "type": "String", "category": "Identity", "description": "Unique support ID of the security event"},
    {"name": "policy", "type": "String", "category": "WAF Policy", "description": "Name of the App Protect policy"},
    {"name": "request_status", "type": "String", "category": "Enforcement", "description": "Request status (blocked, alerted, passed)"},
    {"name": "request_outcome", "type": "String", "category": "Enforcement", "description": "Outcome of the request (passed, rejected)"},
    {"name": "request_outcome_reason", "type": "String", "category": "Enforcement", "description": "Reason for the request outcome"},
    {"name": "violation_rating", "type": "UInt8", "category": "Violations", "description": "Violation rating score (0-5)"},
    {"name": "ip", "type": "String", "category": "HTTP", "description": "Client IP address (client_ip / remote_addr)"},
    {"name": "country", "type": "String", "category": "Geo", "description": "Two-letter ISO 3166-1 alpha-2 country code"},
    {"name": "url", "type": "String", "category": "HTTP", "description": "Requested URL / URI path"},
    {"name": "request_method", "type": "String", "category": "HTTP", "description": "HTTP request method (GET, POST, etc.)"},
    {"name": "response_code", "type": "UInt16", "category": "HTTP", "description": "HTTP response status code"},
    {"name": "request_host", "type": "String", "category": "HTTP", "description": "HTTP Host header / target hostname"},
    {"name": "hostname", "type": "String", "category": "System", "description": "NGINX instance hostname"},
    {"name": "instance_object_id", "type": "String", "category": "System", "description": "UUID of the NGINX instance in NGINX One"},
    {"name": "csg_object_id", "type": "String", "category": "System", "description": "UUID of the Config Sync Group (CSG) in NGINX One"},
    {"name": "signature_id", "type": "String", "category": "Signatures", "description": "Triggered attack signature ID"},
    {"name": "signature_name", "type": "String", "category": "Signatures", "description": "Triggered attack signature name"},
    {"name": "accuracy", "type": "String", "category": "Signatures", "description": "Signature accuracy level (high, medium, low)"},
    {"name": "risk", "type": "String", "category": "Signatures", "description": "Signature risk level (high, medium, low)"},
    {"name": "cve", "type": "String", "category": "Signatures", "description": "Common Vulnerabilities and Exposures (CVE) identifier"},
    {"name": "violation", "type": "String", "category": "Violations", "description": "Violation name"},
    {"name": "sub_violation", "type": "String", "category": "Violations", "description": "Sub-violation name"},
    {"name": "context", "type": "String", "category": "Violations", "description": "Violation context (url, header, parameter, cookie, request)"},
    {"name": "context_key", "type": "String", "category": "Violations", "description": "Violation field / context key name"},
    {"name": "context_value", "type": "String", "category": "Violations", "description": "Violation field / context value"},
    {"name": "threat_campaign", "type": "String", "category": "Threat Intelligence", "description": "Threat campaign name"},
]

NGINX_ONE_VALID_FILTER_FIELD_NAMES = {f["name"] for f in NGINX_ONE_ANALYTICS_FILTER_FIELDS}

# Columns returned by listSecurityEvents (plus normalized aliases for table compatibility)
NGINX_ONE_EVENTS_LIST_COLUMNS: List[Dict[str, str]] = [
    {"name": "timestamp", "type": "DateTime64", "category": "Identity", "description": "Timestamp of the security event (ISO 8601)"},
    {"name": "support_id", "type": "String", "category": "Identity", "description": "Unique support ID of the security event"},
    {"name": "request_status", "type": "String", "category": "Enforcement", "description": "Status of the request (blocked, alerted, passed)"},
    {"name": "policy_name", "type": "String", "category": "WAF Policy", "description": "Name of the App Protect policy"},
    {"name": "violation_rating", "type": "UInt8", "category": "Violations", "description": "Violation rating score (0-5)"},
    {"name": "http__request_method", "type": "String", "category": "HTTP", "description": "HTTP request method (request_method)"},
    {"name": "http__uri", "type": "String", "category": "HTTP", "description": "Requested URL / URI (url)"},
    {"name": "http__remote_addr", "type": "String", "category": "HTTP", "description": "Client IP address (client_ip)"},
    {"name": "http__response_code", "type": "UInt16", "category": "HTTP", "description": "HTTP response status code (response_code)"},
    {"name": "country_code", "type": "String", "category": "Geo", "description": "Two-letter ISO 3166-1 alpha-2 country code"},
    {"name": "instance_object_id", "type": "String", "category": "System", "description": "UUID of the NGINX instance"},
    {"name": "csg_object_id", "type": "String", "category": "System", "description": "UUID of the Config Sync Group"},
    {"name": "client_ip", "type": "String", "category": "HTTP", "description": "Client IP address (NGINX One Console field)"},
    {"name": "url", "type": "String", "category": "HTTP", "description": "Requested URL (NGINX One Console field)"},
    {"name": "request_method", "type": "String", "category": "HTTP", "description": "HTTP request method (NGINX One Console field)"},
    {"name": "response_code", "type": "UInt16", "category": "HTTP", "description": "HTTP response code (NGINX One Console field)"},
]

# Mapping from UI / ClickHouse column names or aliases to NGINX One AnalyticsFilterField
COLUMN_TO_NGINX_ONE_FILTER_FIELD: Dict[str, str] = {
    "support_id": "support_id",
    "policy_name": "policy",
    "policy": "policy",
    "request_status": "request_status",
    "request_outcome": "request_outcome",
    "request_outcome_reason": "request_outcome_reason",
    "violation_rating": "violation_rating",
    "http__remote_addr": "ip",
    "client_ip": "ip",
    "ip": "ip",
    "country_code": "country",
    "country": "country",
    "http__uri": "url",
    "url": "url",
    "http__request_method": "request_method",
    "request_method": "request_method",
    "method": "request_method",
    "http__response_code": "response_code",
    "response_code": "response_code",
    "http__hostname": "request_host",
    "request_host": "request_host",
    "parent_hostname": "hostname",
    "host_display_name": "hostname",
    "hostname": "hostname",
    "instance_object_id": "instance_object_id",
    "system_id": "instance_object_id",
    "csg_object_id": "csg_object_id",
    "threat_campaign_names": "threat_campaign",
    "threat_campaign": "threat_campaign",
    "signature_ids": "signature_id",
    "signature_id": "signature_id",
    "signature_names": "signature_name",
    "signature_name": "signature_name",
    "signature_accuracy": "accuracy",
    "accuracy": "accuracy",
    "signature_risk": "risk",
    "risk": "risk",
    "cve": "cve",
    "signature_cve": "cve",
    "violations": "violation",
    "violation_name": "violation",
    "violation": "violation",
    "sub_violations": "sub_violation",
    "sub_violation": "sub_violation",
    "violation_context": "context",
    "violation_contexts": "context",
    "context": "context",
    "field_name": "context_key",
    "field_names": "context_key",
    "context_key": "context_key",
    "field_value": "context_value",
    "field_values": "context_value",
    "context_value": "context_value",
}

NGINX_ONE_SERVER_FILTER_FIELDS = NGINX_ONE_VALID_FILTER_FIELD_NAMES | set(
    COLUMN_TO_NGINX_ONE_FILTER_FIELD.keys()
)

# Combined schema for NGINX One Console security events (listSecurityEvents + ClickHouse-compatible columns)
_seen_schema_cols = {c["name"] for c in NGINX_ONE_EVENTS_LIST_COLUMNS}
NGINX_ONE_SECURITY_EVENTS_SCHEMA: List[Dict[str, str]] = list(NGINX_ONE_EVENTS_LIST_COLUMNS)
for _col in V4_SECURITY_EVENTS_SCHEMA:
    if _col["name"] not in _seen_schema_cols:
        NGINX_ONE_SECURITY_EVENTS_SCHEMA.append(_col)
        _seen_schema_cols.add(_col["name"])

NGINX_ONE_SECURITY_EVENTS_COLUMNS: List[str] = [
    c["name"] for c in NGINX_ONE_SECURITY_EVENTS_SCHEMA
]


def _normalize_tenant_and_base_url(
    tenant_cname: Optional[str],
    base_url: Optional[str],
) -> Tuple[str, str]:
    """
    Normalize tenant_cname and base_url into:
      (clean_tenant_cname, clean_base_url)
    where clean_base_url is e.g. 'https://{tenant_cname}.console.ves.volterra.io'
    without any trailing slash or '/api/nginx/one...' path suffix.
    """
    raw_tenant = (tenant_cname or "").strip()
    raw_base = (base_url or "").strip()

    # If user pasted a full URL into tenant_cname, treat it as base_url as well
    if raw_tenant and (raw_tenant.startswith("http://") or raw_tenant.startswith("https://") or "/" in raw_tenant):
        if not raw_base:
            raw_base = raw_tenant
        # Extract hostname part
        m = re.match(r"^https?://([^/]+)", raw_tenant, flags=re.IGNORECASE)
        host_part = m.group(1) if m else raw_tenant.split("/")[0]
        if host_part.endswith(".console.ves.volterra.io"):
            raw_tenant = host_part[: -len(".console.ves.volterra.io")]
        else:
            raw_tenant = host_part
    elif raw_tenant.endswith(".console.ves.volterra.io"):
        raw_tenant = raw_tenant[: -len(".console.ves.volterra.io")]

    if raw_base:
        if not raw_base.startswith("http://") and not raw_base.startswith("https://"):
            raw_base = f"https://{raw_base}"
        # Strip any /api/nginx/one... suffix if user pasted the full endpoint URL
        raw_base = re.sub(r"/api/nginx/one.*$", "", raw_base, flags=re.IGNORECASE)
        raw_base = raw_base.rstrip("/")
        if not raw_tenant:
            m = re.match(r"^https?://([^/]+)", raw_base, flags=re.IGNORECASE)
            if m:
                host_part = m.group(1)
                if host_part.endswith(".console.ves.volterra.io"):
                    raw_tenant = host_part[: -len(".console.ves.volterra.io")]
                else:
                    raw_tenant = host_part
    elif raw_tenant:
        raw_base = f"https://{raw_tenant}.console.ves.volterra.io"

    return raw_tenant, raw_base


class NginxOneConsoleService:
    """Client and WAF policy tuning coordinator for NGINX One Console security events REST API."""

    def __init__(self) -> None:
        tenant, base_url = _normalize_tenant_and_base_url(
            settings.nginx_one_tenant_cname,
            settings.nginx_one_base_url,
        )
        self.tenant_cname: str = tenant
        self.base_url: str = base_url
        self.namespace: str = (settings.nginx_one_namespace or "default").strip() or "default"
        self.api_token: str = (settings.nginx_one_api_token or "").strip()
        self.verify_ssl: bool = settings.nginx_one_verify_ssl
        self._loaded_from_redis: bool = False
        self._persisted_in_redis: bool = False

    # ------------------------------------------------------------------
    # Configuration & Redis Persistence
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        return bool((self.base_url or self.tenant_cname) and self.api_token)

    def get_resolved_base_url(
        self,
        tenant_cname: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        t = tenant_cname if tenant_cname is not None else self.tenant_cname
        if base_url is not None:
            b = base_url
        elif tenant_cname is not None:
            b = ""
        else:
            b = self.base_url
        _, resolved_base = _normalize_tenant_and_base_url(t, b)
        return resolved_base

    def get_events_endpoint_url(
        self,
        support_id: Optional[str] = None,
        tenant_cname: Optional[str] = None,
        base_url: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> str:
        resolved_base = self.get_resolved_base_url(tenant_cname=tenant_cname, base_url=base_url)
        ns = (namespace if namespace is not None else self.namespace).strip() or "default"
        url = f"{resolved_base}/api/nginx/one/namespaces/{ns}/app-protect/events"
        if support_id is not None and str(support_id).strip():
            url = f"{url}/{str(support_id).strip()}"
        return url

    def _events_endpoint_url(
        self,
        tenant_cname: Optional[str] = None,
        base_url: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> str:
        return self.get_events_endpoint_url(
            tenant_cname=tenant_cname,
            base_url=base_url,
            namespace=namespace,
        )

    def _event_detail_endpoint_url(
        self,
        support_id: str,
        tenant_cname: Optional[str] = None,
        base_url: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> str:
        return self.get_events_endpoint_url(
            support_id=support_id,
            tenant_cname=tenant_cname,
            base_url=base_url,
            namespace=namespace,
        )

    def _build_headers(self, api_token: Optional[str] = None) -> Dict[str, str]:
        token = (api_token if api_token is not None else self.api_token or "").strip()
        headers: Dict[str, str] = {
            "Accept": "application/json",
        }
        if token:
            lower = token.lower()
            if lower.startswith("bearer ") or lower.startswith("apitoken "):
                headers["Authorization"] = token
            else:
                headers["Authorization"] = f"APIToken {token}"
        return headers

    def get_config(self, include_secret: bool = False) -> Dict[str, Any]:
        """Return the current NGINX One Console configuration."""
        persisted = self._persisted_in_redis or self._is_persisted_in_redis()
        cfg: Dict[str, Any] = {
            "configured": self.is_configured(),
            "tenant_cname": self.tenant_cname,
            "base_url": self.get_resolved_base_url(),
            "namespace": self.namespace,
            "verify_ssl": self.verify_ssl,
            "has_token": bool(self.api_token),
            "has_api_token": bool(self.api_token),
            "persisted_in_redis": persisted,
            "endpoints": {
                "listSecurityEvents": self.get_events_endpoint_url() if (self.base_url or self.tenant_cname) else "",
                "getSecurityEvent": (
                    f"{self.get_events_endpoint_url()}/{{id}}"
                    if (self.base_url or self.tenant_cname)
                    else ""
                ),
            },
        }
        if include_secret:
            cfg["api_token"] = self.api_token
        return cfg

    def get_public_config(self) -> Dict[str, Any]:
        """Return current NGINX One Console configuration with masked API token for UI display."""
        return self.get_config(include_secret=False)

    def get_status(self, check_live: bool = False) -> Dict[str, Any]:
        """Return current configuration and optional live connectivity check."""
        if not self._loaded_from_redis and not self.is_configured():
            self.load_config_from_redis()
        if check_live and self.is_configured():
            return self.test_connection()
        cfg = self.get_public_config()
        return {
            **cfg,
            "connected": self.is_configured(),
            "error": None if self.is_configured() else "NGINX One Console is not configured.",
            "config": cfg,
        }

    def _get_redis_client_and_prefix(self) -> Tuple[Optional[Any], str]:
        """Return an active Redis client and key prefix if Redis is available."""
        from ..storage import _local_storage
        from .redis_backend import RedisPolicyStorage

        prefix = settings.redis_key_prefix or ""
        try:
            if _local_storage is not None:
                if isinstance(_local_storage, RedisPolicyStorage) and _local_storage.client is not None:
                    _local_storage.client.ping()
                    return _local_storage.client, (_local_storage.key_prefix or prefix)
                return None, prefix
        except Exception:
            return None, prefix

        try:
            import redis

            client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password,
                ssl=settings.redis_ssl,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            client.ping()
            return client, prefix
        except Exception:
            return None, prefix

    def _redis_key(self, prefix: str = "") -> str:
        return f"{prefix}{NGINX_ONE_CONFIG_REDIS_KEY}"

    def _is_persisted_in_redis(self) -> bool:
        client, prefix = self._get_redis_client_and_prefix()
        if client is None:
            return False
        try:
            key = self._redis_key(prefix)
            if hasattr(client, "exists"):
                return bool(client.exists(key))
            return bool(client.get(key))
        except Exception:
            return False

    def load_config_from_redis(self) -> bool:
        """Load persisted NGINX One Console connection settings from Redis if present."""
        client, prefix = self._get_redis_client_and_prefix()
        if client is None:
            return False
        try:
            key = self._redis_key(prefix)
            raw = client.get(key)
            if not raw:
                return False
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False

            tenant, base_url = _normalize_tenant_and_base_url(
                data.get("tenant_cname"),
                data.get("base_url"),
            )
            if tenant or base_url:
                self.tenant_cname = tenant
                self.base_url = base_url
            if data.get("namespace"):
                self.namespace = str(data["namespace"]).strip() or "default"
            if "api_token" in data and data["api_token"] is not None:
                self.api_token = str(data["api_token"]).strip()
            if "verify_ssl" in data:
                self.verify_ssl = bool(data["verify_ssl"])

            self._loaded_from_redis = True
            self._persisted_in_redis = True
            return True
        except Exception:
            return False

    def save_config(
        self,
        tenant_cname: Optional[Any] = None,
        base_url: Optional[str] = None,
        namespace: str = "default",
        api_token: Optional[str] = None,
        verify_ssl: bool = True,
        persist_to_redis: bool = True,
    ) -> Dict[str, Any]:
        """Update NGINX One Console runtime config (accepts dict or kwargs) and persist it to Redis."""
        if isinstance(tenant_cname, dict):
            cfg_dict = tenant_cname
            raw_tenant = cfg_dict.get("tenant_cname", self.tenant_cname)
            if "base_url" in cfg_dict:
                raw_base = cfg_dict.get("base_url")
            elif "tenant_cname" in cfg_dict:
                raw_base = ""
            else:
                raw_base = self.base_url
            raw_ns = cfg_dict.get("namespace", self.namespace)
            raw_token = cfg_dict.get("api_token")
            raw_verify = cfg_dict.get("verify_ssl", self.verify_ssl)
        else:
            raw_tenant = tenant_cname
            raw_base = base_url
            raw_ns = namespace
            raw_token = api_token
            raw_verify = verify_ssl

        clean_tenant, clean_base = _normalize_tenant_and_base_url(raw_tenant, raw_base)
        self.tenant_cname = clean_tenant
        self.base_url = clean_base
        self.namespace = (str(raw_ns or "default")).strip() or "default"
        # Preserve existing token if api_token is None, empty, or masked when already configured
        if raw_token is not None and str(raw_token).strip() not in ("", "********"):
            self.api_token = str(raw_token).strip()
        elif raw_token == "" and not self.api_token:
            self.api_token = ""
        self.verify_ssl = bool(raw_verify) if raw_verify is not None else True

        # Keep global settings in sync
        settings.nginx_one_tenant_cname = self.tenant_cname
        settings.nginx_one_base_url = self.base_url
        settings.nginx_one_namespace = self.namespace
        settings.nginx_one_api_token = self.api_token
        settings.nginx_one_verify_ssl = self.verify_ssl

        persisted = False
        if persist_to_redis:
            client, prefix = self._get_redis_client_and_prefix()
            if client is not None:
                try:
                    key = self._redis_key(prefix)
                    payload = {
                        "tenant_cname": self.tenant_cname,
                        "base_url": self.base_url,
                        "namespace": self.namespace,
                        "api_token": self.api_token,
                        "verify_ssl": self.verify_ssl,
                    }
                    client.set(key, json.dumps(payload, ensure_ascii=False))
                    persisted = True
                except Exception:
                    persisted = False

        self._persisted_in_redis = persisted
        res = self.get_public_config()
        res["persisted_in_redis"] = persisted or self._is_persisted_in_redis()
        return res

    # ------------------------------------------------------------------
    # REST API Client Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_query_params_tuples(params: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Convert query parameters dict (supporting list values for filter_fields,
        filter_values, filter_ops) into a list of (key, value) tuples for httpx.
        """
        tuples: List[Tuple[str, str]] = []
        for k, v in params.items():
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                for item in v:
                    if item is not None:
                        tuples.append((k, str(item)))
            elif isinstance(v, bool):
                tuples.append((k, "true" if v else "false"))
            else:
                tuples.append((k, str(v)))
        return tuples

    def _request_json(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        api_token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: float = 15.0,
    ) -> Dict[str, Any]:
        """Execute an HTTP request against the NGINX One Console REST API and return parsed JSON."""
        headers = self._build_headers(api_token=api_token)
        verify = self.verify_ssl if verify_ssl is None else bool(verify_ssl)
        query_tuples = self._build_query_params_tuples(params or {})

        with httpx.Client(verify=verify, timeout=timeout) as client:
            resp = client.request(
                method=method,
                url=url,
                params=query_tuples if query_tuples else None,
                headers=headers,
            )
            if resp.status_code >= 400:
                body_preview = resp.text.strip()[:500]
                try:
                    err_json = resp.json()
                    if isinstance(err_json, dict):
                        msg = (
                            err_json.get("message")
                            or err_json.get("detail")
                            or err_json.get("error")
                            or body_preview
                        )
                        body_preview = str(msg)
                except Exception:
                    pass
                raise RuntimeError(
                    f"NGINX One Console API HTTP {resp.status_code}: {body_preview or resp.reason_phrase}"
                )
            if not resp.text.strip():
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {"items": data}

    def test_connection(
        self,
        override_config: Optional[Dict[str, Any]] = None,
        tenant_cname: Optional[str] = None,
        base_url: Optional[str] = None,
        namespace: Optional[str] = None,
        api_token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Test connectivity to NGINX One Console by calling `listSecurityEvents`
        with `paginated=true`, `offset=1`, `limit=1`.
        """
        if not self._loaded_from_redis and not self.is_configured():
            self.load_config_from_redis()

        if isinstance(override_config, dict):
            tenant_cname = override_config.get("tenant_cname", tenant_cname)
            base_url = override_config.get("base_url", base_url)
            namespace = override_config.get("namespace", namespace)
            api_token = override_config.get("api_token", api_token)
            verify_ssl = override_config.get("verify_ssl", verify_ssl)

        eff_tenant = tenant_cname if tenant_cname is not None else self.tenant_cname
        eff_base = base_url if base_url is not None else self.base_url
        eff_ns = (namespace if namespace is not None else self.namespace).strip() or "default"
        eff_token = (
            api_token.strip()
            if (api_token is not None and api_token not in ("", "********"))
            else self.api_token
        )
        eff_verify = self.verify_ssl if verify_ssl is None else bool(verify_ssl)

        norm_tenant, norm_base = _normalize_tenant_and_base_url(eff_tenant, eff_base)
        if not norm_base:
            return {
                "connected": False,
                "configured": False,
                "error": "NGINX One Console Tenant CNAME or Base URL is not configured.",
                "config": self.get_public_config(),
            }
        if not eff_token:
            return {
                "connected": False,
                "configured": False,
                "error": "NGINX One Console API Token is required.",
                "config": self.get_public_config(),
            }

        endpoint_url = self.get_events_endpoint_url(
            tenant_cname=norm_tenant,
            base_url=norm_base,
            namespace=eff_ns,
        )
        try:
            data = self._request_json(
                "GET",
                endpoint_url,
                params={"paginated": True, "offset": 1, "limit": 1},
            )
            total = int(data.get("total", len(data.get("items") or [])) or 0)
            return {
                "connected": True,
                "configured": True,
                "tenant_cname": norm_tenant,
                "base_url": norm_base,
                "namespace": eff_ns,
                "endpoint": endpoint_url,
                "endpoints": {
                    "listSecurityEvents": endpoint_url,
                    "getSecurityEvent": f"{endpoint_url}/{{id}}",
                },
                "total_events": total,
                "error": None,
                "config": self.get_public_config(),
            }
        except Exception as exc:
            return {
                "connected": False,
                "configured": True,
                "tenant_cname": norm_tenant,
                "base_url": norm_base,
                "namespace": eff_ns,
                "endpoint": endpoint_url,
                "endpoints": {
                    "listSecurityEvents": endpoint_url,
                    "getSecurityEvent": f"{endpoint_url}/{{id}}",
                },
                "total_events": 0,
                "error": str(exc),
                "config": self.get_public_config(),
            }

    # ------------------------------------------------------------------
    # Normalization & Schema Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_severity_from_rating(rating: Any, request_status: str = "") -> str:
        """Map violation_rating (0-5) or request_status to a human-readable severity string."""
        try:
            r = int(rating)
        except Exception:
            r = -1
        if r >= 5:
            return "critical"
        if r == 4:
            return "error"
        if r == 3:
            return "warning"
        if r in (1, 2):
            return "notice"
        if r == 0:
            return "informational"
        status_lower = (request_status or "").lower()
        if status_lower == "blocked":
            return "error"
        if status_lower == "alerted":
            return "warning"
        return "notice"

    @classmethod
    def normalize_event_list_item(cls, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a `SecurityEventListItem` returned by `listSecurityEvents`
        so it exposes both the native NGINX One Console properties AND the
        ClickHouse `v4_security_events` column names used by the UI table.
        """
        support_id = str(item.get("support_id") or item.get("id") or "").strip()
        timestamp = str(item.get("timestamp") or "")
        policy_name = str(item.get("policy_name") or item.get("policy") or "N/A")
        request_status = str(item.get("request_status") or "")
        client_ip = str(
            item.get("client_ip")
            or item.get("http_remote_addr")
            or item.get("http__remote_addr")
            or (item.get("http") or {}).get("remote_addr")
            or ""
        )
        url = str(
            item.get("url")
            or item.get("http_uri")
            or item.get("http__uri")
            or (item.get("http") or {}).get("uri")
            or ""
        )
        request_method = str(
            item.get("request_method")
            or item.get("method")
            or item.get("http_request_method")
            or item.get("http__request_method")
            or (item.get("http") or {}).get("request_method")
            or ""
        )
        response_code = (
            item.get("response_code")
            if item.get("response_code") is not None
            else (
                item.get("http_response_code")
                if item.get("http_response_code") is not None
                else (
                    item.get("http__response_code")
                    if item.get("http__response_code") is not None
                    else (item.get("http") or {}).get("response_code", 0)
                )
            )
        )
        violation_rating = (
            item.get("violation_rating")
            if item.get("violation_rating") is not None
            else 0
        )
        country_code = str(item.get("country_code") or item.get("country") or "")
        instance_object_id = str(item.get("instance_object_id") or "")
        csg_object_id = str(item.get("csg_object_id") or "")
        severity = str(
            item.get("severity")
            or cls._derive_severity_from_rating(violation_rating, request_status)
        )

        # If item also contains inline signatures/violations, summarize them
        sigs = item.get("signatures")
        if isinstance(sigs, list) and sigs:
            sig_ids = ",".join(
                str(s.get("id") or s.get("signature_id") or "")
                for s in sigs
                if isinstance(s, dict) and (s.get("id") or s.get("signature_id"))
            )
            sig_names = ",".join(
                str(s.get("name") or s.get("signature_name") or "")
                for s in sigs
                if isinstance(s, dict) and (s.get("name") or s.get("signature_name"))
            )
        else:
            sig_ids = str(item.get("signature_ids") or item.get("signature_id") or "N/A")
            sig_names = str(item.get("signature_names") or item.get("signature_name") or "N/A")

        viols = item.get("violations")
        if isinstance(viols, list) and viols:
            viol_str = ",".join(
                str(v.get("name") or v.get("violation") or "")
                for v in viols
                if isinstance(v, dict) and (v.get("name") or v.get("violation"))
            )
            sub_viol_str = ",".join(
                str(v.get("sub_name") or v.get("sub_violation") or "")
                for v in viols
                if isinstance(v, dict) and (v.get("sub_name") or v.get("sub_violation"))
            )
        else:
            viol_str = str(item.get("violations") if not isinstance(viols, list) else "" or "N/A")
            sub_viol_str = str(item.get("sub_violations") or "N/A")

        normalized: Dict[str, Any] = {
            **item,
            "event_uuid": str(item.get("uuid") or item.get("id") or item.get("event_uuid") or support_id),
            "timestamp": timestamp,
            "support_id": support_id,
            "policy_name": policy_name,
            "request_status": request_status,
            "severity": severity,
            "violation_rating": violation_rating,
            "country_code": country_code,
            "instance_object_id": instance_object_id,
            "csg_object_id": csg_object_id,
            "client_ip": client_ip,
            "url": url,
            "request_method": request_method,
            "response_code": response_code,
            # ClickHouse-compatible column aliases so table columns render seamlessly
            "http__remote_addr": client_ip,
            "http__uri": url,
            "http__request_method": request_method,
            "http__response_code": response_code,
            "http__hostname": str(
                item.get("http__hostname")
                or item.get("http_hostname")
                or (item.get("http") or {}).get("hostname")
                or item.get("request_host")
                or "N/A"
            ),
            "parent_hostname": str(item.get("parent_hostname") or "N/A"),
            "host_display_name": str(item.get("host_display_name") or "N/A"),
            "system_id": str(item.get("system_id") or instance_object_id or "N/A"),
            "signature_ids": sig_ids or "N/A",
            "signature_names": sig_names or "N/A",
            "violations": viol_str or "N/A",
            "sub_violations": sub_viol_str or "N/A",
            "bot_signature_name": str(item.get("bot_signature_name") or "N/A"),
        }
        return normalized

    @classmethod
    def normalize_full_security_event(
        cls,
        raw_event: Dict[str, Any],
        fallback_support_id: str = "",
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Transform a `SecurityEvent` payload from `getSecurityEvent`
        (`GET /api/nginx/one/namespaces/{namespace}/app-protect/events/{id}`)
        into:
          1. `event_row`: Full normalized `security_events` record (including all 53 fields & raw HTTP request)
          2. `violation_rows`: Normalized `violation_data` rows
          3. `signature_rows`: Normalized `signatures_data` rows
        """
        if isinstance(raw_event.get("item"), dict):
            raw_event = raw_event["item"]

        support_id = str(raw_event.get("support_id") or fallback_support_id or "").strip()
        event_uuid = str(
            raw_event.get("id")
            or raw_event.get("uuid")
            or raw_event.get("event_uuid")
            or support_id
        )
        timestamp = str(raw_event.get("timestamp") or "")
        policy_name = str(raw_event.get("policy_name") or "N/A")
        request_status = str(raw_event.get("request_status") or "")
        request_outcome = str(raw_event.get("request_outcome") or "")
        request_outcome_reason = str(raw_event.get("request_outcome_reason") or "N/A")
        violation_rating = (
            raw_event.get("violation_rating")
            if raw_event.get("violation_rating") is not None
            else 0
        )
        blocking_exception_reason = str(raw_event.get("blocking_exception_reason") or "N/A")
        is_truncated = bool(
            raw_event.get("is_truncated", raw_event.get("is_truncated_values", False))
        )
        version = str(raw_event.get("version") or "N/A")
        system_id = str(raw_event.get("system_id") or "N/A")
        parent_hostname = str(raw_event.get("parent_hostname") or "N/A")
        host_display_name = str(raw_event.get("host_display_name") or "N/A")
        instance_object_id = str(raw_event.get("instance_object_id") or "")
        csg_object_id = str(raw_event.get("csg_object_id") or "")
        country_code = str(raw_event.get("country_code") or "")
        xff = str(raw_event.get("x_forwarded_for_header_value") or "N/A")
        raw_request = str(raw_event.get("request") or "")

        http_meta = raw_event.get("http") if isinstance(raw_event.get("http"), dict) else {}
        http_hostname = str(
            http_meta.get("hostname")
            or raw_event.get("http__hostname")
            or raw_event.get("http_hostname")
            or ""
        )
        remote_addr = str(
            http_meta.get("remote_addr")
            or raw_event.get("client_ip")
            or raw_event.get("http__remote_addr")
            or raw_event.get("http_remote_addr")
            or ""
        )
        remote_port = str(
            http_meta.get("remote_port")
            or raw_event.get("http__remote_port")
            or raw_event.get("http_remote_port")
            or ""
        )
        server_addr = str(
            http_meta.get("server_addr")
            or raw_event.get("http__server_addr")
            or raw_event.get("http_server_addr")
            or ""
        )
        raw_server_port = (
            http_meta.get("server_port")
            or raw_event.get("http__server_port")
            or raw_event.get("http_server_port")
            or 0
        )
        try:
            server_port: Any = int(raw_server_port)
        except (ValueError, TypeError):
            server_port = str(raw_server_port)

        uri = str(
            http_meta.get("uri")
            or raw_event.get("url")
            or raw_event.get("http__uri")
            or raw_event.get("http_uri")
            or ""
        )
        request_method = str(
            http_meta.get("request_method")
            or raw_event.get("request_method")
            or raw_event.get("http__request_method")
            or raw_event.get("http_request_method")
            or ""
        )
        raw_resp_code = (
            http_meta.get("response_code")
            if http_meta.get("response_code") is not None
            else (
                raw_event.get("response_code")
                or raw_event.get("http__response_code")
                or raw_event.get("http_response_code")
                or 0
            )
        )
        try:
            response_code: Any = int(raw_resp_code)
        except (ValueError, TypeError):
            response_code = str(raw_resp_code)

        threat_campaigns = raw_event.get("threat_campaign_names")
        if isinstance(threat_campaigns, list):
            threat_campaign_names_str = ",".join(str(x) for x in threat_campaigns if x) or "N/A"
        else:
            threat_campaign_names_str = str(threat_campaigns or "N/A")

        raw_violations = (
            raw_event.get("violations")
            if isinstance(raw_event.get("violations"), list)
            else []
        )
        top_signatures = (
            raw_event.get("signatures")
            if isinstance(raw_event.get("signatures"), list)
            else []
        )
        # Collect signatures from both top-level `signatures` and nested `violations[].signatures`
        raw_signatures: List[Dict[str, Any]] = [
            s for s in top_signatures if isinstance(s, dict)
        ]
        for v in raw_violations:
            if isinstance(v, dict) and isinstance(v.get("signatures"), list):
                for s in v["signatures"]:
                    if isinstance(s, dict):
                        raw_signatures.append(s)

        # Summarize signatures for cross-reference in event & violation rows
        sig_id_list = [
            str(s.get("id") or s.get("signature_id") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("id") or s.get("signature_id") or "").strip()
        ]
        sig_name_list = [
            str(s.get("name") or s.get("signature_name") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("name") or s.get("signature_name") or "").strip()
        ]
        sig_acc_list = [
            str(s.get("accuracy") or s.get("signature_accuracy") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("accuracy") or s.get("signature_accuracy") or "").strip()
        ]
        sig_risk_list = [
            str(s.get("risk") or s.get("signature_risk") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("risk") or s.get("signature_risk") or "").strip()
        ]
        sig_cve_list = [
            str(s.get("cve") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("cve") or "").strip()
        ]
        sig_buf_list = [
            str(s.get("buffer") or "").strip()
            for s in raw_signatures
            if isinstance(s, dict) and str(s.get("buffer") or "").strip()
        ]
        sig_offset_list = [
            str(s.get("offset") if s.get("offset") is not None else "")
            for s in raw_signatures
            if isinstance(s, dict) and s.get("offset") is not None
        ]
        sig_length_list = [
            str(s.get("length") if s.get("length") is not None else "")
            for s in raw_signatures
            if isinstance(s, dict) and s.get("length") is not None
        ]
        sig_mask_list = [
            str(s.get("blocking_mask") if s.get("blocking_mask") is not None else "")
            for s in raw_signatures
            if isinstance(s, dict) and s.get("blocking_mask") is not None
        ]

        sig_ids_str = ",".join(sig_id_list) if sig_id_list else "N/A"
        sig_names_str = ",".join(sig_name_list) if sig_name_list else "N/A"
        sig_accs_str = ",".join(sig_acc_list) if sig_acc_list else "N/A"
        sig_risks_str = ",".join(sig_risk_list) if sig_risk_list else "N/A"
        sig_cves_str = ",".join(sig_cve_list) if sig_cve_list else "N/A"

        def _extract_sub_violation_str(v_dict: Dict[str, Any]) -> str:
            sv = v_dict.get("sub_name") or v_dict.get("sub_violations")
            if isinstance(sv, list):
                names = [
                    str(x.get("name") if isinstance(x, dict) else x).strip()
                    for x in sv
                    if x
                ]
                return ",".join(n for n in names if n)
            return str(sv or "").strip()

        # Summarize violations for cross-reference in event & signature rows
        viol_name_list = [
            str(v.get("name") or v.get("violations") or "").strip()
            for v in raw_violations
            if isinstance(v, dict) and str(v.get("name") or v.get("violations") or "").strip()
        ]
        sub_viol_list = [
            _extract_sub_violation_str(v)
            for v in raw_violations
            if isinstance(v, dict) and _extract_sub_violation_str(v)
        ]
        viol_ctx_list = [
            str(v.get("context") or v.get("violation_context") or "").strip()
            for v in raw_violations
            if isinstance(v, dict) and str(v.get("context") or v.get("violation_context") or "").strip()
        ]
        field_name_list = [
            str(v.get("field_name") or "").strip()
            for v in raw_violations
            if isinstance(v, dict) and str(v.get("field_name") or "").strip()
        ]
        field_val_list = [
            str(v.get("field_value") or "").strip()
            for v in raw_violations
            if isinstance(v, dict) and str(v.get("field_value") or "").strip()
        ]

        violations_str = ",".join(viol_name_list) if viol_name_list else "N/A"
        sub_violations_str = ",".join(sub_viol_list) if sub_viol_list else "N/A"
        violation_contexts_str = ",".join(viol_ctx_list) if viol_ctx_list else "N/A"
        field_names_str = ",".join(field_name_list) if field_name_list else ""
        field_values_str = ",".join(field_val_list) if field_val_list else ""

        severity = cls._derive_severity_from_rating(violation_rating, request_status)

        # Build violation_data rows
        violation_rows: List[Dict[str, Any]] = []
        for idx, v in enumerate(raw_violations):
            if not isinstance(v, dict):
                continue
            v_name = str(v.get("name") or v.get("violations") or "N/A")
            v_sub = _extract_sub_violation_str(v) or "N/A"
            v_ctx = str(v.get("context") or v.get("violation_context") or "N/A")
            v_det_name = str(v.get("detail_name") or v.get("violation_details_name") or "N/A")
            v_det_ctx = str(v.get("detail_context") or v.get("violation_details_context") or "N/A")
            v_fname = str(v.get("field_name") or "")
            v_fval = str(v.get("field_value") or "")
            violation_rows.append({
                "uuid": str(v.get("uuid") or f"{support_id}-viol-{idx + 1}"),
                "timestamp": timestamp,
                "support_id": support_id,
                "name": v_name,
                "sub_name": v_sub,
                "context": v_ctx,
                "detail_name": v_det_name,
                "detail_context": v_det_ctx,
                "violations": v_name,
                "violation_name": v_name,
                "sub_violations": v_sub,
                "violation_context": v_ctx,
                "violation_details_name": v_det_name,
                "violation_details_context": v_det_ctx,
                "field_name": v_fname,
                "field_value": v_fval,
                "parameter_data_name": v_fname,
                "parameter_data_value": v_fval,
                "violation_rating": violation_rating,
                "signature_ids": sig_ids_str,
                "signature_names": sig_names_str,
                "signature_accuracy": sig_accs_str,
                "signature_risk": sig_risks_str,
                "signature_cve": sig_cves_str,
                "signature_buffer": ",".join(sig_buf_list) if sig_buf_list else "N/A",
                "signature_offset": ",".join(sig_offset_list) if sig_offset_list else "N/A",
                "signature_length": ",".join(sig_length_list) if sig_length_list else "N/A",
                "signature_blocking_mask": ",".join(sig_mask_list) if sig_mask_list else "N/A",
                "policy_name": policy_name,
                "request_status": request_status,
                "request_outcome": request_outcome,
                "request_outcome_reason": request_outcome_reason,
                "http__hostname": http_hostname,
                "http__remote_addr": remote_addr,
                "http__remote_port": remote_port,
                "http__server_addr": server_addr,
                "http__server_port": server_port,
                "http__request_method": request_method,
                "http__uri": uri,
                "http__response_code": response_code,
                "country_code": country_code,
                "system_id": system_id,
                "parent_hostname": parent_hostname,
                "host_display_name": host_display_name,
                "instance_object_id": instance_object_id,
                "csg_object_id": csg_object_id,
                "version": version,
                "x_forwarded_for_header_value": xff,
                "threat_campaign_names": threat_campaign_names_str,
            })

        # Build signatures_data rows
        signature_rows: List[Dict[str, Any]] = []
        for idx, s in enumerate(raw_signatures):
            if not isinstance(s, dict):
                continue
            s_id = str(s.get("id") or s.get("signature_id") or "").strip()
            s_name = str(s.get("name") or s.get("signature_name") or "N/A")
            s_acc = str(s.get("accuracy") or s.get("signature_accuracy") or "N/A")
            s_risk = str(s.get("risk") or s.get("signature_risk") or "N/A")
            s_cve = str(s.get("cve") or "N/A")
            s_mask = s.get("blocking_mask") if s.get("blocking_mask") is not None else 0
            s_buf = str(s.get("buffer") or "")
            s_offset = int(s.get("offset") or 0)
            s_len = int(s.get("length") or 0)
            signature_rows.append({
                "uuid": f"{support_id}-sig-{s_id or (idx + 1)}-{idx + 1}",
                "timestamp": timestamp,
                "support_id": support_id,
                "id": s_id,
                "name": s_name,
                "accuracy": s_acc,
                "risk": s_risk,
                "signature_id": s_id,
                "signature_name": s_name,
                "signature_accuracy": s_acc,
                "signature_risk": s_risk,
                "cve": s_cve,
                "blocking_mask": s_mask,
                "buffer": s_buf,
                "offset": s_offset,
                "length": s_len,
                "is_truncated_Now": str(is_truncated).lower(),
                "violations": violations_str,
                "sub_violations": sub_violations_str,
                "violation_contexts": violation_contexts_str,
                "violation_details_names": ",".join(
                    str(v.get("detail_name") or "") for v in raw_violations if isinstance(v, dict) and v.get("detail_name")
                ) or "N/A",
                "violation_details_contexts": ",".join(
                    str(v.get("detail_context") or "") for v in raw_violations if isinstance(v, dict) and v.get("detail_context")
                ) or "N/A",
                "field_names": field_names_str,
                "field_values": field_values_str,
                "parameter_data_names": field_names_str or "N/A",
                "parameter_data_values": field_values_str or "N/A",
                "violation_rating": violation_rating,
                "policy_name": policy_name,
                "request_status": request_status,
                "request_outcome": request_outcome,
                "request_outcome_reason": request_outcome_reason,
                "http__hostname": http_hostname,
                "http__remote_addr": remote_addr,
                "http__remote_port": remote_port,
                "http__server_addr": server_addr,
                "http__server_port": server_port,
                "http__request_method": request_method,
                "http__uri": uri,
                "http__response_code": response_code,
                "country_code": country_code,
                "system_id": system_id,
                "parent_hostname": parent_hostname,
                "host_display_name": host_display_name,
                "instance_object_id": instance_object_id,
                "csg_object_id": csg_object_id,
                "version": version,
                "x_forwarded_for_header_value": xff,
                "threat_campaign_names": threat_campaign_names_str,
            })

        # Build full event row (all NGINX One SecurityEvent fields + 53 ClickHouse-compatible columns)
        event_row: Dict[str, Any] = {
            **raw_event,
            "id": event_uuid,
            "event_uuid": event_uuid,
            "timestamp": timestamp,
            "support_id": support_id,
            "version": version,
            "system_id": system_id,
            "parent_hostname": parent_hostname,
            "host_display_name": host_display_name,
            "instance_object_id": instance_object_id,
            "csg_object_id": csg_object_id,
            "http": http_meta,
            "http__hostname": http_hostname,
            "http__remote_addr": remote_addr,
            "http__remote_port": remote_port,
            "http__server_addr": server_addr,
            "http__server_port": server_port,
            "http__uri": uri,
            "http__request_method": request_method,
            "http__response_code": response_code,
            "client_ip": remote_addr,
            "url": uri,
            "request_method": request_method,
            "response_code": response_code,
            "x_forwarded_for_header_value": xff,
            "country_code": country_code,
            "policy_name": policy_name,
            "request_status": request_status,
            "request_outcome": request_outcome,
            "request_outcome_reason": request_outcome_reason,
            "severity": severity,
            "violation_rating": violation_rating,
            "blocking_exception_reason": blocking_exception_reason,
            "is_truncated": is_truncated,
            "is_truncated_Values": str(is_truncated).lower(),
            "request": raw_request,
            "threat_campaign_names": threat_campaign_names_str,
            "violations": violations_str,
            "sub_violations": sub_violations_str,
            "violation_contexts": violation_contexts_str,
            "signature_ids": sig_ids_str,
            "signature_names": sig_names_str,
            "signature_Check": "true" if sig_id_list else "false",
            "signature_accuracy": sig_accs_str,
            "signature_risk": sig_risks_str,
            "signature_cves": sig_cves_str,
            "signature_buffers": ",".join(sig_buf_list) if sig_buf_list else "N/A",
            "signature_offsets": ",".join(sig_offset_list) if sig_offset_list else "N/A",
            "signature_lengths": ",".join(sig_length_list) if sig_length_list else "N/A",
            "signature_blocking_masks": ",".join(sig_mask_list) if sig_mask_list else "N/A",
            "bot_signature_name": str(raw_event.get("bot_signature_name") or "N/A"),
            "bot_category": str(raw_event.get("bot_category") or "N/A"),
            "bot_anomalies": str(raw_event.get("bot_anomalies") or "N/A"),
            "enforced_bot_anomalies": str(raw_event.get("enforced_bot_anomalies") or "N/A"),
            "client_class": str(raw_event.get("client_class") or "N/A"),
            "client_application": str(raw_event.get("client_application") or "N/A"),
            "client_application_version": str(raw_event.get("client_application_version") or "N/A"),
        }

        return event_row, violation_rows, signature_rows

    def get_schema_metadata(self) -> Dict[str, Any]:
        """Return schema metadata for NGINX One Console security events and filter fields."""
        seen = {c["name"] for c in NGINX_ONE_EVENTS_LIST_COLUMNS}
        merged_columns = list(NGINX_ONE_EVENTS_LIST_COLUMNS)
        for col in V4_SECURITY_EVENTS_SCHEMA:
            if col["name"] not in seen:
                merged_columns.append(col)
                seen.add(col["name"])

        return {
            "source": "nginx_one",
            "endpoints": {
                "listSecurityEvents": {
                    "method": "GET",
                    "path": "/api/nginx/one/namespaces/{namespace}/app-protect/events",
                    "description": "Retrieve a list of App Protect security events with optional filtering and pagination.",
                    "filter_fields": NGINX_ONE_ANALYTICS_FILTER_FIELDS,
                    "filter_ops": ["IN"],
                },
                "getSecurityEvent": {
                    "method": "GET",
                    "path": "/api/nginx/one/namespaces/{namespace}/app-protect/events/{id}",
                    "description": "Retrieve details of a specific App Protect security event by its support_id.",
                },
            },
            "tables": {
                "v4_security_events": {
                    "name": "app-protect/events",
                    "description": "NGINX One Console App Protect security events (listSecurityEvents & getSecurityEvent).",
                    "column_count": len(merged_columns),
                    "columns": merged_columns,
                },
                "v4_security_events_violation_data": {
                    "name": "SecurityEvent.violations",
                    "description": "Per-violation records from getSecurityEvent (correlated by support_id).",
                    "column_count": len(V4_VIOLATION_DATA_SCHEMA),
                    "columns": V4_VIOLATION_DATA_SCHEMA,
                },
                "v4_security_events_signatures_data": {
                    "name": "SecurityEvent.signatures",
                    "description": "Per-signature records from getSecurityEvent (correlated by support_id) with signature_id for policy tuning.",
                    "column_count": len(V4_SIGNATURES_DATA_SCHEMA),
                    "columns": V4_SIGNATURES_DATA_SCHEMA,
                },
            },
            "analytics_filter_fields": NGINX_ONE_ANALYTICS_FILTER_FIELDS,
            "operators": NGINX_ONE_SUPPORTED_OPERATORS,
            "correlation_key": "support_id",
        }

    # ------------------------------------------------------------------
    # Client-Side Filter Evaluation (for operators beyond API 'IN' or global search)
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_filter(row: Dict[str, Any], col: str, op: str, val: str) -> bool:
        raw_cell = row.get(col)
        if raw_cell is None and col in COLUMN_TO_NGINX_ONE_FILTER_FIELD:
            mapped = COLUMN_TO_NGINX_ONE_FILTER_FIELD[col]
            raw_cell = row.get(mapped)
        cell_str = "" if raw_cell is None else str(raw_cell)
        cell_lower = cell_str.lower()
        val_str = (val or "").strip()
        val_lower = val_str.lower()

        if op == "is_empty":
            return cell_str == "" or cell_str.upper() == "N/A"
        if op == "is_not_empty":
            return cell_str != "" and cell_str.upper() != "N/A"
        if op == "equals":
            return cell_lower == val_lower
        if op == "not_equals":
            return cell_lower != val_lower
        if op == "contains":
            if "|" in val_lower:
                parts = [p.strip() for p in val_lower.split("|") if p.strip()]
                return any(p in cell_lower for p in parts)
            return val_lower in cell_lower
        if op == "not_contains":
            return val_lower not in cell_lower
        if op == "starts_with":
            return cell_lower.startswith(val_lower)
        if op == "ends_with":
            return cell_lower.endswith(val_lower)
        if op == "in":
            parts = [
                p.strip().lower()
                for p in re.split(r"[,|]", val_str)
                if p.strip()
            ]
            return cell_lower in parts or any(p in cell_lower for p in parts)
        if op in ("gt", "gte", "lt", "lte"):
            try:
                c_num = float(cell_str)
                v_num = float(val_str)
                if op == "gt":
                    return c_num > v_num
                if op == "gte":
                    return c_num >= v_num
                if op == "lt":
                    return c_num < v_num
                if op == "lte":
                    return c_num <= v_num
            except Exception:
                if op == "gt":
                    return cell_str > val_str
                if op == "gte":
                    return cell_str >= val_str
                if op == "lt":
                    return cell_str < val_str
                if op == "lte":
                    return cell_str <= val_str
        return True

    # ------------------------------------------------------------------
    # 1. listSecurityEvents (`GET /app-protect/events`)
    # ------------------------------------------------------------------

    def search_security_events(
        self,
        filters: Optional[List[Dict[str, Any]]] = None,
        field_filters: Optional[Dict[str, str]] = None,
        exact_columns: Optional[List[str]] = None,
        global_search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_dir: str = "DESC",
        sort_order: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        filter_fields: Optional[List[str]] = None,
        filter_values: Optional[List[str]] = None,
        filter_ops: Optional[List[str]] = None,
        paginated: bool = True,
        include_correlations: bool = False,
    ) -> Dict[str, Any]:
        """
        Query WAF security events from NGINX One Console using `listSecurityEvents`:
          `GET https://{tenant_cname}.console.ves.volterra.io/api/nginx/one/namespaces/{namespace}/app-protect/events`
        """
        if not self._loaded_from_redis and not self.is_configured():
            self.load_config_from_redis()
        if not self.is_configured():
            raise RuntimeError(
                "NGINX One Console connection is not configured. Please configure Tenant CNAME / Base URL and API Token first."
            )

        effective_sort_dir = (sort_order or sort_dir or "DESC").upper()
        safe_limit = max(1, min(int(limit or 50), 500))
        safe_offset = max(0, int(offset or 0))

        # Build official NGINX One API filter arrays (filter_fields, filter_values, filter_ops)
        # AND filter expression string
        api_filter_map: Dict[str, List[str]] = {}
        post_filters: List[Dict[str, str]] = []
        filter_expr_parts: List[str] = []

        # 1) Explicit NGINX One API filter arrays if passed directly
        if filter_fields and filter_values:
            for idx, ff in enumerate(filter_fields):
                f_name = str(ff or "").strip()
                mapped_ff = COLUMN_TO_NGINX_ONE_FILTER_FIELD.get(f_name, f_name)
                if mapped_ff in NGINX_ONE_VALID_FILTER_FIELD_NAMES and idx < len(filter_values):
                    f_val = str(filter_values[idx] or "").strip()
                    if f_val:
                        api_filter_map.setdefault(mapped_ff, []).append(f_val)

        # Merge legacy field_filters and exact_columns into structured filters list
        combined_filters: List[Dict[str, Any]] = list(filters or [])
        exact_set = set(exact_columns.keys() if isinstance(exact_columns, dict) else (exact_columns or []))
        if isinstance(exact_columns, dict):
            for col_name, col_val in exact_columns.items():
                if col_val is not None and str(col_val).strip():
                    combined_filters.append({
                        "column": col_name,
                        "operator": "equals",
                        "value": str(col_val).strip(),
                    })
        if isinstance(field_filters, list):
            for item in field_filters:
                if isinstance(item, dict):
                    combined_filters.append(item)
        elif isinstance(field_filters, dict):
            for col_name, col_val in field_filters.items():
                if col_val is not None and str(col_val).strip():
                    combined_filters.append({
                        "column": col_name,
                        "operator": "equals" if col_name in exact_set else "contains",
                        "value": str(col_val).strip(),
                    })

        # 2) Structured UI filters
        for flt in combined_filters:
            col = str(flt.get("column") or flt.get("field") or "").strip()
            op = str(flt.get("operator") or "contains").strip().lower()
            val = str(flt.get("value") or "").strip()
            if not col:
                continue
            if op not in ("is_empty", "is_not_empty") and not val:
                continue

            escaped_val = val.replace("'", "\\'")
            if op == "equals":
                filter_expr_parts.append(f"{col}='{escaped_val}'")
            elif op == "not_equals":
                filter_expr_parts.append(f"{col}!='{escaped_val}'")
            elif op == "contains":
                filter_expr_parts.append(f"{col} CONTAINS '{escaped_val}'")

            mapped_api_field = COLUMN_TO_NGINX_ONE_FILTER_FIELD.get(col)
            if mapped_api_field and op in ("equals", "in", "contains"):
                pipe_val = "|".join(
                    p.strip() for p in re.split(r"[,|]", val) if p.strip()
                )
                if pipe_val:
                    api_filter_map.setdefault(mapped_api_field, []).append(pipe_val)
            else:
                post_filters.append({"column": col, "operator": op, "value": val})

        final_filter_fields: List[str] = []
        final_filter_values: List[str] = []
        final_filter_ops: List[str] = []

        for ff_name, vals in api_filter_map.items():
            dedup_vals: List[str] = []
            for v in vals:
                for sub_v in v.split("|"):
                    sv = sub_v.strip()
                    if sv and sv not in dedup_vals:
                        dedup_vals.append(sv)
            if dedup_vals:
                final_filter_fields.append(ff_name)
                final_filter_values.append("|".join(dedup_vals))
                final_filter_ops.append("IN")

        now_utc = datetime.now(timezone.utc)
        effective_end_time = (
            str(end_time).strip()
            if (end_time and str(end_time).strip())
            else now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        effective_start_time = (
            str(start_time).strip()
            if (start_time and str(start_time).strip())
            else (now_utc - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        # Note: NGINX One Console `offset` parameter is 1-based (`minimum: 1`) when `paginated=true`
        api_offset = safe_offset + 1
        query_params: Dict[str, Any] = {
            "paginated": bool(paginated),
            "offset": api_offset,
            "limit": safe_limit,
            "start_time": effective_start_time,
            "end_time": effective_end_time,
        }
        if filter_expr_parts:
            query_params["filter"] = " AND ".join(filter_expr_parts)
        if final_filter_fields:
            query_params["filter_fields"] = final_filter_fields
            query_params["filter_values"] = final_filter_values
            query_params["filter_ops"] = final_filter_ops

        endpoint_url = self.get_events_endpoint_url()
        raw_response = self._request_json("GET", endpoint_url, params=query_params)

        raw_items = raw_response.get("items")
        if not isinstance(raw_items, list):
            raw_items = []

        rows = [
            self.normalize_event_list_item(item)
            for item in raw_items
            if isinstance(item, dict)
        ]

        # Apply client-side post-filters if any non-API filter operators or global search were used
        if post_filters:
            for pf in post_filters:
                rows = [
                    r
                    for r in rows
                    if self._matches_filter(r, pf["column"], pf["operator"], pf["value"])
                ]

        if global_search and global_search.strip():
            needle = global_search.strip().lower()
            rows = [
                r
                for r in rows
                if any(
                    needle in str(v).lower()
                    for v in r.values()
                    if v is not None and not isinstance(v, (dict, list))
                )
            ]

        # Optional client-side sorting if requested
        sort_col = sort_by if sort_by else "timestamp"
        reverse = effective_sort_dir != "ASC"
        if rows and sort_col and any(sort_col in r for r in rows):
            try:
                rows.sort(
                    key=lambda r: (
                        r.get(sort_col) is None,
                        r.get(sort_col) if isinstance(r.get(sort_col), (int, float)) else str(r.get(sort_col) or ""),
                    ),
                    reverse=reverse,
                )
            except Exception:
                pass

        total_from_api = raw_response.get("total")
        if post_filters or (global_search and global_search.strip()):
            total = len(rows)
        else:
            total = int(total_from_api if total_from_api is not None else len(rows))

        qs_tuples = self._build_query_params_tuples(query_params)
        executed_request = f"GET {endpoint_url}" + (
            f"?{urlencode(qs_tuples)}" if qs_tuples else ""
        )

        return {
            "source": "nginx_one",
            "total": total,
            "count": int(raw_response.get("count", len(rows))),
            "start_index": int(raw_response.get("start_index", api_offset)),
            "items_per_page": int(raw_response.get("items_per_page", safe_limit)),
            "limit": safe_limit,
            "offset": safe_offset,
            "sort_by": sort_col,
            "sort_dir": "DESC" if reverse else "ASC",
            "rows": rows,
            "events": rows,
            "items": rows,
            "query": executed_request,
            "filter_fields": final_filter_fields,
            "filter_values": final_filter_values,
            "filter_ops": final_filter_ops,
        }

    # ------------------------------------------------------------------
    # 2. getSecurityEvent (`GET /app-protect/events/{id}`) & Correlation
    # ------------------------------------------------------------------

    def get_security_event(self, support_id: str) -> Dict[str, Any]:
        """
        Retrieve a single security event by its `support_id` via `getSecurityEvent`:
          `GET https://{tenant_cname}.console.ves.volterra.io/api/nginx/one/namespaces/{namespace}/app-protect/events/{id}`
        """
        if not self._loaded_from_redis and not self.is_configured():
            self.load_config_from_redis()
        if not self.is_configured():
            raise RuntimeError(
                "NGINX One Console connection is not configured. Please configure Tenant CNAME / Base URL and API Token first."
            )

        clean_id = (support_id or "").strip()
        if not clean_id:
            raise ValueError("support_id is required to fetch an NGINX One Console security event.")

        endpoint_url = self.get_events_endpoint_url(support_id=clean_id)
        return self._request_json("GET", endpoint_url)

    def get_correlated_event(
        self,
        support_id: str,
        policy_name: Optional[str] = None,
        target_policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Fetch full event details for `support_id` from NGINX One Console (`getSecurityEvent`)
        and correlate its `signatures`, `violations`, and `http`/`request` data with the
        target WAF policy in storage so the user can fine-tune `signature_id` states.
        """
        clean_id = (support_id or "").strip()
        if not clean_id:
            raise ValueError("support_id is required for correlation.")

        raw_event = self.get_security_event(clean_id)
        event_row, violation_rows, signature_rows = self.normalize_full_security_event(
            raw_event,
            fallback_support_id=clean_id,
        )
        events_rows = [event_row]

        # Aggregate unique signatures triggered by this support_id
        unique_signatures_map: Dict[str, Dict[str, Any]] = {}
        for row in signature_rows:
            sig_id = str(row.get("signature_id") or "").strip()
            if not sig_id or sig_id.upper() == "N/A":
                continue
            if sig_id not in unique_signatures_map:
                unique_signatures_map[sig_id] = {
                    "signature_id": sig_id,
                    "signature_name": row.get("signature_name", ""),
                    "signature_accuracy": row.get("signature_accuracy", ""),
                    "signature_risk": row.get("signature_risk", ""),
                    "cve": row.get("cve", "N/A"),
                    "blocking_mask": row.get("blocking_mask", 0),
                    "buffer": row.get("buffer", ""),
                    "offset": row.get("offset", 0),
                    "length": row.get("length", 0),
                    "violation_contexts": row.get("violation_contexts", ""),
                    "field_names": row.get("field_names", ""),
                    "field_values": row.get("field_values", ""),
                    "violations": row.get("violations", ""),
                    "sub_violations": row.get("sub_violations", ""),
                    "occurrences": 1,
                }
            else:
                unique_signatures_map[sig_id]["occurrences"] += 1

        # Determine log policy_name and resolve target WAF policy from storage
        log_policy_name: Optional[str] = None
        if event_row.get("policy_name") and str(event_row["policy_name"]).strip().upper() != "N/A":
            log_policy_name = str(event_row["policy_name"]).strip()

        matched_log_policy_name = (
            self._find_matching_policy_name(log_policy_name)
            if log_policy_name
            else None
        )

        explicit_policy = (target_policy_name or policy_name or "").strip()
        target_policy = explicit_policy or matched_log_policy_name or log_policy_name
        resolved_target_policy = (
            self._find_matching_policy_name(target_policy)
            if target_policy
            else None
        )
        effective_policy_for_states = resolved_target_policy or target_policy

        policy_signature_states: Dict[str, Dict[str, Any]] = {}
        if effective_policy_for_states:
            policy_signature_states = self.get_policy_signature_states(
                effective_policy_for_states,
                list(unique_signatures_map.keys()),
            )

        for sig_id, sig_info in unique_signatures_map.items():
            sig_info["policy_override"] = policy_signature_states.get(
                sig_id,
                {
                    "signatureId": int(sig_id) if sig_id.isdigit() else sig_id,
                    "in_policy": False,
                    "status": "default",
                    "enabled": None,
                    "tag": None,
                },
            )

        for row in signature_rows:
            sig_id = str(row.get("signature_id") or "").strip()
            row["policy_override"] = policy_signature_states.get(
                sig_id,
                {
                    "signatureId": int(sig_id) if sig_id.isdigit() else sig_id,
                    "in_policy": False,
                    "status": "default",
                    "enabled": None,
                    "tag": None,
                },
            )

        return {
            "found": True,
            "source": "nginx_one",
            "support_id": clean_id,
            "target_policy_name": effective_policy_for_states,
            "matched_policy_name": resolved_target_policy or matched_log_policy_name,
            "log_policy_name": log_policy_name,
            "matched_log_policy_name": matched_log_policy_name,
            "event_summary": event_row,
            "security_events": events_rows,
            "violation_data": violation_rows,
            "signatures_data": signature_rows,
            "unique_signatures": list(unique_signatures_map.values()),
            "policy_signature_states": policy_signature_states,
            "raw_nginx_one_event": raw_event,
            "endpoint": self.get_events_endpoint_url(support_id=clean_id),
            "counts": {
                "security_events": len(events_rows),
                "violation_data": len(violation_rows),
                "signatures_data": len(signature_rows),
                "unique_signatures": len(unique_signatures_map),
            },
        }

    def batch_correlate_events(
        self,
        support_ids: List[str],
        policy_name: Optional[str] = None,
        target_policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Correlate multiple support_ids via `getSecurityEvent` and aggregate all triggered signatures."""
        clean_ids = [str(s).strip() for s in support_ids if str(s).strip()]
        if not clean_ids:
            return {
                "source": "nginx_one",
                "support_ids": [],
                "security_events": [],
                "violation_data": [],
                "signatures_data": [],
                "unique_signatures": [],
            }

        events_rows: List[Dict[str, Any]] = []
        violation_rows: List[Dict[str, Any]] = []
        signature_rows: List[Dict[str, Any]] = []

        for sid in clean_ids[:50]:
            try:
                raw_ev = self.get_security_event(sid)
                ev_row, v_rows, s_rows = self.normalize_full_security_event(
                    raw_ev,
                    fallback_support_id=sid,
                )
                events_rows.append(ev_row)
                violation_rows.extend(v_rows)
                signature_rows.extend(s_rows)
            except Exception:
                continue

        unique_sigs: Dict[str, Dict[str, Any]] = {}
        for row in signature_rows:
            sig_id = str(row.get("signature_id") or "").strip()
            if not sig_id or sig_id.upper() == "N/A":
                continue
            if sig_id not in unique_sigs:
                unique_sigs[sig_id] = {
                    "signature_id": sig_id,
                    "signature_name": row.get("signature_name", ""),
                    "signature_accuracy": row.get("signature_accuracy", ""),
                    "signature_risk": row.get("signature_risk", ""),
                    "cve": row.get("cve", "N/A"),
                    "blocking_mask": row.get("blocking_mask", 0),
                    "buffer": row.get("buffer", ""),
                    "offset": row.get("offset", 0),
                    "length": row.get("length", 0),
                    "violation_contexts": row.get("violation_contexts", ""),
                    "field_names": row.get("field_names", ""),
                    "occurrences": 1,
                    "support_ids": [row.get("support_id", "")],
                }
            else:
                unique_sigs[sig_id]["occurrences"] += 1
                sid_val = row.get("support_id", "")
                if sid_val and sid_val not in unique_sigs[sig_id]["support_ids"]:
                    unique_sigs[sig_id]["support_ids"].append(sid_val)

        target_policy = (target_policy_name or policy_name or "").strip()
        if not target_policy and events_rows:
            raw_pol = events_rows[0].get("policy_name")
            if raw_pol and raw_pol != "N/A":
                target_policy = raw_pol

        policy_signature_states: Dict[str, Dict[str, Any]] = {}
        if target_policy:
            policy_signature_states = self.get_policy_signature_states(
                target_policy,
                list(unique_sigs.keys()),
            )
        for sig_id, sig_info in unique_sigs.items():
            sig_info["policy_override"] = policy_signature_states.get(
                sig_id,
                {
                    "signatureId": int(sig_id) if sig_id.isdigit() else sig_id,
                    "in_policy": False,
                    "status": "default",
                    "enabled": None,
                    "tag": None,
                },
            )

        return {
            "source": "nginx_one",
            "support_ids": clean_ids,
            "target_policy_name": target_policy or None,
            "security_events": events_rows,
            "violation_data": violation_rows,
            "signatures_data": signature_rows,
            "unique_signatures": list(unique_sigs.values()),
            "policy_signature_states": policy_signature_states,
        }

    # ------------------------------------------------------------------
    # 3. WAF Policy Signature Fine-Tuning (Delegates to shared policy logic)
    # ------------------------------------------------------------------

    def _find_matching_policy_name(self, raw_policy_name: Optional[str]) -> Optional[str]:
        return get_clickhouse_service()._find_matching_policy_name(raw_policy_name)

    def find_matching_policy_name(self, raw_policy_name: Optional[str]) -> Optional[str]:
        return get_clickhouse_service()._find_matching_policy_name(raw_policy_name)

    def get_policy_signature_states(
        self,
        policy_name: str,
        signature_ids: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        return get_clickhouse_service().get_policy_signature_states(policy_name, signature_ids)

    def tune_policy_signature(
        self,
        policy_name: str,
        signature_id: int | str,
        enabled: Optional[bool],
        signature_name: Optional[str] = None,
        tag: Optional[str] = None,
        support_id: Optional[str] = None,
        action: str = "set",
    ) -> Dict[str, Any]:
        effective_tag = tag
        if not effective_tag and support_id:
            effective_tag = f"tuned-from-support-id-{support_id}"
        return get_clickhouse_service().tune_policy_signature(
            policy_name=policy_name,
            signature_id=signature_id,
            enabled=enabled,
            signature_name=signature_name,
            tag=effective_tag,
            support_id=support_id,
            action=action,
        )

    def bulk_tune_policy_signatures(
        self,
        policy_name: str,
        signatures: List[Dict[str, Any]],
        support_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return get_clickhouse_service().bulk_tune_policy_signatures(
            policy_name=policy_name,
            signatures=signatures,
            support_id=support_id,
        )

    def save_tuned_policy_to_redis(
        self,
        policy_name: str,
        signatures: Optional[List[Dict[str, Any]]] = None,
        support_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return get_clickhouse_service().save_tuned_policy_to_redis(
            policy_name=policy_name,
            signatures=signatures,
            support_id=support_id,
        )


# Singleton instance used across API routes
_nginx_one_service_instance: Optional[NginxOneConsoleService] = None


def get_nginx_one_service() -> NginxOneConsoleService:
    global _nginx_one_service_instance
    if _nginx_one_service_instance is None:
        _nginx_one_service_instance = NginxOneConsoleService()
    return _nginx_one_service_instance


def set_nginx_one_service(service: NginxOneConsoleService) -> None:
    global _nginx_one_service_instance
    _nginx_one_service_instance = service


nginx_one_service = get_nginx_one_service()
