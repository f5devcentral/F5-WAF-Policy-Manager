"""
ClickHouse Service for F5 WAF Policy Manager.
Connects to the ClickHouse instance inside NGINX Instance Manager (NIM / NMS),
persists connection configuration in Redis across reboots, searches across all 53
fields of v4_security_events, correlates v4_security_events,
v4_security_events_violation_data, and v4_security_events_signatures_data by support_id,
and provides WAF policy signature fine-tuning (enabling/disabling signature_id).
"""

import datetime
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from ..config import settings

logger = logging.getLogger("f5_waf_editor.clickhouse")

CLICKHOUSE_REDIS_CONFIG_KEY = "__clickhouse__:config"
CLICKHOUSE_CONFIG_REDIS_KEY = CLICKHOUSE_REDIS_CONFIG_KEY

# ---------------------------------------------------------------------------
# Complete Schema Definitions for the 3 Correlated ClickHouse Tables
# ---------------------------------------------------------------------------

V4_SECURITY_EVENTS_SCHEMA: List[Dict[str, str]] = [
    {"name": "timestamp", "type": "DateTime", "category": "Core & Timing", "description": "Event timestamp when the security violation occurred"},
    {"name": "event_uuid", "type": "String", "category": "Core & Timing", "description": "Unique security event identifier (UUID)"},
    {"name": "system_id", "type": "String", "category": "Instance & System", "description": "NGINX Instance Manager system UUID"},
    {"name": "parent_hostname", "type": "String", "category": "Instance & System", "description": "Parent host hostname"},
    {"name": "system__tags", "type": "String", "category": "Instance & System", "description": "System tags assigned in NGINX Instance Manager"},
    {"name": "instance", "type": "String", "category": "Instance & System", "description": "NGINX instance identifier"},
    {"name": "instance_group", "type": "String", "category": "Instance & System", "description": "NGINX instance group name"},
    {"name": "support_id", "type": "String", "category": "Core & Timing", "description": "Primary WAF correlation key across all 3 security event tables"},
    {"name": "country_code", "type": "String", "category": "Client & Network", "description": "GeoIP country code of the client"},
    {"name": "http__hostname", "type": "String", "category": "HTTP Request", "description": "HTTP Host / Virtual Server identifier"},
    {"name": "http__remote_addr", "type": "String", "category": "Client & Network", "description": "Client source IP address"},
    {"name": "http__remote_port", "type": "UInt16", "category": "Client & Network", "description": "Client source TCP port"},
    {"name": "http__request_method", "type": "String", "category": "HTTP Request", "description": "HTTP method (GET, POST, PUT, DELETE, etc.)"},
    {"name": "http__response_code", "type": "String", "category": "HTTP Request", "description": "HTTP response status code or 'Blocked'"},
    {"name": "http__server_port", "type": "UInt16", "category": "Client & Network", "description": "Destination server TCP port"},
    {"name": "http__uri", "type": "String", "category": "HTTP Request", "description": "Requested HTTP URI path"},
    {"name": "http__x_forwarded_for", "type": "String", "category": "Client & Network", "description": "X-Forwarded-For HTTP header value"},
    {"name": "protocol", "type": "String", "category": "HTTP Request", "description": "Application protocol (HTTP, HTTPS, gRPC, etc.)"},
    {"name": "request_outcome", "type": "String", "category": "WAF Verdict", "description": "Outcome of the request (Blocked, Passed, Alerted)"},
    {"name": "request_outcome_reason", "type": "String", "category": "WAF Verdict", "description": "Reason for request outcome (e.g. SECURITY_WAF_VIOLATION)"},
    {"name": "request_status", "type": "String", "category": "WAF Verdict", "description": "Request status (e.g. blocked, passed, alerted)"},
    {"name": "policy_name", "type": "String", "category": "WAF Verdict", "description": "F5 WAF / NGINX App Protect policy name that evaluated the request"},
    {"name": "severity", "type": "String", "category": "WAF Verdict", "description": "Violation severity (critical, error, warning, notice, informational)"},
    {"name": "signature_cves", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated CVE identifiers associated with matched signatures"},
    {"name": "threat_campaign_names", "type": "String", "category": "Signatures & Threats", "description": "Matched threat campaign names"},
    {"name": "client_class", "type": "String", "category": "Bot & Client Defense", "description": "Bot Defense client classification (e.g. Untrusted Bot, Browser)"},
    {"name": "client_application", "type": "String", "category": "Bot & Client Defense", "description": "Detected client application"},
    {"name": "client_application_version", "type": "String", "category": "Bot & Client Defense", "description": "Detected client application version"},
    {"name": "bot_anomalies", "type": "String", "category": "Bot & Client Defense", "description": "Detected bot anomalies"},
    {"name": "bot_category", "type": "String", "category": "Bot & Client Defense", "description": "Bot category (e.g. HTTP Library, Search Engine, Scraper)"},
    {"name": "bot_signature_name", "type": "String", "category": "Bot & Client Defense", "description": "Matched bot signature name (e.g. curl, python-requests)"},
    {"name": "enforced_bot_anomalies", "type": "String", "category": "Bot & Client Defense", "description": "Enforced bot anomalies"},
    {"name": "violation_rating", "type": "UInt8", "category": "Violations", "description": "Numerical violation threat rating (0-5)"},
    {"name": "violations", "type": "String", "category": "Violations", "description": "Comma-separated list of triggered WAF violations"},
    {"name": "sub_violations", "type": "String", "category": "Violations", "description": "Comma-separated list of triggered sub-violations"},
    {"name": "violation_details", "type": "String", "category": "Violations", "description": "Detailed XML/structured violation payload"},
    {"name": "Attack_types", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated attack types associated with the event"},
    {"name": "request", "type": "String", "category": "HTTP Request", "description": "Full raw HTTP request payload"},
    {"name": "enforced_threat_campaign_names", "type": "String", "category": "Signatures & Threats", "description": "Enforced threat campaign names"},
    {"name": "enforced_signature_ids", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated IDs of enforced attack signatures"},
    {"name": "enforced_signature_names", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated names of enforced attack signatures"},
    {"name": "enforced_signature_cves", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated CVEs of enforced attack signatures"},
    {"name": "signature_ids", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated IDs of all triggered attack signatures"},
    {"name": "signature_names", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated names of all triggered attack signatures"},
    {"name": "signature_accuracies", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated accuracies of triggered signatures (high, medium, low)"},
    {"name": "signature_risks", "type": "String", "category": "Signatures & Threats", "description": "Comma-separated risk levels of triggered signatures (high, medium, low)"},
    {"name": "blocking_exception_reason", "type": "String", "category": "WAF Verdict", "description": "Reason for blocking exception if applicable"},
    {"name": "is_truncated_Values", "type": "String", "category": "HTTP Request", "description": "Whether logged request values were truncated"},
    {"name": "db_timestamp", "type": "DateTime", "category": "Core & Timing", "description": "Timestamp when the event was ingested into ClickHouse"},
    {"name": "partition_key", "type": "Date", "category": "Core & Timing", "description": "ClickHouse table partition date (YYYY-MM-DD)"},
    {"name": "violation_contexts", "type": "String", "category": "Violations", "description": "Comma-separated contexts where violations occurred (uri, header, parameter, body, other)"},
    {"name": "field_names", "type": "String", "category": "Violations", "description": "Comma-separated field names associated with violations"},
    {"name": "field_values", "type": "String", "category": "Violations", "description": "Comma-separated field values associated with violations"},
]

V4_VIOLATION_DATA_SCHEMA: List[Dict[str, str]] = [
    {"name": "timestamp", "type": "DateTime", "description": "Event timestamp"},
    {"name": "event_uuid", "type": "String", "description": "Parent event UUID from v4_security_events"},
    {"name": "uuid", "type": "String", "description": "Unique violation row UUID"},
    {"name": "system_id", "type": "String", "description": "System UUID"},
    {"name": "parent_hostname", "type": "String", "description": "Parent hostname"},
    {"name": "system__tags", "type": "String", "description": "System tags"},
    {"name": "instance", "type": "String", "description": "NGINX instance"},
    {"name": "instance_group", "type": "String", "description": "Instance group"},
    {"name": "support_id", "type": "String", "description": "Common correlation key across the 3 tables"},
    {"name": "country_code", "type": "String", "description": "Client country code"},
    {"name": "http__hostname", "type": "String", "description": "HTTP hostname"},
    {"name": "http__remote_addr", "type": "String", "description": "Client IP address"},
    {"name": "request_status", "type": "String", "description": "Request status"},
    {"name": "request_outcome_reason", "type": "String", "description": "Request outcome reason"},
    {"name": "policy_name", "type": "String", "description": "WAF policy name"},
    {"name": "http__request_method", "type": "String", "description": "HTTP request method"},
    {"name": "http__response_code", "type": "String", "description": "HTTP response code"},
    {"name": "severity", "type": "String", "description": "Event severity"},
    {"name": "signature_cves", "type": "String", "description": "Signature CVEs"},
    {"name": "threat_campaign_names", "type": "String", "description": "Threat campaign names"},
    {"name": "http__uri", "type": "String", "description": "HTTP URI"},
    {"name": "client_class", "type": "String", "description": "Client class"},
    {"name": "client_application", "type": "String", "description": "Client application"},
    {"name": "bot_anomalies", "type": "String", "description": "Bot anomalies"},
    {"name": "bot_category", "type": "String", "description": "Bot category"},
    {"name": "bot_signature_name", "type": "String", "description": "Bot signature name"},
    {"name": "signature_names", "type": "String", "description": "Signature names"},
    {"name": "signature_ids", "type": "String", "description": "Signature IDs"},
    {"name": "signature_accuracies", "type": "String", "description": "Signature accuracies"},
    {"name": "signature_risks", "type": "String", "description": "Signature risks"},
    {"name": "violation_rating", "type": "UInt8", "description": "Violation rating"},
    {"name": "violations", "type": "String", "description": "Violation name for this record"},
    {"name": "sub_violations", "type": "String", "description": "Sub-violations"},
    {"name": "violation_context", "type": "String", "description": "Specific violation context (e.g. uri, header, parameter, other)"},
    {"name": "blocking_mask", "type": "String", "description": "Blocking mask bitfield"},
    {"name": "db_timestamp", "type": "DateTime", "description": "Database ingestion timestamp"},
    {"name": "partition_key", "type": "Date", "description": "Partition date key"},
    {"name": "field_name", "type": "String", "description": "Specific field name that triggered this violation"},
    {"name": "field_value", "type": "String", "description": "Specific field value that triggered this violation"},
]

V4_SIGNATURES_DATA_SCHEMA: List[Dict[str, str]] = [
    {"name": "timestamp", "type": "DateTime", "description": "Event timestamp"},
    {"name": "event_uuid", "type": "String", "description": "Parent event UUID from v4_security_events"},
    {"name": "uuid", "type": "String", "description": "Unique signature row UUID"},
    {"name": "system_id", "type": "String", "description": "System UUID"},
    {"name": "parent_hostname", "type": "String", "description": "Parent hostname"},
    {"name": "system__tags", "type": "String", "description": "System tags"},
    {"name": "instance", "type": "String", "description": "NGINX instance"},
    {"name": "instance_group", "type": "String", "description": "Instance group"},
    {"name": "support_id", "type": "String", "description": "Common correlation key across the 3 tables"},
    {"name": "country_code", "type": "String", "description": "Client country code"},
    {"name": "http__hostname", "type": "String", "description": "HTTP hostname"},
    {"name": "http__remote_addr", "type": "String", "description": "Client IP address"},
    {"name": "request_status", "type": "String", "description": "Request status"},
    {"name": "request_outcome_reason", "type": "String", "description": "Request outcome reason"},
    {"name": "policy_name", "type": "String", "description": "WAF policy name"},
    {"name": "http__request_method", "type": "String", "description": "HTTP request method"},
    {"name": "http__response_code", "type": "String", "description": "HTTP response code"},
    {"name": "severity", "type": "String", "description": "Event severity"},
    {"name": "signature_cves", "type": "String", "description": "Signature CVEs"},
    {"name": "threat_campaign_names", "type": "String", "description": "Threat campaign names"},
    {"name": "http__uri", "type": "String", "description": "HTTP URI"},
    {"name": "client_class", "type": "String", "description": "Client class"},
    {"name": "client_application", "type": "String", "description": "Client application"},
    {"name": "bot_anomalies", "type": "String", "description": "Bot anomalies"},
    {"name": "bot_category", "type": "String", "description": "Bot category"},
    {"name": "bot_signature_name", "type": "String", "description": "Bot signature name"},
    {"name": "violation_rating", "type": "UInt8", "description": "Violation rating"},
    {"name": "violations", "type": "String", "description": "Violations list"},
    {"name": "sub_violations", "type": "String", "description": "Sub-violations list"},
    {"name": "signature_id", "type": "String", "description": "Triggered F5 WAF Attack Signature ID (used for policy signature tightening/relaxation)"},
    {"name": "signature_name", "type": "String", "description": "Triggered Attack Signature human-readable name"},
    {"name": "signature_accuracy", "type": "String", "description": "Signature accuracy rating (high, medium, low)"},
    {"name": "signature_risk", "type": "String", "description": "Signature risk rating (high, medium, low)"},
    {"name": "blocking_mask", "type": "UInt8", "description": "Signature blocking mask bitfield"},
    {"name": "buffer", "type": "String", "description": "Matched request buffer snippet where the signature triggered"},
    {"name": "offset", "type": "UInt32", "description": "Byte offset of signature match within the buffer"},
    {"name": "length", "type": "UInt32", "description": "Byte length of signature match within the buffer"},
    {"name": "db_timestamp", "type": "DateTime", "description": "Database ingestion timestamp"},
    {"name": "partition_key", "type": "Date", "description": "Partition date key"},
    {"name": "violation_contexts", "type": "String", "description": "Violation contexts"},
    {"name": "field_names", "type": "String", "description": "Field names"},
    {"name": "field_values", "type": "String", "description": "Field values"},
]

V4_SECURITY_EVENTS_COLUMNS: List[str] = [col["name"] for col in V4_SECURITY_EVENTS_SCHEMA]
V4_VIOLATION_DATA_COLUMNS: List[str] = [col["name"] for col in V4_VIOLATION_DATA_SCHEMA]
V4_SIGNATURES_DATA_COLUMNS: List[str] = [col["name"] for col in V4_SIGNATURES_DATA_SCHEMA]
V4_SECURITY_EVENTS_VIOLATION_DATA_COLUMNS: List[str] = V4_VIOLATION_DATA_COLUMNS
V4_SECURITY_EVENTS_SIGNATURES_DATA_COLUMNS: List[str] = V4_SIGNATURES_DATA_COLUMNS

SUPPORTED_FILTER_OPERATORS: List[Dict[str, str]] = [
    {"id": "contains", "op": "contains", "label": "Contains (case-insensitive)"},
    {"id": "equals", "op": "equals", "label": "Equals (=)"},
    {"id": "not_equals", "op": "not_equals", "label": "Does not equal (!=)"},
    {"id": "not_contains", "op": "not_contains", "label": "Does not contain"},
    {"id": "starts_with", "op": "starts_with", "label": "Starts with"},
    {"id": "ends_with", "op": "ends_with", "label": "Ends with"},
    {"id": "in", "op": "in", "label": "In comma-separated list"},
    {"id": "gt", "op": "gt", "label": "Greater than (>)"},
    {"id": "gte", "op": "gte", "label": "Greater than or equal (>=)"},
    {"id": "lt", "op": "lt", "label": "Less than (<)"},
    {"id": "lte", "op": "lte", "label": "Less than or equal (<=)"},
    {"id": "is_empty", "op": "is_empty", "label": "Is empty or N/A"},
    {"id": "is_not_empty", "op": "is_not_empty", "label": "Is not empty and not N/A"},
]

_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

_COLUMN_ALIASES: Dict[str, str] = {
    "is_truncated": "is_truncated_Values",
    "x_forwarded_for_header_value": "http__x_forwarded_for",
    "uuid": "event_uuid",
    "attack_types": "Attack_types",
}


def _escape_sql_string(val: Any) -> str:
    """Safely escape a string literal for ClickHouse SQL single-quoted string."""
    s = str(val if val is not None else "")
    s = s.replace("\\", "\\\\").replace("'", "\\'").replace("\x00", "")
    return f"'{s}'"


def _validate_column(col: str, allowed: Optional[List[str]] = None) -> str:
    """Validate a column identifier against the allowed list and strict regex."""
    col_clean = (col or "").strip()
    if not _SAFE_IDENTIFIER_RE.match(col_clean):
        raise ValueError(f"Invalid column identifier: {col!r}")
    if allowed is not None and col_clean not in allowed:
        alias_target = _COLUMN_ALIASES.get(col_clean)
        if alias_target and alias_target in allowed:
            return alias_target
        # Case-insensitive fallback match against allowed columns (e.g. Attack_types)
        lower_map = {c.lower(): c for c in allowed}
        if col_clean.lower() in lower_map:
            return lower_map[col_clean.lower()]
        raise ValueError(f"Unknown column '{col_clean}'. Allowed columns: {', '.join(allowed[:10])}...")
    return col_clean


def build_filter_clause(field: str, operator: str, value: Any, allowed_columns: Optional[List[str]] = None) -> str:
    """Build a safe ClickHouse SQL WHERE predicate for a single column filter."""
    col = _validate_column(field, allowed_columns)
    op = (operator or "contains").strip().lower()
    col_str = f"toString(`{col}`)"
    val_str = str(value if value is not None else "").strip()

    if op == "is_empty":
        return f"({col_str} = '' OR {col_str} = 'N/A' OR `{col}` IS NULL)"
    if op == "is_not_empty":
        return f"({col_str} != '' AND {col_str} != 'N/A' AND `{col}` IS NOT NULL)"

    escaped = _escape_sql_string(val_str)

    if op == "equals" or op == "=" or op == "eq":
        return f"lowerUTF8({col_str}) = lowerUTF8({escaped})"
    if op == "not_equals" or op == "!=" or op == "neq":
        return f"lowerUTF8({col_str}) != lowerUTF8({escaped})"
    if op == "contains" or op == "like":
        return f"positionCaseInsensitiveUTF8({col_str}, {escaped}) > 0"
    if op == "not_contains" or op == "not_like":
        return f"positionCaseInsensitiveUTF8({col_str}, {escaped}) = 0"
    if op == "starts_with":
        return f"startsWith(lowerUTF8({col_str}), lowerUTF8({escaped}))"
    if op == "ends_with":
        return f"endsWith(lowerUTF8({col_str}), lowerUTF8({escaped}))"
    if op == "in":
        items = [x.strip() for x in val_str.split(",") if x.strip()]
        if not items:
            return "1 = 1"
        escaped_list = ", ".join(_escape_sql_string(x.lower()) for x in items)
        return f"lowerUTF8({col_str}) IN ({escaped_list})"
    if op in ("gt", "gte", "lt", "lte", ">", ">=", "<", "<="):
        sql_op = {
            "gt": ">", ">": ">",
            "gte": ">=", ">=": ">=",
            "lt": "<", "<": "<",
            "lte": "<=", "<=": "<=",
        }[op]
        if col in ("timestamp", "db_timestamp", "partition_key"):
            return f"{col_str} {sql_op} {escaped}"
        try:
            num_val = float(val_str)
            return f"toFloat64OrZero({col_str}) {sql_op} {num_val}"
        except ValueError:
            return f"{col_str} {sql_op} {escaped}"

    raise ValueError(f"Unsupported filter operator: {operator!r}")


class ClickHouseService:
    """Manages ClickHouse connection config, Redis persistence, event search, 3-table correlation, and WAF policy signature tuning."""

    def __init__(self, transport: Optional[Any] = None) -> None:
        self._transport = transport
        self._config: Dict[str, Any] = {
            "host": settings.clickhouse_host or "",
            "port": int(settings.clickhouse_port or 8123),
            "username": settings.clickhouse_user or "default",
            "password": settings.clickhouse_password or "",
            "database": settings.clickhouse_database or "nms",
            "ssl": bool(settings.clickhouse_ssl),
            "verify_ssl": bool(settings.clickhouse_verify_ssl),
            "updated_at": None,
        }
        self._persisted_in_redis: bool = False
        self._last_error: Optional[str] = None
        self._resolved_database: Optional[str] = None

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

        # Fallback only if storage has not been initialized yet
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
        return f"{prefix}{CLICKHOUSE_REDIS_CONFIG_KEY}"

    def load_config_from_redis(self) -> bool:
        """Load persisted ClickHouse connection configuration from Redis if present."""
        client, prefix = self._get_redis_client_and_prefix()
        if client is None:
            return False
        try:
            raw = client.get(self._redis_key(prefix))
            if not raw:
                return False
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False
            self._apply_config_dict(data)
            self._persisted_in_redis = True
            logger.info(
                "Loaded persisted ClickHouse configuration from Redis (host=%s, port=%s, database=%s)",
                self._config["host"],
                self._config["port"],
                self._config["database"],
            )
            return True
        except Exception as exc:
            logger.warning("Failed to load ClickHouse config from Redis: %s", exc)
            return False

    def _apply_config_dict(self, data: Dict[str, Any]) -> None:
        host = str(data.get("host") if data.get("host") is not None else self._config.get("host", "")).strip()
        # Strip accidental http:// or https:// prefix if user pasted a URL into host
        ssl_flag = data.get("ssl")
        if host.startswith("https://"):
            host = host[len("https://"):].strip("/")
            if ssl_flag is None:
                ssl_flag = True
        elif host.startswith("http://"):
            host = host[len("http://"):].strip("/")
            if ssl_flag is None:
                ssl_flag = False
        # Strip host:port if user included port in host string
        if ":" in host and not host.startswith("["):
            parts = host.rsplit(":", 1)
            if parts[1].isdigit():
                host = parts[0]
                if data.get("port") is None:
                    data["port"] = int(parts[1])

        port = int(data.get("port") or self._config.get("port") or 8123)
        username = str(
            data.get("username")
            if data.get("username") is not None
            else (data.get("user") if data.get("user") is not None else self._config.get("username", "default"))
        ).strip() or "default"

        # Preserve existing password if password is not supplied or masked
        if "password" in data and data["password"] is not None and data["password"] != "********":
            password = str(data["password"])
        else:
            password = self._config.get("password", "")

        database = str(
            data.get("database") if data.get("database") is not None else self._config.get("database", "nms")
        ).strip() or "default"

        ssl = bool(ssl_flag) if ssl_flag is not None else bool(self._config.get("ssl", False))
        verify_ssl = (
            bool(data.get("verify_ssl"))
            if data.get("verify_ssl") is not None
            else bool(self._config.get("verify_ssl", True))
        )

        self._config = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "database": database,
            "ssl": ssl,
            "verify_ssl": verify_ssl,
            "updated_at": data.get("updated_at") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._resolved_database = None

        # Sync to global settings
        settings.clickhouse_host = host
        settings.clickhouse_port = port
        settings.clickhouse_user = username
        settings.clickhouse_password = password
        settings.clickhouse_database = database
        settings.clickhouse_ssl = ssl
        settings.clickhouse_verify_ssl = verify_ssl

    def save_config(self, config_data: Dict[str, Any], persist_to_redis: bool = True) -> Dict[str, Any]:
        """Update ClickHouse connection settings and persist them to Redis across reboots."""
        self._apply_config_dict(config_data)
        self._persisted_in_redis = False

        if persist_to_redis:
            client, prefix = self._get_redis_client_and_prefix()
            if client is not None:
                try:
                    client.set(self._redis_key(prefix), json.dumps(self._config, ensure_ascii=False))
                    self._persisted_in_redis = True
                    logger.info(
                        "Persisted ClickHouse configuration to Redis key '%s'",
                        self._redis_key(prefix),
                    )
                except Exception as exc:
                    logger.warning("Could not persist ClickHouse config to Redis: %s", exc)

        return self.get_config(include_password=False)

    def get_config(self, include_password: bool = False) -> Dict[str, Any]:
        """Return the current ClickHouse configuration."""
        cfg = dict(self._config)
        cfg["has_password"] = bool(cfg.get("password"))
        cfg["persisted_in_redis"] = self._persisted_in_redis
        cfg["configured"] = bool(cfg.get("host"))
        if not include_password:
            cfg.pop("password", None)
        return cfg

    def is_configured(self) -> bool:
        return bool((self._config.get("host") or "").strip())

    def _build_base_url(self, override_config: Optional[Dict[str, Any]] = None) -> str:
        cfg = override_config or self._config
        host = (cfg.get("host") or "").strip()
        if not host:
            raise ConnectionError("ClickHouse host/IP address is not configured.")
        port = int(cfg.get("port") or 8123)
        scheme = "https" if cfg.get("ssl") else "http"
        return f"{scheme}://{host}:{port}/"

    def execute_query(
        self,
        sql: str,
        database: Optional[str] = None,
        override_config: Optional[Dict[str, Any]] = None,
        timeout: float = 15.0,
        use_json_format: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a SQL query against the ClickHouse HTTP(S) interface and return parsed JSON.
        Automatically appends FORMAT JSON and preserves 64-bit integer strings (e.g. support_id).
        """
        cfg = dict(self._config)
        if override_config:
            for k, v in override_config.items():
                if v is not None and not (k == "password" and v == "********"):
                    cfg[k] = v

        base_url = self._build_base_url(cfg)
        query_sql = sql.strip().rstrip(";")
        if use_json_format and not re.search(r"\bFORMAT\s+\w+$", query_sql, re.IGNORECASE):
            query_sql = f"{query_sql} FORMAT JSON"

        params: Dict[str, Any] = {
            "output_format_json_quote_64bit_integers": 1,
        }
        db_to_use = database if database is not None else (self._resolved_database or cfg.get("database"))
        if db_to_use:
            params["database"] = db_to_use

        headers: Dict[str, str] = {
            "Content-Type": "text/plain; charset=utf-8",
        }
        user = (cfg.get("username") or cfg.get("user") or "default").strip()
        password = cfg.get("password") or ""
        if user:
            headers["X-ClickHouse-User"] = user
        if password:
            headers["X-ClickHouse-Key"] = password

        # NOTE: Do NOT pass `auth=(user, password)` to httpx alongside X-ClickHouse-* headers.
        # ClickHouse 24.9+ rejects requests that send both X-ClickHouse-* and Authorization
        # headers simultaneously with HTTP 403 Code 516 (AUTHENTICATION_FAILED).
        verify_ssl = bool(cfg.get("verify_ssl", True)) if cfg.get("ssl") else True

        client_kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "verify": verify_ssl,
            "trust_env": False,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.post(
                    base_url,
                    params=params,
                    headers=headers,
                    content=query_sql.encode("utf-8"),
                )
        except Exception as exc:
            self._last_error = f"ClickHouse connection failed ({base_url}): {exc}"
            raise ConnectionError(self._last_error) from exc

        if resp.status_code >= 400:
            err_body = resp.text.strip()
            self._last_error = f"ClickHouse HTTP {resp.status_code}: {err_body[:500]}"
            raise RuntimeError(self._last_error)

        self._last_error = None
        if not use_json_format:
            return {"raw": resp.text}

        try:
            return resp.json()
        except Exception as exc:
            raise RuntimeError(f"Failed to parse ClickHouse JSON response: {exc}") from exc

    def resolve_tables_database(self, override_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Discover which ClickHouse database contains the NGINX Instance Manager
        v4_security_events tables (e.g. 'nms' or 'default').
        """
        cfg = dict(self._config)
        if override_config:
            cfg.update({k: v for k, v in override_config.items() if v is not None and v != "********"})

        configured_db = (cfg.get("database") or "nms").strip()
        try:
            res = self.execute_query(
                "SELECT database, name FROM system.tables "
                "WHERE name IN ('v4_security_events', 'v4_security_events_violation_data', 'v4_security_events_signatures_data')",
                database="",
                override_config=cfg,
            )
            rows = res.get("data", [])
            db_tables: Dict[str, List[str]] = {}
            for r in rows:
                db_name = r.get("database", "")
                tbl_name = r.get("name", "")
                if db_name and tbl_name:
                    db_tables.setdefault(db_name, []).append(tbl_name)

            if configured_db in db_tables:
                self._resolved_database = configured_db
                return configured_db
            # If the tables exist in another database (e.g. 'nms' or 'default'), use the one that has v4_security_events
            for db_name, tbls in db_tables.items():
                if "v4_security_events" in tbls:
                    self._resolved_database = db_name
                    return db_name
        except Exception:
            pass

        return configured_db

    def test_connection(self, override_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Test connectivity to ClickHouse and verify the 3 WAF security event tables."""
        cfg = dict(self._config)
        if override_config:
            for k, v in override_config.items():
                if v is not None and not (k == "password" and v == "********"):
                    cfg[k] = v

        if not (cfg.get("host") or "").strip():
            return {
                "connected": False,
                "configured": False,
                "error": "ClickHouse host/IP address is not configured.",
                "config": self.get_config(include_password=False),
            }

        try:
            version_res = self.execute_query(
                "SELECT version() AS version, currentDatabase() AS current_db",
                database="",
                override_config=cfg,
                timeout=8.0,
            )
            version_rows = version_res.get("data", [])
            ch_version = version_rows[0].get("version", "unknown") if version_rows else "unknown"

            resolved_db = self.resolve_tables_database(override_config=cfg)
            tables_res = self.execute_query(
                "SELECT name, total_rows FROM system.tables "
                f"WHERE database = {_escape_sql_string(resolved_db)} "
                "AND name IN ('v4_security_events', 'v4_security_events_violation_data', 'v4_security_events_signatures_data')",
                database="",
                override_config=cfg,
                timeout=8.0,
            )
            found_tables: Dict[str, Any] = {}
            for row in tables_res.get("data", []):
                found_tables[row["name"]] = row.get("total_rows")

            required_tables = [
                "v4_security_events",
                "v4_security_events_violation_data",
                "v4_security_events_signatures_data",
            ]
            missing_tables = [t for t in required_tables if t not in found_tables]
            tables_info = {
                t: {
                    "exists": t in found_tables,
                    "row_count": found_tables.get(t),
                }
                for t in required_tables
            }

            return {
                "connected": True,
                "configured": True,
                "version": ch_version,
                "database": resolved_db,
                "tables": tables_info,
                "all_tables_present": len(missing_tables) == 0,
                "missing_tables": missing_tables,
                "persisted_in_redis": self._persisted_in_redis,
                "config": self.get_config(include_password=False),
            }
        except Exception as exc:
            return {
                "connected": False,
                "configured": True,
                "error": str(exc),
                "persisted_in_redis": self._persisted_in_redis,
                "config": self.get_config(include_password=False),
            }

    def get_status(self, check_live: bool = False) -> Dict[str, Any]:
        """Return ClickHouse configuration and connection status."""
        if not self.is_configured():
            self.load_config_from_redis()
        if check_live and self.is_configured():
            return self.test_connection()
        return {
            "connected": self._last_error is None and self.is_configured(),
            "configured": self.is_configured(),
            "error": self._last_error,
            "persisted_in_redis": self._persisted_in_redis,
            "config": self.get_config(include_password=False),
        }

    def search_security_events(
        self,
        global_search: Optional[str] = None,
        field_filters: Optional[List[Dict[str, Any]]] = None,
        exact_columns: Optional[Dict[str, Any]] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        sort_by: str = "timestamp",
        sort_order: str = "DESC",
        limit: int = 50,
        offset: int = 0,
        include_correlations: bool = False,
    ) -> Dict[str, Any]:
        """
        Search and filter across ALL 53 fields of v4_security_events.
        Supports:
          - global_search: substring search across key or all columns in v4_security_events
          - field_filters: list of {"field"|"column": <column>, "operator": <op>, "value": <val>} across all 53 columns
          - exact_columns: dict of {column_name: substring_or_value} quick filters
          - start_time / end_time: timestamp range bounds
          - pagination (limit, offset) and sorting (sort_by, sort_order)
        """
        if not self.is_configured():
            self.load_config_from_redis()
        if not self.is_configured():
            raise ConnectionError("ClickHouse connection is not configured. Please configure ClickHouse IP, port, username, and password.")

        db = self.resolve_tables_database()
        where_clauses: List[str] = []

        # 1. Global free-text search across all 53 fields in v4_security_events
        if global_search and str(global_search).strip():
            q_escaped = _escape_sql_string(str(global_search).strip())
            or_parts = [
                f"positionCaseInsensitiveUTF8(toString(`{col}`), {q_escaped}) > 0"
                for col in V4_SECURITY_EVENTS_COLUMNS
            ]
            where_clauses.append("(" + " OR ".join(or_parts) + ")")

        # 2. Structured field_filters across any of the 53 columns
        if field_filters:
            for flt in field_filters:
                if not isinstance(flt, dict):
                    continue
                f_name = (flt.get("field") or flt.get("column") or "").strip()
                f_op = (flt.get("operator") or "contains").strip()
                f_val = flt.get("value")
                if not f_name:
                    continue
                if f_op not in ("is_empty", "is_not_empty") and (f_val is None or str(f_val).strip() == ""):
                    continue
                clause = build_filter_clause(f_name, f_op, f_val, V4_SECURITY_EVENTS_COLUMNS)
                where_clauses.append(clause)

        # 3. Quick column filters (exact_columns map)
        if exact_columns and isinstance(exact_columns, dict):
            for col_name, col_val in exact_columns.items():
                if col_val is None or str(col_val).strip() == "":
                    continue
                col_clean = _validate_column(col_name, V4_SECURITY_EVENTS_COLUMNS)
                where_clauses.append(build_filter_clause(col_clean, "contains", col_val, V4_SECURITY_EVENTS_COLUMNS))

        # 4. Time window bounds
        if start_time and str(start_time).strip():
            where_clauses.append(f"toString(`timestamp`) >= {_escape_sql_string(str(start_time).strip())}")
        if end_time and str(end_time).strip():
            where_clauses.append(f"toString(`timestamp`) <= {_escape_sql_string(str(end_time).strip())}")

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        sort_col = _validate_column(sort_by or "timestamp", V4_SECURITY_EVENTS_COLUMNS)
        sort_dir = "ASC" if (sort_order or "DESC").strip().upper() == "ASC" else "DESC"
        safe_limit = max(1, min(int(limit or 50), 500))
        safe_offset = max(0, int(offset or 0))

        count_sql = f"SELECT count() AS total FROM `{db}`.`v4_security_events` {where_sql}"
        data_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events` "
            f"{where_sql} "
            f"ORDER BY `{sort_col}` {sort_dir} "
            f"LIMIT {safe_limit} OFFSET {safe_offset}"
        )

        try:
            count_res = self.execute_query(count_sql, database=db)
        except Exception as exc:
            # If the ClickHouse version has a slightly different column subset in v4_security_events,
            # dynamically introspect system.columns and rebuild the global_search clause.
            if global_search and ("Missing columns" in str(exc) or "UNKNOWN_IDENTIFIER" in str(exc)):
                cols_res = self.execute_query(
                    f"SELECT name FROM system.columns WHERE database = {_escape_sql_string(db)} AND table = 'v4_security_events'",
                    database=db,
                )
                live_cols = [
                    r["name"]
                    for r in cols_res.get("data", [])
                    if isinstance(r, dict) and r.get("name") and _SAFE_IDENTIFIER_RE.match(str(r["name"]))
                ]
                if live_cols:
                    q_escaped = _escape_sql_string(str(global_search).strip())
                    where_clauses[0] = "(" + " OR ".join(
                        f"positionCaseInsensitiveUTF8(toString(`{col}`), {q_escaped}) > 0"
                        for col in live_cols
                    ) + ")"
                    where_sql = "WHERE " + " AND ".join(where_clauses)
                    count_sql = f"SELECT count() AS total FROM `{db}`.`v4_security_events` {where_sql}"
                    data_sql = (
                        f"SELECT * FROM `{db}`.`v4_security_events` "
                        f"{where_sql} "
                        f"ORDER BY `{sort_col}` {sort_dir} "
                        f"LIMIT {safe_limit} OFFSET {safe_offset}"
                    )
                    count_res = self.execute_query(count_sql, database=db)
                else:
                    raise
            else:
                raise

        total_rows = 0
        if count_res.get("data"):
            total_rows = int(count_res["data"][0].get("total", 0))

        data_res = self.execute_query(data_sql, database=db)
        events: List[Dict[str, Any]] = data_res.get("data", [])

        # Normalize support_id to string to preserve 64-bit precision
        for ev in events:
            if "support_id" in ev and ev["support_id"] is not None:
                ev["support_id"] = str(ev["support_id"])

        correlations_by_support_id: Dict[str, Any] = {}
        if include_correlations and events:
            support_ids = list({ev.get("support_id") for ev in events if ev.get("support_id")})
            if support_ids:
                correlations_by_support_id = self.batch_correlate_events(support_ids, database=db)

        return {
            "total": total_rows,
            "limit": safe_limit,
            "offset": safe_offset,
            "database": db,
            "query": data_sql,
            "query_where": where_sql,
            "rows": events,
            "events": events,
            "correlations": correlations_by_support_id if include_correlations else None,
        }

    def get_correlated_event(
        self,
        support_id: str,
        target_policy_name: Optional[str] = None,
        database: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Correlate all 3 ClickHouse tables using `support_id` as the join key:
          1. v4_security_events
          2. v4_security_events_violation_data
          3. v4_security_events_signatures_data
        Also cross-references every triggered `signature_id` from v4_security_events_signatures_data
        against the selected WAF policy in F5 WAF Policy Manager so the user can see and toggle
        its enabled/disabled state.
        """
        if not self.is_configured():
            self.load_config_from_redis()
        if not self.is_configured():
            raise ConnectionError("ClickHouse connection is not configured.")

        sid_clean = str(support_id or "").strip()
        if not sid_clean:
            raise ValueError("support_id is required for correlation")

        db = database or self.resolve_tables_database()
        sid_escaped = _escape_sql_string(sid_clean)

        events_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events` "
            f"WHERE toString(`support_id`) = {sid_escaped} "
            f"ORDER BY `timestamp` DESC LIMIT 50"
        )
        violations_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events_violation_data` "
            f"WHERE toString(`support_id`) = {sid_escaped} "
            f"ORDER BY `timestamp` DESC LIMIT 200"
        )
        signatures_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events_signatures_data` "
            f"WHERE toString(`support_id`) = {sid_escaped} "
            f"ORDER BY `timestamp` DESC LIMIT 200"
        )

        events_rows = self.execute_query(events_sql, database=db).get("data", [])
        violation_rows = self.execute_query(violations_sql, database=db).get("data", [])
        signature_rows = self.execute_query(signatures_sql, database=db).get("data", [])

        for row in events_rows + violation_rows + signature_rows:
            if "support_id" in row and row["support_id"] is not None:
                row["support_id"] = str(row["support_id"])
            if "signature_id" in row and row["signature_id"] is not None:
                row["signature_id"] = str(row["signature_id"])

        # Extract the violation's own policy_name from the ClickHouse rows
        log_policy_name: Optional[str] = None
        for r in events_rows + signature_rows + violation_rows:
            pname = (r.get("policy_name") or "").strip()
            if pname and pname != "N/A":
                log_policy_name = pname
                break

        matched_log_policy = self._find_matching_policy_name(log_policy_name) if log_policy_name else None

        # Determine which WAF policy to inspect for current signature override states
        inferred_policy_name = target_policy_name or matched_log_policy or log_policy_name

        matched_policy = self._find_matching_policy_name(inferred_policy_name) if inferred_policy_name else None
        policy_sig_states = self.get_policy_signature_states(inferred_policy_name) if inferred_policy_name else {}

        # Enrich each signature row with its current override state in the target WAF policy
        unique_signatures: Dict[str, Dict[str, Any]] = {}
        correlated_sig_states: Dict[str, Dict[str, Any]] = dict(policy_sig_states)
        for sig_row in signature_rows:
            sig_id_str = str(sig_row.get("signature_id", "")).strip()
            default_state = {
                "signatureId": int(sig_id_str) if sig_id_str.isdigit() else sig_id_str,
                "in_policy": False,
                "status": "default",
                "enabled": None,
                "tag": None,
            }
            state_info = policy_sig_states.get(sig_id_str, default_state)
            sig_row["policy_override"] = state_info
            if sig_id_str and sig_id_str != "N/A":
                correlated_sig_states.setdefault(sig_id_str, state_info)
                if sig_id_str not in unique_signatures:
                    unique_signatures[sig_id_str] = {
                        "signature_id": sig_id_str,
                        "signature_name": sig_row.get("signature_name", ""),
                        "signature_accuracy": sig_row.get("signature_accuracy", ""),
                        "signature_risk": sig_row.get("signature_risk", ""),
                        "blocking_mask": sig_row.get("blocking_mask", ""),
                        "buffer": sig_row.get("buffer", ""),
                        "offset": sig_row.get("offset", ""),
                        "length": sig_row.get("length", ""),
                        "violation_contexts": sig_row.get("violation_contexts", ""),
                        "field_names": sig_row.get("field_names", ""),
                        "field_values": sig_row.get("field_values", ""),
                        "policy_name": sig_row.get("policy_name", ""),
                        "support_id": sid_clean,
                        "policy_override": state_info,
                    }

        return {
            "support_id": sid_clean,
            "database": db,
            "log_policy_name": log_policy_name,
            "matched_log_policy_name": matched_log_policy,
            "target_policy_name": inferred_policy_name,
            "policy_found": bool(matched_policy),
            "matched_policy_name": matched_policy,
            "matched_policy_key": matched_policy,
            "security_events": events_rows,
            "violation_data": violation_rows,
            "signatures_data": signature_rows,
            "unique_signatures": list(unique_signatures.values()),
            "policy_signature_states": correlated_sig_states,
            "counts": {
                "security_events": len(events_rows),
                "violation_data": len(violation_rows),
                "signatures_data": len(signature_rows),
                "unique_signatures": len(unique_signatures),
            },
        }

    def batch_correlate_events(
        self,
        support_ids: List[str],
        target_policy_name: Optional[str] = None,
        database: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Correlate multiple support_ids in a single batch query against
        v4_security_events_violation_data and v4_security_events_signatures_data.
        """
        clean_ids = [str(s).strip() for s in support_ids if s and str(s).strip()]
        if not clean_ids:
            return {}

        db = database or self.resolve_tables_database()
        in_list = ", ".join(_escape_sql_string(s) for s in clean_ids[:100])

        violations_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events_violation_data` "
            f"WHERE toString(`support_id`) IN ({in_list}) "
            f"ORDER BY `timestamp` DESC LIMIT 1000"
        )
        signatures_sql = (
            f"SELECT * FROM `{db}`.`v4_security_events_signatures_data` "
            f"WHERE toString(`support_id`) IN ({in_list}) "
            f"ORDER BY `timestamp` DESC LIMIT 1000"
        )

        violation_rows = self.execute_query(violations_sql, database=db).get("data", [])
        signature_rows = self.execute_query(signatures_sql, database=db).get("data", [])

        policy_sig_states = self.get_policy_signature_states(target_policy_name) if target_policy_name else {}

        grouped: Dict[str, Dict[str, Any]] = {
            sid: {"support_id": sid, "violation_data": [], "signatures_data": []}
            for sid in clean_ids
        }

        for v_row in violation_rows:
            sid = str(v_row.get("support_id", ""))
            v_row["support_id"] = sid
            if sid in grouped:
                grouped[sid]["violation_data"].append(v_row)

        for s_row in signature_rows:
            sid = str(s_row.get("support_id", ""))
            sig_id_str = str(s_row.get("signature_id", "")).strip()
            s_row["support_id"] = sid
            s_row["signature_id"] = sig_id_str
            s_row["policy_override"] = policy_sig_states.get(
                sig_id_str, {"in_policy": False, "status": "default", "enabled": None, "tag": None}
            )
            if sid in grouped:
                grouped[sid]["signatures_data"].append(s_row)

        return grouped

    # -----------------------------------------------------------------------
    # WAF Policy Signature Tightening / Fine-Tuning Helpers
    # -----------------------------------------------------------------------

    def _find_matching_policy_name(self, policy_name: Optional[str]) -> Optional[str]:
        """
        Resolve a policy name from ClickHouse (e.g. 'nms_app_protect_default_policy')
        to a stored policy key in F5 WAF Policy Manager (exact match, case-insensitive match,
        or matching internal policy.name).
        """
        if not policy_name:
            return None
        from ..storage import get_storage
        storage = get_storage()
        target = policy_name.strip()

        # 1. Direct key lookup
        if storage.policy_exists(target):
            return target

        # 2. Match against list_policies() key name or internal policy.name
        try:
            policies = storage.list_policies()
            for p in policies:
                key_name = p.get("name", "")
                internal_name = p.get("policy_name", "")
                if key_name.lower() == target.lower() or internal_name.lower() == target.lower():
                    return key_name
        except Exception:
            pass
        return None

    def get_policy_signature_states(
        self,
        policy_name: Optional[str],
        requested_signature_ids: Optional[List[Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return a mapping of {str(signatureId): {"in_policy": bool, "status": "enabled"|"disabled"|"default", "enabled": bool|None, "tag": str}}
        for all signature overrides configured in the specified WAF policy.
        """
        resolved_name = self._find_matching_policy_name(policy_name)
        states: Dict[str, Dict[str, Any]] = {}

        if resolved_name:
            from ..storage import get_storage
            storage = get_storage()
            policy_doc = storage.get_policy(resolved_name)
            if isinstance(policy_doc, dict) and "policy" in policy_doc:
                signatures = policy_doc.get("policy", {}).get("signatures", [])
                if isinstance(signatures, list):
                    for sig in signatures:
                        if not isinstance(sig, dict):
                            continue
                        sig_id = sig.get("signatureId")
                        if sig_id is None:
                            continue
                        enabled = bool(sig.get("enabled", True))
                        states[str(sig_id)] = {
                            "signatureId": int(sig_id) if str(sig_id).isdigit() else sig_id,
                            "in_policy": True,
                            "status": "enabled" if enabled else "disabled",
                            "enabled": enabled,
                            "tag": sig.get("tag") or "",
                        }

        if requested_signature_ids:
            for req_id in requested_signature_ids:
                req_str = str(req_id).strip()
                if req_str and req_str not in states:
                    states[req_str] = {
                        "signatureId": int(req_str) if req_str.isdigit() else req_str,
                        "in_policy": False,
                        "status": "default",
                        "enabled": None,
                        "tag": None,
                    }

        return states

    def _persist_policy_to_redis_for_github(
        self,
        resolved_name: str,
        policy_doc: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Save the WAF policy to the active storage AND explicitly persist it to Redis
        (as a dirty draft marked for GitHub commit) so that the user can commit it
        to GitHub from the "WAF Policies" page even if they tuned it from the
        Violation Logs & Tuning inspector or when switching storage modes.
        """
        from ..storage import get_storage, get_local_storage

        storage = get_storage()
        local_store = get_local_storage()

        # 1. Save through active storage backend (handles GitHubStorageBackend or local store)
        storage.save_policy(resolved_name, policy_doc)

        # 2. Ensure local_store (Redis if connected, or Memory fallback) also holds the latest
        #    policy and metadata with uncommitted_changes=True so it is ready to commit to GitHub.
        persisted_in_redis = False
        try:
            if local_store is not storage:
                local_store.save_policy(resolved_name, policy_doc)
        except Exception:
            pass

        # 3. Mark dirty in GitHubStorageBackend if active, AND directly in Redis dirty-set + meta cache
        #    so whether GitHub is currently active or configured, the policy shows "Modified (in Redis)"
        #    and has its "Commit to GitHub" button enabled on the WAF Policies page.
        if hasattr(storage, "_mark_dirty"):
            try:
                storage._mark_dirty(resolved_name)
            except Exception:
                pass

        redis_client, prefix = self._get_redis_client_and_prefix()
        if redis_client is not None:
            try:
                raw_json = json.dumps(policy_doc, indent=2, ensure_ascii=False)
                redis_client.set(f"{prefix}{resolved_name}", raw_json)
                redis_client.sadd(f"{prefix}__github_dirty_policies__", resolved_name)
                meta_key = f"{prefix}__meta__:{resolved_name}"
                raw_meta = redis_client.get(meta_key)
                if raw_meta:
                    try:
                        meta = json.loads(raw_meta)
                        if isinstance(meta, dict):
                            meta["uncommitted_changes"] = True
                            meta["status"] = "modified"
                            meta["saved_to"] = "redis"
                            redis_client.set(meta_key, json.dumps(meta, ensure_ascii=False))
                    except Exception:
                        pass
                persisted_in_redis = True
            except Exception:
                pass

        # Also update in-memory metadata cache if local_store is MemoryStorageBackend
        if hasattr(local_store, "_meta_cache") and isinstance(getattr(local_store, "_meta_cache", None), dict):
            meta_entry = local_store._meta_cache.get(resolved_name)
            if isinstance(meta_entry, dict):
                meta_entry["uncommitted_changes"] = True
                meta_entry["status"] = "modified"
                meta_entry["saved_to"] = "redis" if persisted_in_redis else "local"

        return {
            "saved": True,
            "persisted_in_redis": persisted_in_redis,
            "uncommitted_changes": True,
            "status": "modified",
        }

    def save_tuned_policy_to_redis(
        self,
        policy_name: str,
        signatures: Optional[List[Dict[str, Any]]] = None,
        support_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Explicitly save a fine-tuned WAF policy to Redis (optionally applying any pending
        signature overrides first) and mark it as having uncommitted changes so it can be
        committed to GitHub from the "WAF Policies" page.
        """
        from ..storage import get_storage

        if not policy_name or not str(policy_name).strip():
            raise ValueError("policy_name is required")

        if signatures:
            bulk_res = self.bulk_tune_policy_signatures(
                policy_name=policy_name,
                signatures=signatures,
                support_id=support_id,
            )
            resolved_name = bulk_res["policy_name"]
        else:
            resolved_name = self._find_matching_policy_name(policy_name) or policy_name.strip()

        storage = get_storage()
        policy_doc = storage.get_policy(resolved_name)
        if not isinstance(policy_doc, dict) or "policy" not in policy_doc:
            raise KeyError(f"WAF policy '{policy_name}' not found in storage")

        persist_info = self._persist_policy_to_redis_for_github(resolved_name, policy_doc)
        sigs = policy_doc.get("policy", {}).get("signatures", [])
        sig_count = len(sigs) if isinstance(sigs, list) else 0

        return {
            "policy_name": resolved_name,
            "saved": True,
            "persisted_in_redis": persist_info["persisted_in_redis"],
            "uncommitted_changes": True,
            "status": "modified",
            "total_signature_overrides": sig_count,
            "message": (
                f"Policy '{resolved_name}' saved to Redis ({sig_count} signature override(s)) "
                f"and marked ready to commit to GitHub from the WAF Policies page."
            ),
        }

    def tune_policy_signature(
        self,
        policy_name: str,
        signature_id: Any,
        enabled: Optional[bool],
        signature_name: Optional[str] = None,
        support_id: Optional[str] = None,
        tag: Optional[str] = None,
        action: str = "set",
    ) -> Dict[str, Any]:
        """
        Fine-tune a WAF policy by enabling, disabling, or removing a signature_id override
        in `policy.signatures`.
        - action == "set" (default): sets `{"signatureId": int(signature_id), "enabled": bool(enabled), "tag": ...}`
        - action == "remove" or enabled is None: removes the override for `signature_id` from `policy.signatures`
        """
        from ..storage import get_storage
        storage = get_storage()

        resolved_name = self._find_matching_policy_name(policy_name) or policy_name.strip()
        policy_doc = storage.get_policy(resolved_name)
        if not isinstance(policy_doc, dict) or "policy" not in policy_doc:
            raise KeyError(f"WAF policy '{policy_name}' not found in storage")

        sig_str = str(signature_id).strip()
        if not sig_str or sig_str == "N/A":
            raise ValueError(f"Invalid signature_id: {signature_id!r}")

        try:
            sig_int: Any = int(sig_str)
        except ValueError:
            raise ValueError(f"signature_id must be a numeric ID, got {signature_id!r}")

        pol = policy_doc["policy"]
        if "signatures" not in pol or not isinstance(pol["signatures"], list):
            pol["signatures"] = []

        sigs: List[Dict[str, Any]] = pol["signatures"]

        if action == "remove" or enabled is None:
            before_len = len(sigs)
            pol["signatures"] = [
                s for s in sigs
                if not (isinstance(s, dict) and str(s.get("signatureId")) == str(sig_int) and not s.get("name"))
            ]
            removed = len(pol["signatures"]) < before_len
            persist_info = self._persist_policy_to_redis_for_github(resolved_name, policy_doc)
            state_obj = {
                "signatureId": sig_int,
                "in_policy": False,
                "status": "default",
                "enabled": None,
                "tag": None,
            }
            return {
                "policy_name": resolved_name,
                "signature_id": sig_int,
                "action": "removed",
                "removed": removed,
                "override": state_obj,
                "signature_state": state_obj,
                "total_signature_overrides": len(pol["signatures"]),
                "persisted_in_redis": persist_info["persisted_in_redis"],
                "uncommitted_changes": True,
            }

        # Build human-readable tag for auditability in policy.signatures
        computed_tag = (tag or "").strip()
        if not computed_tag:
            parts: List[str] = []
            if signature_name and signature_name != "N/A":
                parts.append(str(signature_name).strip())
            if support_id:
                parts.append(f"support_id={support_id}")
            computed_tag = " | ".join(parts) if parts else f"Tuned signature {sig_int}"

        updated_existing = False
        target_entry: Dict[str, Any] = {
            "signatureId": sig_int,
            "enabled": bool(enabled),
            "tag": computed_tag,
        }

        for existing in sigs:
            if isinstance(existing, dict) and str(existing.get("signatureId")) == str(sig_int) and not existing.get("name"):
                existing["signatureId"] = sig_int
                existing["enabled"] = bool(enabled)
                if computed_tag:
                    existing["tag"] = computed_tag
                target_entry = existing
                updated_existing = True
                break

        if not updated_existing:
            sigs.append(target_entry)

        persist_info = self._persist_policy_to_redis_for_github(resolved_name, policy_doc)

        state_obj = {
            "signatureId": sig_int,
            "in_policy": True,
            "status": "enabled" if enabled else "disabled",
            "enabled": bool(enabled),
            "tag": target_entry.get("tag", ""),
        }
        return {
            "policy_name": resolved_name,
            "signature_id": sig_int,
            "action": "updated" if updated_existing else "added",
            "enabled": bool(enabled),
            "override": state_obj,
            "signature_state": state_obj,
            "total_signature_overrides": len(pol["signatures"]),
            "persisted_in_redis": persist_info["persisted_in_redis"],
            "uncommitted_changes": True,
        }

    def bulk_tune_policy_signatures(
        self,
        policy_name: str,
        signatures: List[Dict[str, Any]],
        support_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Apply multiple signature enable/disable overrides to a WAF policy in a single atomic save.
        Each item in `signatures` specifies `signature_id`, `enabled` (bool or None to remove),
        and optional `signature_name` / `tag`.
        """
        from ..storage import get_storage
        storage = get_storage()

        resolved_name = self._find_matching_policy_name(policy_name) or policy_name.strip()
        policy_doc = storage.get_policy(resolved_name)
        if not isinstance(policy_doc, dict) or "policy" not in policy_doc:
            raise KeyError(f"WAF policy '{policy_name}' not found in storage")

        pol = policy_doc["policy"]
        if "signatures" not in pol or not isinstance(pol["signatures"], list):
            pol["signatures"] = []

        results: List[Dict[str, Any]] = []
        updated_items: List[Dict[str, Any]] = []
        for item in signatures:
            sig_raw = item.get("signature_id") or item.get("signatureId")
            if sig_raw is None or str(sig_raw).strip() in ("", "N/A"):
                continue
            sig_int = int(str(sig_raw).strip())
            enabled = item.get("enabled")
            action = item.get("action", "set")
            sig_name = item.get("signature_name") or item.get("name") or ""
            item_sid = item.get("support_id") or support_id
            tag = (item.get("tag") or "").strip()

            if action == "remove" or enabled is None:
                pol["signatures"] = [
                    s for s in pol["signatures"]
                    if not (isinstance(s, dict) and str(s.get("signatureId")) == str(sig_int) and not s.get("name"))
                ]
                state_obj = {
                    "signatureId": sig_int,
                    "signature_id": sig_int,
                    "in_policy": False,
                    "status": "default",
                    "enabled": None,
                    "tag": None,
                }
                results.append(state_obj)
                updated_items.append({"signature_id": sig_int, "state": state_obj})
                continue

            if not tag:
                parts = []
                if sig_name and sig_name != "N/A":
                    parts.append(str(sig_name).strip())
                if item_sid:
                    parts.append(f"support_id={item_sid}")
                tag = " | ".join(parts) if parts else f"Tuned signature {sig_int}"

            found = False
            for existing in pol["signatures"]:
                if isinstance(existing, dict) and str(existing.get("signatureId")) == str(sig_int) and not existing.get("name"):
                    existing["signatureId"] = sig_int
                    existing["enabled"] = bool(enabled)
                    if tag:
                        existing["tag"] = tag
                    found = True
                    break
            if not found:
                pol["signatures"].append({
                    "signatureId": sig_int,
                    "enabled": bool(enabled),
                    "tag": tag,
                })
            state_obj = {
                "signatureId": sig_int,
                "signature_id": sig_int,
                "in_policy": True,
                "status": "enabled" if enabled else "disabled",
                "enabled": bool(enabled),
                "tag": tag,
            }
            results.append(state_obj)
            updated_items.append({"signature_id": sig_int, "state": state_obj})

        persist_info = self._persist_policy_to_redis_for_github(resolved_name, policy_doc)
        return {
            "policy_name": resolved_name,
            "updated_count": len(results),
            "results": results,
            "updated": updated_items,
            "total_signature_overrides": len(pol["signatures"]),
            "persisted_in_redis": persist_info["persisted_in_redis"],
            "uncommitted_changes": True,
        }


_clickhouse_service: Optional[ClickHouseService] = None


def get_clickhouse_service() -> ClickHouseService:
    """Return the singleton ClickHouseService instance."""
    global _clickhouse_service
    if _clickhouse_service is None:
        _clickhouse_service = ClickHouseService()
        _clickhouse_service.load_config_from_redis()
    return _clickhouse_service


def set_clickhouse_service(service: ClickHouseService) -> None:
    """Override the singleton ClickHouseService instance (used in unit tests)."""
    global _clickhouse_service
    _clickhouse_service = service
