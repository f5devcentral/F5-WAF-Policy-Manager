"""
Tests for ClickHouse Violation Logs Search, 3-Table support_id Correlation,
Redis Config Persistence, and WAF Policy Signature Fine-Tuning.
"""

from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from f5_waf_editor.app import app
from f5_waf_editor.storage import init_storage
from f5_waf_editor.storage.clickhouse_service import (
    CLICKHOUSE_CONFIG_REDIS_KEY,
    V4_SECURITY_EVENTS_COLUMNS,
    V4_SECURITY_EVENTS_SIGNATURES_DATA_COLUMNS,
    V4_SECURITY_EVENTS_VIOLATION_DATA_COLUMNS,
    ClickHouseService,
    get_clickhouse_service,
)


# Sample records matching the exact NGINX Instance Manager ClickHouse tables
SAMPLE_SUPPORT_ID = "10134279319999872904"

SAMPLE_V4_SECURITY_EVENT = {
    "timestamp": "2026-10-16 12:04:33",
    "event_uuid": "86411230-4cea-4a8a-8061-3bf552344f3a",
    "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
    "parent_hostname": "8ad15599fa4d",
    "system__tags": "nginx-docker-test",
    "instance": "8ad15599fa4d",
    "instance_group": "",
    "support_id": SAMPLE_SUPPORT_ID,
    "country_code": "N/A",
    "http__hostname": "5-localhost:1-/",
    "http__remote_addr": "127.0.0.1",
    "http__remote_port": "42970",
    "http__request_method": "GET",
    "http__response_code": "Blocked",
    "http__server_port": "80",
    "http__uri": "/etc/passwd",
    "http__x_forwarded_for": "N/A",
    "protocol": "HTTP",
    "request_outcome": "Blocked",
    "request_outcome_reason": "SECURITY_WAF_VIOLATION",
    "request_status": "blocked",
    "policy_name": "nms_app_protect_default_policy",
    "severity": "critical",
    "signature_cves": "N/A,N/A",
    "threat_campaign_names": "N/A",
    "client_class": "Untrusted Bot",
    "client_application": "N/A",
    "client_application_version": "N/A",
    "bot_anomalies": "N/A",
    "bot_category": "HTTP Library",
    "bot_signature_name": "curl",
    "enforced_bot_anomalies": "N/A",
    "violation_rating": "4",
    "violations": "HTTP protocol compliance failed,Attack signature detected,Violation Rating Threat detected,Bot Client Detected",
    "sub_violations": "HTTP protocol compliance failed:Host header contains IP address",
    "violation_details": "<?xml version='1.0' encoding='UTF-8'?><BAD_MSG>...</BAD_MSG>",
    "Attack_types": "Non-browser Client,Abuse of Functionality,Predictable Resource Location,Other Application Activity",
    "request": "GET /etc/passwd HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nUser-Agent: curl/7.81.0\\r\\nAccept: */*\\r\\n\\r\\n",
    "enforced_threat_campaign_names": "N/A",
    "enforced_signature_ids": "200010468,200003056",
    "enforced_signature_names": '"/etc/passwd" access (URI),"/etc" execution attempt (URI)',
    "enforced_signature_cves": "N/A,N/A",
    "signature_ids": "200010468,200003056",
    "signature_names": '"/etc/passwd" access (URI),"/etc" execution attempt (URI)',
    "signature_accuracies": "medium,low",
    "signature_risks": "high,low",
    "blocking_exception_reason": "N/A",
    "is_truncated_Values": "",
    "db_timestamp": "2026-10-16 12:05:40",
    "partition_key": "2026-10-16",
    "violation_contexts": "uri,other,other,other",
    "field_names": "Attack Signature",
    "field_values": "",
}

SAMPLE_V4_SIGNATURES_DATA = [
    {
        "timestamp": "2026-10-16 12:04:33",
        "event_uuid": "86411230-4cea-4a8a-8061-3bf552344f3a",
        "uuid": "853cb083-9d6f-4f4d-a8d1-f202ea18113f",
        "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
        "parent_hostname": "8ad15599fa4d",
        "system__tags": "nginx-docker-test",
        "instance": "8ad15599fa4d",
        "instance_group": "",
        "support_id": SAMPLE_SUPPORT_ID,
        "country_code": "N/A",
        "http__hostname": "5-localhost:1-/",
        "http__remote_addr": "127.0.0.1",
        "request_status": "blocked",
        "request_outcome_reason": "SECURITY_WAF_VIOLATION",
        "policy_name": "nms_app_protect_default_policy",
        "http__request_method": "GET",
        "http__response_code": "Blocked",
        "severity": "critical",
        "signature_cves": "N/A,N/A",
        "threat_campaign_names": "N/A",
        "http__uri": "/etc/passwd",
        "client_class": "Untrusted Bot",
        "client_application": "N/A",
        "bot_anomalies": "N/A",
        "bot_category": "HTTP Library",
        "bot_signature_name": "curl",
        "violation_rating": 4,
        "violations": "HTTP protocol compliance failed,Attack signature detected,Violation Rating Threat detected,Bot Client Detected",
        "sub_violations": "HTTP protocol compliance failed:Host header contains IP address",
        "signature_id": "200010468",
        "signature_name": '"/etc/passwd" access (URI)',
        "signature_accuracy": "medium",
        "signature_risk": "high",
        "blocking_mask": 2,
        "buffer": "/etc/passwd",
        "offset": 0,
        "length": 11,
        "db_timestamp": "2026-10-16 12:05:40",
        "partition_key": "2026-10-16",
        "violation_contexts": "uri,other,other,other",
        "field_names": "Attack Signature",
        "field_values": "",
    },
    {
        "timestamp": "2026-10-16 12:04:33",
        "event_uuid": "86411230-4cea-4a8a-8061-3bf552344f3a",
        "uuid": "2679ff44-9051-4518-a914-91442613cf9f",
        "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
        "parent_hostname": "8ad15599fa4d",
        "system__tags": "nginx-docker-test",
        "instance": "8ad15599fa4d",
        "instance_group": "",
        "support_id": SAMPLE_SUPPORT_ID,
        "country_code": "N/A",
        "http__hostname": "5-localhost:1-/",
        "http__remote_addr": "127.0.0.1",
        "request_status": "blocked",
        "request_outcome_reason": "SECURITY_WAF_VIOLATION",
        "policy_name": "nms_app_protect_default_policy",
        "http__request_method": "GET",
        "http__response_code": "Blocked",
        "severity": "critical",
        "signature_cves": "N/A,N/A",
        "threat_campaign_names": "N/A",
        "http__uri": "/etc/passwd",
        "client_class": "Untrusted Bot",
        "client_application": "N/A",
        "bot_anomalies": "N/A",
        "bot_category": "HTTP Library",
        "bot_signature_name": "curl",
        "violation_rating": 4,
        "violations": "HTTP protocol compliance failed,Attack signature detected,Violation Rating Threat detected,Bot Client Detected",
        "sub_violations": "HTTP protocol compliance failed:Host header contains IP address",
        "signature_id": "200003056",
        "signature_name": '"/etc" execution attempt (URI)',
        "signature_accuracy": "low",
        "signature_risk": "low",
        "blocking_mask": 2,
        "buffer": "/etc/passwd",
        "offset": 0,
        "length": 11,
        "db_timestamp": "2026-10-16 12:05:40",
        "partition_key": "2026-10-16",
        "violation_contexts": "uri,other,other,other",
        "field_names": "Attack Signature",
        "field_values": "",
    },
]

SAMPLE_V4_VIOLATION_DATA = [
    {
        "timestamp": "2026-10-16 12:04:33",
        "event_uuid": "86411230-4cea-4a8a-8061-3bf552344f3a",
        "uuid": "5b1f0fc8-cb73-4f16-a2b7-4fd49218499f",
        "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
        "parent_hostname": "8ad15599fa4d",
        "system__tags": "nginx-docker-test",
        "instance": "8ad15599fa4d",
        "instance_group": "",
        "support_id": SAMPLE_SUPPORT_ID,
        "country_code": "N/A",
        "http__hostname": "5-localhost:1-/",
        "http__remote_addr": "127.0.0.1",
        "request_status": "blocked",
        "request_outcome_reason": "SECURITY_WAF_VIOLATION",
        "policy_name": "nms_app_protect_default_policy",
        "http__request_method": "GET",
        "http__response_code": "Blocked",
        "severity": "critical",
        "signature_cves": "N/A,N/A",
        "threat_campaign_names": "N/A",
        "http__uri": "/etc/passwd",
        "client_class": "Untrusted Bot",
        "client_application": "N/A",
        "bot_anomalies": "N/A",
        "bot_category": "HTTP Library",
        "bot_signature_name": "curl",
        "signature_names": '"/etc/passwd" access (URI),"/etc" execution attempt (URI)',
        "signature_ids": "200010468,200003056",
        "signature_accuracies": "medium,low",
        "signature_risks": "high,low",
        "violation_rating": 4,
        "violations": "Attack signature detected",
        "sub_violations": "N/A",
        "violation_context": "uri",
        "blocking_mask": "2",
        "db_timestamp": "2026-10-16 12:05:40",
        "partition_key": "2026-10-16",
        "field_name": "Attack Signature",
        "field_value": "",
    },
    {
        "timestamp": "2026-10-16 12:04:33",
        "event_uuid": "86411230-4cea-4a8a-8061-3bf552344f3a",
        "uuid": "fb04a336-6cf3-4d9d-9359-b2d18c7d4b37",
        "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
        "parent_hostname": "8ad15599fa4d",
        "system__tags": "nginx-docker-test",
        "instance": "8ad15599fa4d",
        "instance_group": "",
        "support_id": SAMPLE_SUPPORT_ID,
        "country_code": "N/A",
        "http__hostname": "5-localhost:1-/",
        "http__remote_addr": "127.0.0.1",
        "request_status": "blocked",
        "request_outcome_reason": "SECURITY_WAF_VIOLATION",
        "policy_name": "nms_app_protect_default_policy",
        "http__request_method": "GET",
        "http__response_code": "Blocked",
        "severity": "critical",
        "signature_cves": "N/A,N/A",
        "threat_campaign_names": "N/A",
        "http__uri": "/etc/passwd",
        "client_class": "Untrusted Bot",
        "client_application": "N/A",
        "bot_anomalies": "N/A",
        "bot_category": "HTTP Library",
        "bot_signature_name": "curl",
        "signature_names": '"/etc/passwd" access (URI),"/etc" execution attempt (URI)',
        "signature_ids": "200010468,200003056",
        "signature_accuracies": "medium,low",
        "signature_risks": "high,low",
        "violation_rating": 4,
        "violations": "HTTP protocol compliance failed",
        "sub_violations": "HTTP protocol compliance failed:Host header contains IP address",
        "violation_context": "other",
        "blocking_mask": "0",
        "db_timestamp": "2026-10-16 12:05:40",
        "partition_key": "2026-10-16",
        "field_name": "N/A",
        "field_value": "N/A",
    },
]


@pytest.fixture(autouse=True)
def setup_storage():
    init_storage(force_memory=True)
    # Reset singleton ClickHouseService config for clean test state
    svc = get_clickhouse_service()
    svc.save_config(
        {
            "host": "10.0.0.55",
            "port": 8123,
            "username": "default",
            "password": "secret",
            "database": "nms",
        },
        persist_to_redis=False,
    )


@pytest.fixture
def client():
    return TestClient(app)


def test_clickhouse_schema_endpoint(client):
    """Verify schema endpoint returns all 3 tables with exact column counts and support_id correlation key."""
    res = client.get("/api/clickhouse/schema")
    assert res.status_code == 200
    data = res.json()
    assert data["correlation_key"] == "support_id"

    tables = data["tables"]
    assert "v4_security_events" in tables
    assert "v4_security_events_violation_data" in tables
    assert "v4_security_events_signatures_data" in tables

    assert len(tables["v4_security_events"]["columns"]) == 53
    assert len(V4_SECURITY_EVENTS_COLUMNS) == 53
    assert len(tables["v4_security_events_violation_data"]["columns"]) == 39
    assert len(V4_SECURITY_EVENTS_VIOLATION_DATA_COLUMNS) == 39
    assert len(tables["v4_security_events_signatures_data"]["columns"]) == 42
    assert len(V4_SECURITY_EVENTS_SIGNATURES_DATA_COLUMNS) == 42

    # Verify key columns exist (exact NGINX Instance Manager ClickHouse column names)
    ev_col_names = [c["name"] for c in tables["v4_security_events"]["columns"]]
    assert "support_id" in ev_col_names
    assert "event_uuid" in ev_col_names
    assert "violations" in ev_col_names
    assert "is_truncated_Values" in ev_col_names
    assert "request" in ev_col_names
    assert "http__x_forwarded_for" in ev_col_names
    assert "Attack_types" in ev_col_names
    assert "enforced_signature_ids" in ev_col_names

    viol_col_names = [c["name"] for c in tables["v4_security_events_violation_data"]["columns"]]
    assert "support_id" in viol_col_names
    assert "violations" in viol_col_names
    assert "blocking_mask" in viol_col_names

    sig_col_names = [c["name"] for c in tables["v4_security_events_signatures_data"]["columns"]]
    assert "support_id" in sig_col_names
    assert "signature_id" in sig_col_names
    assert "signature_name" in sig_col_names
    assert "signature_accuracy" in sig_col_names
    assert "signature_risk" in sig_col_names


def test_clickhouse_config_persistence_in_redis_mock():
    """Verify ClickHouse configuration is saved to Redis and restored on restart."""
    from f5_waf_editor.config import settings

    fake_redis_store = {}

    class FakeRedisClient:
        def get(self, k):
            return fake_redis_store.get(k)

        def set(self, k, v):
            fake_redis_store[k] = v

    fake_client = FakeRedisClient()
    svc = ClickHouseService()
    with patch.object(
        ClickHouseService,
        "_get_redis_client_and_prefix",
        return_value=(fake_client, "waf:policy:"),
    ):
        saved = svc.save_config(
            {
                "host": "192.168.10.25",
                "port": 8123,
                "username": "nim_admin",
                "password": "ch_password_123",
                "database": "nms",
                "ssl": False,
                "verify_ssl": False,
            }
        )
        assert saved["persisted_in_redis"] is True
        assert f"waf:policy:{CLICKHOUSE_CONFIG_REDIS_KEY}" in fake_redis_store

        # Simulate application reboot with fresh settings and a new service instance
        settings.clickhouse_host = ""
        new_svc = ClickHouseService()
        assert new_svc.get_config()["host"] != "192.168.10.25"

        loaded = new_svc.load_config_from_redis()
        assert loaded is True
        cfg = new_svc.get_config(include_password=True)
        assert cfg["host"] == "192.168.10.25"
        assert cfg["port"] == 8123
        assert cfg["username"] == "nim_admin"
        assert cfg["password"] == "ch_password_123"
        assert cfg["database"] == "nms"


def test_search_v4_security_events_across_all_53_fields(client):
    """Verify searching across all 53 columns of v4_security_events constructs valid SQL and returns rows."""
    captured_queries = []

    def fake_execute_query(query, *args, **kwargs):
        captured_queries.append(query)
        if "count() AS total" in query:
            return {"data": [{"total": "1"}], "meta": [], "rows": 1}
        if "system.tables" in query:
            return {"data": [{"database": "nms", "name": "v4_security_events"}], "meta": [], "rows": 1}
        return {"data": [SAMPLE_V4_SECURITY_EVENT], "meta": [], "rows": 1}

    svc = get_clickhouse_service()
    with patch.object(svc, "execute_query", side_effect=fake_execute_query):
        # Test filtering on multiple columns across the 53-column schema + global search
        payload = {
            "global_search": "/etc/passwd",
            "filters": [
                {"column": "support_id", "operator": "equals", "value": SAMPLE_SUPPORT_ID},
                {"column": "policy_name", "operator": "contains", "value": "nms_app_protect_default_policy"},
                {"column": "severity", "operator": "in", "value": "critical, high"},
                {"column": "violation_rating", "operator": "gte", "value": "3"},
                {"column": "violations", "operator": "contains", "value": "Attack signature detected"},
                {"column": "request", "operator": "starts_with", "value": "GET /etc/passwd"},
                {"column": "bot_signature_name", "operator": "equals", "value": "curl"},
                {"column": "is_truncated", "operator": "is_empty", "value": ""},
            ],
            "limit": 25,
            "offset": 0,
            "sort_by": "timestamp",
            "sort_dir": "DESC",
        }
        res = client.post("/api/clickhouse/events/search", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["rows"]) == 1
        assert data["rows"][0]["support_id"] == SAMPLE_SUPPORT_ID
        assert data["rows"][0]["http__uri"] == "/etc/passwd"

        # Verify every one of the 53 columns can be filtered without error
        all_col_filters = [
            {"column": col_name, "operator": "is_not_empty", "value": ""}
            for col_name in V4_SECURITY_EVENTS_COLUMNS
        ]
        res_all = client.post(
            "/api/clickhouse/events/search",
            json={"filters": all_col_filters, "limit": 10, "offset": 0},
        )
        assert res_all.status_code == 200
        sql_executed = res_all.json()["query"]
        for col_name in V4_SECURITY_EVENTS_COLUMNS:
            assert f"`{col_name}`" in sql_executed


def test_correlate_3_tables_by_support_id(client):
    """
    Verify correlating v4_security_events, v4_security_events_violation_data,
    and v4_security_events_signatures_data by support_id = '10134279319999872904'.
    """
    # Create the policy matching policy_name in the sample logs
    client.post(
        "/api/policies",
        json={"name": "nms_app_protect_default_policy", "template_id": "default"},
    )

    def fake_execute_query(query, *args, **kwargs):
        if "system.tables" in query:
            return {"data": [{"database": "nms", "name": "v4_security_events"}], "meta": [], "rows": 1}
        if "`v4_security_events`" in query:
            return {"data": [SAMPLE_V4_SECURITY_EVENT], "meta": [], "rows": 1}
        if "`v4_security_events_violation_data`" in query:
            return {"data": SAMPLE_V4_VIOLATION_DATA, "meta": [], "rows": len(SAMPLE_V4_VIOLATION_DATA)}
        if "`v4_security_events_signatures_data`" in query:
            return {"data": SAMPLE_V4_SIGNATURES_DATA, "meta": [], "rows": len(SAMPLE_V4_SIGNATURES_DATA)}
        return {"data": [], "meta": [], "rows": 0}

    svc = get_clickhouse_service()
    with patch.object(svc, "execute_query", side_effect=fake_execute_query):
        res = client.get(f"/api/clickhouse/events/{SAMPLE_SUPPORT_ID}/correlate")
        assert res.status_code == 200
        data = res.json()

        assert data["support_id"] == SAMPLE_SUPPORT_ID
        assert data["matched_policy_name"] == "nms_app_protect_default_policy"
        assert len(data["security_events"]) == 1
        assert len(data["violation_data"]) == 2
        assert len(data["signatures_data"]) == 2

        # Check extracted unique signatures from v4_security_events_signatures_data
        unique_sigs = data["unique_signatures"]
        assert len(unique_sigs) == 2
        sig_ids = {s["signature_id"] for s in unique_sigs}
        assert sig_ids == {"200010468", "200003056"}

        # Check initial policy signature states (not yet overridden)
        states = data["policy_signature_states"]
        assert states["200010468"]["in_policy"] is False
        assert states["200010468"]["enabled"] is None
        assert states["200003056"]["in_policy"] is False
        assert states["200003056"]["enabled"] is None


def test_policy_signature_fine_tuning_enable_disable_reset_and_bulk(client):
    """
    Verify enabling, disabling, resetting, and bulk-tuning signature_id values
    from v4_security_events_signatures_data in a WAF policy.
    """
    # 1. Create policy nms_app_protect_default_policy
    create_res = client.post(
        "/api/policies",
        json={"name": "nms_app_protect_default_policy", "template_id": "default"},
    )
    assert create_res.status_code == 201

    # 2. Disable signature_id 200010468 ("/etc/passwd" access (URI))
    disable_res = client.post(
        "/api/clickhouse/policy/tune-signature",
        json={
            "policy_name": "nms_app_protect_default_policy",
            "signature_id": 200010468,
            "enabled": False,
            "signature_name": '"/etc/passwd" access (URI)',
            "support_id": SAMPLE_SUPPORT_ID,
        },
    )
    assert disable_res.status_code == 200
    disable_data = disable_res.json()
    assert disable_data["signature_state"]["in_policy"] is True
    assert disable_data["signature_state"]["enabled"] is False
    assert disable_data["signature_state"]["status"] == "disabled"

    # Verify policy content has signatureId 200010468 disabled
    pol = client.get("/api/policies/nms_app_protect_default_policy").json()
    sigs = pol["policy"].get("signatures", [])
    sig_200010468 = next((s for s in sigs if s.get("signatureId") == 200010468), None)
    assert sig_200010468 is not None
    assert sig_200010468["enabled"] is False

    # Validate updated policy against schema
    val_res = client.post("/api/policies/validate", json={"content": pol})
    assert val_res.status_code == 200
    assert val_res.json()["valid"] is True

    # 3. Enable signature_id 200010468 (tighten policy)
    enable_res = client.post(
        "/api/clickhouse/policy/tune-signature",
        json={
            "policy_name": "nms_app_protect_default_policy",
            "signature_id": 200010468,
            "enabled": True,
            "signature_name": '"/etc/passwd" access (URI)',
            "support_id": SAMPLE_SUPPORT_ID,
        },
    )
    assert enable_res.status_code == 200
    assert enable_res.json()["signature_state"]["enabled"] is True
    assert enable_res.json()["signature_state"]["status"] == "enabled"

    pol_enabled = client.get("/api/policies/nms_app_protect_default_policy").json()
    sig_200010468_en = next(
        (s for s in pol_enabled["policy"].get("signatures", []) if s.get("signatureId") == 200010468),
        None,
    )
    assert sig_200010468_en is not None
    assert sig_200010468_en["enabled"] is True

    # 4. Bulk disable both signatures (200010468 and 200003056) from support_id 10134279319999872904
    bulk_res = client.post(
        "/api/clickhouse/policy/tune-signatures-bulk",
        json={
            "policy_name": "nms_app_protect_default_policy",
            "support_id": SAMPLE_SUPPORT_ID,
            "signatures": [
                {
                    "signature_id": 200010468,
                    "enabled": False,
                    "signature_name": '"/etc/passwd" access (URI)',
                },
                {
                    "signature_id": 200003056,
                    "enabled": False,
                    "signature_name": '"/etc" execution attempt (URI)',
                },
            ],
        },
    )
    assert bulk_res.status_code == 200
    bulk_data = bulk_res.json()
    assert len(bulk_data["updated"]) == 2

    # Check signature-states endpoint
    states_res = client.get(
        "/api/clickhouse/policy/nms_app_protect_default_policy/signature-states?signature_ids=200010468,200003056"
    )
    assert states_res.status_code == 200
    states_map = states_res.json()["states"]
    assert states_map["200010468"]["enabled"] is False
    assert states_map["200003056"]["enabled"] is False

    # 5. Reset signature_id 200010468 to policy default (enabled=None removes override)
    reset_res = client.post(
        "/api/clickhouse/policy/tune-signature",
        json={
            "policy_name": "nms_app_protect_default_policy",
            "signature_id": 200010468,
            "enabled": None,
        },
    )
    assert reset_res.status_code == 200
    assert reset_res.json()["signature_state"]["in_policy"] is False
    assert reset_res.json()["signature_state"]["status"] == "default"


def test_clickhouse_execute_query_no_simultaneous_auth_headers():
    """
    Regression test for ClickHouse 24.9+ Code 516:
    Ensure execute_query sends X-ClickHouse-User/X-ClickHouse-Key and NEVER sends
    an HTTP Authorization header simultaneously.
    """
    import httpx

    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"data": [{"version": "24.9.2.42"}]})

    svc = ClickHouseService(transport=httpx.MockTransport(handler))
    svc.save_config(
        {
            "host": "10.0.0.55",
            "port": 8123,
            "username": "default",
            "password": "my_password",
            "database": "default",
        },
        persist_to_redis=False,
    )

    res = svc.execute_query("SELECT version() AS version")
    assert res["data"][0]["version"] == "24.9.2.42"
    assert len(captured_requests) == 1

    req_headers = captured_requests[0].headers
    assert req_headers.get("x-clickhouse-user") == "default"
    assert req_headers.get("x-clickhouse-key") == "my_password"
    assert "authorization" not in req_headers


def test_search_global_search_unknown_identifier_fallback(client):
    """
    Verify that if a ClickHouse instance has a slightly different column subset and raises
    Code 47 (UNKNOWN_IDENTIFIER) on global_search, search_security_events introspects
    system.columns and retries cleanly.
    """
    call_count = {"count_query": 0}

    def fake_execute_query(query, *args, **kwargs):
        if "system.tables" in query:
            return {"data": [{"database": "nms", "name": "v4_security_events"}], "meta": [], "rows": 1}
        if "system.columns" in query:
            return {
                "data": [
                    {"name": "timestamp"},
                    {"name": "support_id"},
                    {"name": "policy_name"},
                    {"name": "http__uri"},
                    {"name": "request_status"},
                ],
                "meta": [],
                "rows": 5,
            }
        if "count() AS total" in query:
            call_count["count_query"] += 1
            if call_count["count_query"] == 1:
                raise RuntimeError("ClickHouse HTTP 404: Code: 47. DB::Exception: Missing columns: 'legacy_col' (UNKNOWN_IDENTIFIER)")
            return {"data": [{"total": "1"}], "meta": [], "rows": 1}
        return {"data": [SAMPLE_V4_SECURITY_EVENT], "meta": [], "rows": 1}

    svc = get_clickhouse_service()
    with patch.object(svc, "execute_query", side_effect=fake_execute_query):
        res = client.post(
            "/api/clickhouse/events/search",
            json={"global_search": "/etc/passwd", "limit": 25, "offset": 0},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["rows"]) == 1


def test_ui_clickhouse_state_and_correlation_bindings():
    """
    Regression test ensuring index.html and app.js use matching Alpine state properties
    for ClickHouse correlation (chCorrelatedData), schema columns (chSchemaEventsColumns),
    field filter builder (addChFieldFilter), and signature tuning (tuneSignatureInPolicy).
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    js_content = (root / "f5_waf_editor" / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    html_content = (root / "f5_waf_editor" / "web" / "templates" / "index.html").read_text(encoding="utf-8")

    # 1. Correlation panel state variable must match between HTML and JS
    assert 'x-if="chCorrelatedData"' in html_content
    assert "this.chCorrelatedData = data;" in js_content
    assert 'id="ch-correlation-panel"' in html_content

    # 2. Schema column arrays used in HTML must be populated in loadClickHouseSchema()
    assert "this.chSchemaEventsColumns =" in js_content
    assert "this.chSchemaViolationColumns =" in js_content
    assert "this.chSchemaSignaturesColumns =" in js_content

    # 3. Search input bindings should trigger search on input debounce as well as enter
    assert '@input.debounce.400ms="searchClickHouseEvents(true)"' in html_content
    assert "qf.http__request_method" in js_content

    # 4. Inspector policy dropdown and automatic policy selection from violation policy_name
    assert 'id="ch-inspector-policy-select"' in html_content
    assert "resolvePolicyNameFromLog(" in js_content
    assert "this.chInspectorLogPolicyName" in js_content

    # 5. Dedicated Configuration section containing Redis, GitHub, and ClickHouse settings
    assert "switchSection('configuration')" in html_content
    assert 'activeSection === \'configuration\'' in html_content
    assert 'id="config-card-redis"' in html_content
    assert 'id="config-card-github"' in html_content
    assert 'id="config-card-clickhouse"' in html_content

    # 6. Regression checks for loadPolicy, Open Policy button, Inspector Save button, and Save Policy to Redis button
    assert "async loadPolicy(" in js_content
    assert "async refreshLoadedPolicyIfMatching(" in js_content
    assert "async saveInspectorFineTuning(" in js_content
    assert "async saveTunedPolicyToRedis(" in js_content
    assert 'saveInspectorFineTuning()' in html_content
    assert 'saveTunedPolicyToRedis(chTargetPolicy, false)' in html_content
    assert 'Save Policy to Redis' in html_content
    assert 'Save Fine-Tuning to Redis' in html_content


def test_correlate_always_returns_log_policy_name_for_auto_selection(client):
    """
    Verify that correlating a violation by support_id always extracts log_policy_name
    and matched_log_policy_name from the violation's policy_name field, even if a
    different policy_name was previously selected.
    """
    client.post(
        "/api/policies",
        json={"name": "other_policy", "template_id": "default"},
    )
    client.post(
        "/api/policies",
        json={"name": "nms_app_protect_default_policy", "template_id": "default"},
    )

    def fake_execute_query(query, *args, **kwargs):
        if "system.tables" in query:
            return {"data": [{"database": "nms", "name": "v4_security_events"}], "meta": [], "rows": 1}
        if "`v4_security_events`" in query:
            return {"data": [SAMPLE_V4_SECURITY_EVENT], "meta": [], "rows": 1}
        if "`v4_security_events_violation_data`" in query:
            return {"data": SAMPLE_V4_VIOLATION_DATA, "meta": [], "rows": len(SAMPLE_V4_VIOLATION_DATA)}
        if "`v4_security_events_signatures_data`" in query:
            return {"data": SAMPLE_V4_SIGNATURES_DATA, "meta": [], "rows": len(SAMPLE_V4_SIGNATURES_DATA)}
        return {"data": [], "meta": [], "rows": 0}

    svc = get_clickhouse_service()
    with patch.object(svc, "execute_query", side_effect=fake_execute_query):
        res = client.get(
            f"/api/clickhouse/events/{SAMPLE_SUPPORT_ID}/correlate?policy_name=other_policy"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["log_policy_name"] == "nms_app_protect_default_policy"
        assert data["matched_log_policy_name"] == "nms_app_protect_default_policy"


def test_save_tuned_policy_to_redis_endpoint_marks_policy_modified_for_github(client):
    """
    Verify that POST /api/clickhouse/policy/save-to-redis saves the fine-tuned WAF policy
    (including optional signature overrides) and marks it as modified / uncommitted_changes=True
    so it can be committed to GitHub from the WAF Policies page.
    """
    create_res = client.post(
        "/api/policies",
        json={"name": "nms_app_protect_default_policy", "template_id": "default"},
    )
    assert create_res.status_code in (200, 201)

    save_res = client.post(
        "/api/clickhouse/policy/save-to-redis",
        json={
            "policy_name": "nms_app_protect_default_policy",
            "support_id": SAMPLE_SUPPORT_ID,
            "signatures": [
                {
                    "signature_id": 200010468,
                    "enabled": False,
                    "signature_name": '"/etc/passwd" access (URI)',
                }
            ],
        },
    )
    assert save_res.status_code == 200
    save_data = save_res.json()
    assert save_data["saved"] is True
    assert save_data["policy_name"] == "nms_app_protect_default_policy"
    assert save_data["uncommitted_changes"] is True
    assert save_data["status"] == "modified"
    assert save_data["total_signature_overrides"] >= 1

    # Verify /api/policies lists the policy with uncommitted_changes=True and status='modified'
    list_res = client.get("/api/policies")
    assert list_res.status_code == 200
    policies = list_res.json()
    matched = next((p for p in policies if p["name"] == "nms_app_protect_default_policy"), None)
    assert matched is not None
    assert matched.get("uncommitted_changes") is True
    assert matched.get("status") == "modified"

    # Verify the signature override is persisted in the policy JSON
    pol_res = client.get("/api/policies/nms_app_protect_default_policy")
    assert pol_res.status_code == 200
    pol_doc = pol_res.json()
    sigs = pol_doc.get("policy", {}).get("signatures", [])
    override = next((s for s in sigs if s.get("signatureId") == 200010468), None)
    assert override is not None
    assert override["enabled"] is False




