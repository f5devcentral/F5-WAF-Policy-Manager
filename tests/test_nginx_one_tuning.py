"""
Tests for NGINX One Console Security Events Search (listSecurityEvents),
Single Event Correlation by support_id (getSecurityEvent),
Redis Config Persistence, and WAF Policy Signature Fine-Tuning.
"""

from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from f5_waf_editor.app import app
from f5_waf_editor.storage import get_storage, init_storage
from f5_waf_editor.storage.nginx_one_service import (
    NGINX_ONE_CONFIG_REDIS_KEY,
    NginxOneConsoleService,
    get_nginx_one_service,
)


SAMPLE_SUPPORT_ID = "6661174896666480359"

# Matches the official NGINX One Console OpenAPI schema for listSecurityEvents item (EventSummary)
SAMPLE_NGINX_ONE_EVENT_SUMMARY = {
    "support_id": SAMPLE_SUPPORT_ID,
    "uuid": "5b1f0fc8-cb73-4f16-a2b7-4fd49218499f",
    "timestamp": "2026-10-16T12:04:33Z",
    "system_id": "1e91c5c6-7995-318c-ae43-ed8a4ef5e0f7",
    "parent_hostname": "nginx-one-instance-01",
    "instance_tags": ["prod", "edge-waf"],
    "instance_group": "prod-cluster",
    "request_status": "blocked",
    "request_outcome": "Blocked",
    "request_outcome_reason": "SECURITY_WAF_VIOLATION",
    "http_hostname": "api.example.com",
    "http_remote_addr": "203.0.113.42",
    "http_remote_port": "51324",
    "http_request_method": "GET",
    "http_response_code": "Blocked",
    "http_server_port": "443",
    "http_uri": "/etc/passwd",
    "is_truncated_values": False,
    "policy_name": "api_security_policy",
    "severity": "critical",
    "violation_rating": "4",
    "client_class": "Untrusted Bot",
    "client_application": "N/A",
    "client_application_version": "N/A",
    "bot_anomalies": "N/A",
    "bot_category": "HTTP Library",
    "bot_signature_name": "curl",
    "enforced_bot_anomalies": "N/A",
    "enforced_threat_campaign_names": "N/A",
    "threat_campaign_names": "N/A",
    "violations": "Attack signature detected,HTTP protocol compliance failed",
    "sub_violations": "HTTP protocol compliance failed:Host header contains IP address",
    "signature_ids": "200010468,200003056",
    "signature_names": '"/etc/passwd" access (URI),"/etc" execution attempt (URI)',
    "signature_cves": "N/A,N/A",
}

# Matches the official NGINX One Console OpenAPI schema for getSecurityEvent (DetailedEventResponse)
SAMPLE_NGINX_ONE_DETAILED_EVENT = {
    **SAMPLE_NGINX_ONE_EVENT_SUMMARY,
    "request": "GET /etc/passwd HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
    "blocking_exception_reason": "N/A",
    "x_forwarded_for_header_value": "198.51.100.10",
    "violations": [
        {
            "uuid": "5b1f0fc8-cb73-4f16-a2b7-4fd49218499f",
            "name": "Attack signature detected",
            "context": "uri",
            "blocking_mask": "2",
            "violation_rating": 4,
            "field_name": "Attack Signature",
            "field_value": "/etc/passwd",
            "sub_violations": [],
            "signatures": [
                {
                    "id": "200010468",
                    "name": '"/etc/passwd" access (URI)',
                    "accuracy": "medium",
                    "risk": "high",
                    "blocking_mask": 2,
                    "buffer": "/etc/passwd",
                    "offset": 0,
                    "length": 11,
                },
                {
                    "id": "200003056",
                    "name": '"/etc" execution attempt (URI)',
                    "accuracy": "low",
                    "risk": "low",
                    "blocking_mask": 2,
                    "buffer": "/etc/passwd",
                    "offset": 0,
                    "length": 11,
                },
            ],
        },
        {
            "uuid": "fb04a336-6cf3-4d9d-9359-b2d18c7d4b37",
            "name": "HTTP protocol compliance failed",
            "context": "header",
            "blocking_mask": "0",
            "violation_rating": 4,
            "field_name": "Host",
            "field_value": "127.0.0.1",
            "sub_violations": [
                {
                    "name": "HTTP protocol compliance failed:Host header contains IP address",
                }
            ],
            "signatures": [],
        },
    ],
}


@pytest.fixture(autouse=True)
def setup_storage():
    init_storage(force_memory=True)
    svc = get_nginx_one_service()
    svc.save_config(
        {
            "tenant_cname": "acme-corp",
            "base_url": "",
            "namespace": "production",
            "api_token": "test-api-token-secret-999",
            "verify_ssl": True,
        },
        persist_to_redis=False,
    )


@pytest.fixture
def client():
    return TestClient(app)


def test_nginx_one_url_construction():
    """Verify listSecurityEvents and getSecurityEvent endpoint URLs match NGINX One Console API docs."""
    svc = NginxOneConsoleService()
    svc.save_config(
        {
            "tenant_cname": "my-tenant",
            "namespace": "default",
            "api_token": "tok_123",
        },
        persist_to_redis=False,
    )
    assert (
        svc._events_endpoint_url()
        == "https://my-tenant.console.ves.volterra.io/api/nginx/one/namespaces/default/app-protect/events"
    )
    assert (
        svc._event_detail_endpoint_url(SAMPLE_SUPPORT_ID)
        == f"https://my-tenant.console.ves.volterra.io/api/nginx/one/namespaces/default/app-protect/events/{SAMPLE_SUPPORT_ID}"
    )


def test_nginx_one_config_persistence_in_redis_mock():
    """Verify NGINX One Console configuration is persisted in Redis and restored on startup."""
    fake_redis_store = {}

    class FakeRedisClient:
        def get(self, k):
            return fake_redis_store.get(k)

        def set(self, k, v):
            fake_redis_store[k] = v

    fake_client = FakeRedisClient()
    svc = NginxOneConsoleService()
    with patch.object(
        NginxOneConsoleService,
        "_get_redis_client_and_prefix",
        return_value=(fake_client, "waf:policy:"),
    ):
        saved = svc.save_config(
            {
                "tenant_cname": "f5-demo",
                "namespace": "secops",
                "api_token": "ves_api_token_abc",
                "verify_ssl": True,
            },
            persist_to_redis=True,
        )
        assert saved["persisted_in_redis"] is True
        assert saved["has_api_token"] is True
        assert f"waf:policy:{NGINX_ONE_CONFIG_REDIS_KEY}" in fake_redis_store

        svc2 = NginxOneConsoleService()
        loaded = svc2.load_config_from_redis()
        assert loaded is True
        cfg2 = svc2.get_config(include_secret=True)
        assert cfg2["tenant_cname"] == "f5-demo"
        assert cfg2["namespace"] == "secops"
        assert cfg2["api_token"] == "ves_api_token_abc"


def test_nginx_one_search_events_calls_list_security_events(client):
    """Verify POST /api/nginx-one/events/search calls listSecurityEvents and normalizes rows."""
    captured = {}

    def fake_request_json(self, method, url, params=None):
        captured["method"] = method
        captured["url"] = url
        captured["params"] = params
        return {
            "items": [SAMPLE_NGINX_ONE_EVENT_SUMMARY],
            "total": 1,
        }

    with patch.object(NginxOneConsoleService, "_request_json", fake_request_json):
        res = client.post(
            "/api/nginx-one/events/search",
            json={
                "global_search": "",
                "filters": [
                    {"column": "policy_name", "operator": "contains", "value": "api_security_policy"},
                    {"column": "request_status", "operator": "equals", "value": "blocked"},
                ],
                "limit": 50,
                "offset": 0,
                "sort_by": "timestamp",
                "sort_order": "DESC",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["source"] == "nginx_one"
        assert data["total"] == 1
        assert len(data["rows"]) == 1

        row = data["rows"][0]
        assert row["support_id"] == SAMPLE_SUPPORT_ID
        assert row["policy_name"] == "api_security_policy"
        assert row["http__uri"] == "/etc/passwd"
        assert row["http__remote_addr"] == "203.0.113.42"
        assert row["signature_ids"] == "200010468,200003056"

        assert captured["method"] == "GET"
        assert captured["url"].endswith("/api/nginx/one/namespaces/production/app-protect/events")
        assert "start_time" in captured["params"]
        assert "end_time" in captured["params"]
        assert "policy_name CONTAINS 'api_security_policy'" in captured["params"]["filter"]
        assert "request_status='blocked'" in captured["params"]["filter"]


def test_nginx_one_correlate_event_and_tune_policy(client):
    """
    Verify GET /api/nginx-one/events/{support_id}/correlate calls getSecurityEvent,
    extracts violations and signatures, matches policy_name, and tunes signatures in policy.
    """
    storage = get_storage()
    storage.save_policy(
        "api_security_policy",
        {
            "policy": {
                "name": "api_security_policy",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": "blocking",
                "signatures": [],
            }
        },
    )

    def fake_request_json(self, method, url, params=None):
        assert method == "GET"
        assert url.endswith(f"/api/nginx/one/namespaces/production/app-protect/events/{SAMPLE_SUPPORT_ID}")
        return {"item": SAMPLE_NGINX_ONE_DETAILED_EVENT}

    with patch.object(NginxOneConsoleService, "_request_json", fake_request_json):
        res = client.get(f"/api/nginx-one/events/{SAMPLE_SUPPORT_ID}/correlate")
        assert res.status_code == 200
        corr = res.json()
        assert corr["found"] is True
        assert corr["source"] == "nginx_one"
        assert corr["support_id"] == SAMPLE_SUPPORT_ID
        assert corr["matched_policy_name"] == "api_security_policy"
        assert len(corr["violation_data"]) == 2
        assert len(corr["signatures_data"]) == 2
        assert len(corr["unique_signatures"]) == 2

        sig_ids = [s["signature_id"] for s in corr["unique_signatures"]]
        assert "200010468" in sig_ids
        assert "200003056" in sig_ids

    # Tune signature 200010468 (disable / relax false positive) via /api/nginx-one/policy/tune-signature
    tune_res = client.post(
        "/api/nginx-one/policy/tune-signature",
        json={
            "policy_name": "api_security_policy",
            "signature_id": 200010468,
            "enabled": False,
            "action": "set",
            "signature_name": '"/etc/passwd" access (URI)',
            "support_id": SAMPLE_SUPPORT_ID,
        },
    )
    assert tune_res.status_code == 200
    tune_data = tune_res.json()
    assert tune_data["signature_state"]["status"] == "disabled"
    assert tune_data["signature_state"]["enabled"] is False
    assert tune_data["signature_state"]["tag"] == f"tuned-from-support-id-{SAMPLE_SUPPORT_ID}"

    # Verify policy in storage has the tuned signature
    updated_policy = storage.get_policy("api_security_policy")
    sigs = updated_policy["policy"]["signatures"]
    assert len(sigs) == 1
    assert sigs[0]["signatureId"] == 200010468
    assert sigs[0]["enabled"] is False


def test_ui_nginx_one_and_clickhouse_bindings():
    """Verify both NGINX One Console and ClickHouse UI bindings are present in index.html and app.js."""
    repo_root = Path(__file__).resolve().parent.parent
    html_text = (repo_root / "f5_waf_editor" / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js_text = (repo_root / "f5_waf_editor" / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")

    assert "setViolationsSource('nginx_one')" in html_text
    assert "setViolationsSource('clickhouse')" in html_text
    assert "config-categories-sidebar" in html_text
    assert "config-tab-redis" in html_text
    assert "config-tab-github" in html_text
    assert "config-tab-clickhouse" in html_text
    assert "config-tab-nginx-one" in html_text
    assert "configTab === 'redis'" in html_text
    assert "configTab === 'github'" in html_text
    assert "configTab === 'clickhouse'" in html_text
    assert "configTab === 'nginx_one'" in html_text
    assert "config-card-nginx-one" in html_text
    assert "saveNginxOneConfig()" in html_text
    assert "testNginxOneConnection()" in html_text

    assert "setConfigTab(tab)" in js_text
    assert "/api/nginx-one/events/search" in js_text
    assert "/api/nginx-one/events/" in js_text
    assert "/api/nginx-one/policy/tune-signature" in js_text
    assert "/api/nginx-one/policy/tune-signatures-bulk" in js_text
    assert "/api/nginx-one/policy/save-to-redis" in js_text
    assert "/api/clickhouse/events/search" in js_text
    assert "/api/clickhouse/policy/tune-signature" in js_text
    assert "/api/clickhouse/policy/save-to-redis" in js_text
