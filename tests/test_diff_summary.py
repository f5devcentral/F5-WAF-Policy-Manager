"""
Unit and integration tests for GitOps diff summarization and verbose commit messages.
"""

import json
import pytest
from fastapi.testclient import TestClient

from f5_waf_editor.app import app
from f5_waf_editor.storage.diff_summary import (
    summarize_policy_changes,
    summarize_log_profile_changes,
    summarize_custom_signatures_changes,
)
from f5_waf_editor.storage import init_storage


@pytest.fixture(autouse=True)
def reset_storage_state():
    init_storage(force_memory=True)


def test_summarize_new_policy_creation():
    new_policy = {
        "policy": {
            "name": "brand_new_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "server-technologies": [
                {"serverTechnologyName": "Unix/Linux"},
                {"serverTechnologyName": "Nginx"},
            ],
            "signature-sets": [{"name": "Generic Detection Signatures", "alarm": True, "block": True}],
            "urls": [{"name": "/api/v1/health", "type": "explicit"}],
            "parameters": [{"name": "authToken", "type": "explicit"}],
        }
    }
    desc = summarize_policy_changes(None, new_policy, "brand_new_policy")
    assert "feat(waf): create policy 'brand_new_policy'" in desc
    assert "Initial policy configuration:" in desc
    assert "- Template: POLICY_TEMPLATE_NGINX_BASE" in desc
    assert "- Enforcement mode: blocking" in desc
    assert "- Server technologies: Unix/Linux, Nginx" in desc
    assert "- Signature sets: 1 configured" in desc
    assert "- Allowed URLs: 1 configured" in desc
    assert "- Parameters: 1 configured" in desc


def test_summarize_policy_updates():
    old_policy = {
        "policy": {
            "name": "test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "transparent",
            "server-technologies": [{"serverTechnologyName": "Apache"}],
            "signature-sets": [
                {"name": "High Accuracy", "alarm": True, "block": False},
                {"name": "Old Set", "alarm": True, "block": True},
            ],
            "urls": [{"name": "/old_url"}],
            "parameters": [{"name": "old_param"}],
            "cookies": [{"name": "old_cookie"}],
            "blocking-settings": {
                "violations": [{"name": "VIOL_JSON_MALFORMED", "alarm": True, "block": False}]
            },
            "data-guard": {"enabled": False},
        }
    }

    new_policy = {
        "policy": {
            "name": "test_policy",
            "template": {"name": "POLICY_TEMPLATE_COMPREHENSIVE"},
            "enforcementMode": "blocking",
            "server-technologies": [
                {"serverTechnologyName": "Nginx"},
                {"serverTechnologyName": "PHP"},
            ],
            "signature-sets": [
                {"name": "High Accuracy", "alarm": True, "block": True},  # block changed
                {"name": "New SQL Set", "alarm": True, "block": True},     # added
            ],  # Old Set removed
            "urls": [{"name": "/api/v2/checkout"}, {"name": "/login"}],
            "parameters": [{"name": "session_id"}],
            "cookies": [{"name": "auth_token"}],
            "blocking-settings": {
                "violations": [{"name": "VIOL_JSON_MALFORMED", "alarm": True, "block": True}]
            },
            "data-guard": {"enabled": True},
        }
    }

    desc = summarize_policy_changes(old_policy, new_policy, "test_policy")
    assert "feat(waf): update policy 'test_policy'" in desc
    assert "Changes:" in desc
    assert "- Enforcement mode: changed from 'transparent' to 'blocking'" in desc
    assert "- Base template: changed from 'POLICY_TEMPLATE_NGINX_BASE' to 'POLICY_TEMPLATE_COMPREHENSIVE'" in desc
    assert "Server technologies: added" in desc
    assert "Signature sets added: New SQL Set" in desc
    assert "Signature sets removed: Old Set" in desc
    assert "High Accuracy (block=on)" in desc
    assert "URLs: added" in desc
    assert "Parameters: added" in desc
    assert "Cookies:" in desc
    assert "VIOL_JSON_MALFORMED (blocked)" in desc
    assert "Data Guard: enabled" in desc


def test_summarize_policy_minor_fallback():
    policy = {
        "policy": {
            "name": "stable_policy",
            "enforcementMode": "blocking",
        }
    }
    desc = summarize_policy_changes(policy, policy, "stable_policy")
    assert "feat(waf): update policy 'stable_policy'" in desc
    assert "- Minor configuration and parameter adjustments" in desc


def test_summarize_logging_profile_changes():
    # 1. Creation
    new_log = {
        "filter": {"request_type": "all"},
        "content": {"format": "splunk", "max_message_size": "10k"},
    }
    create_desc = summarize_log_profile_changes(None, new_log, "splunk_log")
    assert "feat(logging): create logging profile 'splunk_log'" in create_desc
    assert "Initial logging profile configuration:" in create_desc
    assert "- Request type: all" in create_desc
    assert "- Storage format: splunk" in create_desc
    assert "- Max message size: 10k" in create_desc

    # 2. Update
    old_log = {
        "filter": {"request_type": "illegal", "description": "Old desc"},
        "content": {"format": "default", "max_message_size": "5k", "escaping": "none"},
    }
    update_desc = summarize_log_profile_changes(old_log, new_log, "splunk_log")
    assert "feat(logging): update logging profile 'splunk_log'" in update_desc
    assert "- Request type: changed from 'illegal' to 'all'" in update_desc
    assert "- Storage format: changed from 'default' to 'splunk'" in update_desc
    assert "- Max message size: changed from '5k' to '10k'" in update_desc


def test_summarize_custom_signatures_changes():
    # 1. Creation
    new_sigs = {"signatures": [{"name": "sig1"}, {"name": "sig2"}]}
    create_desc = summarize_custom_signatures_changes(None, new_sigs, "custom_sigs_app")
    assert "feat(signatures): create custom signature set 'custom_sigs_app'" in create_desc
    assert "- Configured 2 custom signature(s)" in create_desc

    # 2. Update
    old_sigs = {"signatures": [{"name": "sig1"}]}
    update_desc = summarize_custom_signatures_changes(old_sigs, new_sigs, "custom_sigs_app")
    assert "feat(signatures): update custom signatures 'custom_sigs_app'" in update_desc
    assert "Added 1 new custom signature(s)" in update_desc


def test_api_commit_preview_endpoint():
    client = TestClient(app)

    # Preview with draft content provided in request
    payload = {
        "type": "policy",
        "name": "preview_policy",
        "content": {
            "policy": {
                "name": "preview_policy",
                "enforcementMode": "blocking",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            }
        },
    }
    resp = client.post("/api/github/commit-preview", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "policy"
    assert data["name"] == "preview_policy"
    assert "feat(waf): create policy 'preview_policy'" in data["commit_message"]
    assert "- Enforcement mode: blocking" in data["commit_message"]

    # Preview for logging profile
    log_payload = {
        "type": "logging",
        "name": "preview_logging",
        "content": {
            "filter": {"request_type": "all"},
            "content": {"format": "splunk"},
        },
    }
    resp_log = client.post("/api/github/commit-preview", json=log_payload)
    assert resp_log.status_code == 200
    data_log = resp_log.json()
    assert "feat(logging): create logging profile 'preview_logging'" in data_log["commit_message"]
