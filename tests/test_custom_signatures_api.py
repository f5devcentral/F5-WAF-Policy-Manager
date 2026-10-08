"""
Tests for Custom Signatures REST API endpoints:
- GET /api/custom-signatures-catalog
- GET /api/custom-signatures
- GET /api/custom-signatures/all
- GET /api/custom-signatures/{tag}
- POST /api/custom-signatures
- PUT /api/custom-signatures/{tag}
- DELETE /api/custom-signatures/{tag}
- POST /api/custom-signatures/validate
- GET /api/custom-signatures/{tag}/export
- POST /api/custom-signatures/import
"""

import io
import json
import pytest
from fastapi.testclient import TestClient

from f5_waf_editor.app import app
from f5_waf_editor.storage import init_storage


@pytest.fixture
def client():
    init_storage(force_memory=True)
    with TestClient(app) as test_client:
        yield test_client


def test_custom_signatures_catalog(client):
    res = client.get("/api/custom-signatures-catalog")
    assert res.status_code == 200
    data = res.json()
    assert "snortTemplates" in data
    assert "attackTypes" in data
    assert "systems" in data
    assert len(data["snortTemplates"]) >= 5
    assert "Buffer Overflow" in data["attackTypes"]


def test_custom_signatures_crud(client):
    # 1. List pre-seeded files
    list_res = client.get("/api/custom-signatures")
    assert list_res.status_code == 200
    files = list_res.json()
    assert any(f["tag"] == "Fruits" for f in files)

    # 2. Get Fruits
    get_res = client.get("/api/custom-signatures/Fruits")
    assert get_res.status_code == 200
    fruits_doc = get_res.json()
    assert fruits_doc["tag"] == "Fruits"
    assert len(fruits_doc["signatures"]) >= 2

    # 3. List all flattened signatures
    all_res = client.get("/api/custom-signatures/all")
    assert all_res.status_code == 200
    all_sigs = all_res.json()
    assert any(s["name"] == "Apple_medium_acc" and s["tag"] == "Fruits" for s in all_sigs)

    # 4. Create new custom signatures file
    new_doc = {
        "tag": "FinanceApp",
        "softwareVersion": "15.1.0",
        "signatures": [
            {
                "name": "Finance_Token_Theft",
                "rule": 'content:"account_token="; nocase;',
                "signatureType": "request",
                "attackType": {"name": "Information Leakage"},
                "systems": [{"name": "Unix/Linux"}],
                "risk": "high",
                "accuracy": "high",
            }
        ],
    }
    create_res = client.post("/api/custom-signatures", json={"tag": "FinanceApp", "content": new_doc})
    assert create_res.status_code == 201
    assert create_res.json()["tag"] == "FinanceApp"

    # 5. Export JSON
    exp_res = client.get("/api/custom-signatures/FinanceApp/export")
    assert exp_res.status_code == 200
    assert "signatures_FinanceApp.json" in exp_res.headers.get("content-disposition", "")
    exp_data = json.loads(exp_res.text)
    assert exp_data["tag"] == "FinanceApp"
    assert len(exp_data["signatures"]) == 1

    # 6. Delete
    del_res = client.delete("/api/custom-signatures/FinanceApp")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    # 7. Verify 404
    get_del = client.get("/api/custom-signatures/FinanceApp")
    assert get_del.status_code == 404


def test_custom_signatures_validation_endpoint(client):
    valid_payload = {
        "content": {
            "tag": "TestValidation",
            "signatures": [
                {
                    "name": "Valid_Sig",
                    "rule": 'content:"test"; nocase;',
                    "signatureType": "request",
                    "risk": "low",
                    "accuracy": "low",
                }
            ],
        }
    }
    res_val = client.post("/api/custom-signatures/validate", json=valid_payload)
    assert res_val.status_code == 200
    assert res_val.json()["valid"] is True

    invalid_payload = {
        "content": {
            "tag": "TestValidation",
            "signatures": [
                {
                    "name": "Bad_Sig",
                    # missing rule
                    "signatureType": "request",
                    "risk": "low",
                    "accuracy": "low",
                }
            ],
        }
    }
    res_inval = client.post("/api/custom-signatures/validate", json=invalid_payload)
    assert res_inval.status_code == 200
    assert res_inval.json()["valid"] is False
    assert any("missing required 'rule'" in e for e in res_inval.json()["errors"])


def test_custom_signatures_import_file(client):
    file_content = {
        "tag": "ImportedApp",
        "softwareVersion": "15.1.0",
        "signatures": [
            {
                "name": "Imported_Sig_1",
                "rule": 'content:"imported_pattern"; nocase;',
                "signatureType": "request",
                "risk": "medium",
                "accuracy": "high",
            }
        ],
    }
    file_bytes = json.dumps(file_content).encode("utf-8")
    upload_res = client.post(
        "/api/custom-signatures/import",
        files={"file": ("signatures_ImportedApp.json", io.BytesIO(file_bytes), "application/json")},
    )
    assert upload_res.status_code == 200
    data = upload_res.json()
    assert data["imported"] is True
    assert data["tag"] == "ImportedApp"

    # Confirm it is retrievable
    get_res = client.get("/api/custom-signatures/ImportedApp")
    assert get_res.status_code == 200
    assert len(get_res.json()["signatures"]) == 1


def test_custom_signatures_html_ui(client):
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    # Verify User-Defined Signatures section exists
    assert "User-Defined Signatures" in html
    # Verify Signature Requirements section exists
    assert "Signature Requirements" in html
    assert "signature-requirements" in html
    # Verify Snort Assistant and Cheat Sheet modal exists
    assert "Snort Rule Assistant" in html
    # Verify Custom Signature modal exists
    assert "showCustomSigModal" in html
    # Verify mode switcher for exceptions exists
    assert "User-Defined Signature (Name & Tag)" in html


def test_validate_snort_rule_api(client):
    # Valid rule
    res = client.post(
        "/api/custom-signatures/validate-snort-rule",
        json={"rule": 'content:"apple"; nocase;'},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert len(data["errors"]) == 0
    assert data["parsed"]["decoded_patterns"][0]["decoded"] == "apple"

    # Invalid rule: missing semicolon
    res_bad = client.post(
        "/api/custom-signatures/validate-snort-rule",
        json={"rule": 'content:"apple"'},
    )
    assert res_bad.status_code == 200
    data_bad = res_bad.json()
    assert data_bad["valid"] is False
    assert any("missing trailing semicolon" in e for e in data_bad["errors"])


def test_test_snort_rule_api(client):
    # Test matching rule
    res = client.post(
        "/api/custom-signatures/test-snort-rule",
        json={
            "rule": 'content:"apple"; nocase;',
            "context": {
                "uri": "/store/basket",
                "body": "User ordered red apple fruit",
            },
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["matched"] is True
    assert data["valid"] is True
    assert data["details"][0]["found_in_input"] is True

    # Test non-matching rule
    res_miss = client.post(
        "/api/custom-signatures/test-snort-rule",
        json={
            "rule": 'content:"apple"; nocase;',
            "context": {
                "uri": "/store/basket",
                "body": "User ordered orange fruit",
            },
        },
    )
    assert res_miss.status_code == 200
    assert res_miss.json()["matched"] is False


