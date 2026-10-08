"""
Tests for F5 WAF Logging Profile REST API Endpoints.
"""

import io
import pytest
from fastapi.testclient import TestClient
from f5_waf_editor.app import app
from f5_waf_editor.storage import init_storage


@pytest.fixture(autouse=True)
def setup_storage():
    init_storage(force_memory=True)


client = TestClient(app)


def test_list_logging_profiles():
    res = client.get("/api/log-profiles")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 5


def test_get_logging_profile_success():
    res = client.get("/api/log-profiles/log_default")
    assert res.status_code == 200
    doc = res.json()
    assert "filter" in doc
    assert "content" in doc
    assert doc["content"]["format"] == "default"


def test_get_logging_profile_not_found():
    res = client.get("/api/log-profiles/non_existent_profile_xyz")
    assert res.status_code == 404


def test_create_and_delete_logging_profile():
    # 1. Create from template
    create_res = client.post(
        "/api/log-profiles",
        json={"name": "my_new_log", "template_id": "log_splunk"},
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["metadata"]["name"] == "my_new_log"

    # 2. Duplicate create fails
    dup_res = client.post(
        "/api/log-profiles",
        json={"name": "my_new_log", "template_id": "log_default"},
    )
    assert dup_res.status_code == 409

    # 3. Update profile
    update_res = client.put(
        "/api/log-profiles/my_new_log",
        json={
            "content": {
                "filter": {"request_type": "all"},
                "content": {"format": "splunk", "max_message_size": "40k"},
            }
        },
    )
    assert update_res.status_code == 200

    # 4. Clone profile
    clone_res = client.post(
        "/api/log-profiles/my_new_log/clone",
        json={"new_name": "my_new_log_cloned"},
    )
    assert clone_res.status_code == 200

    # 5. Delete both
    del_res1 = client.delete("/api/log-profiles/my_new_log")
    assert del_res1.status_code == 200
    del_res2 = client.delete("/api/log-profiles/my_new_log_cloned")
    assert del_res2.status_code == 200


def test_export_and_import_logging_profile():
    # 1. Export
    exp_res = client.get("/api/log-profiles/log_default/export")
    assert exp_res.status_code == 200
    content = exp_res.content

    # 2. Import under new name
    files = {"file": ("imported_test_log.json", io.BytesIO(content), "application/json")}
    imp_res = client.post("/api/log-profiles/import", files=files)
    assert imp_res.status_code == 200

    # Check imported profile exists
    check_res = client.get("/api/log-profiles/imported_test_log")
    assert check_res.status_code == 200

    # Cleanup
    client.delete("/api/log-profiles/imported_test_log")


def test_logging_templates_and_catalog():
    tmpl_res = client.get("/api/log-templates")
    assert tmpl_res.status_code == 200
    assert len(tmpl_res.json()) >= 6

    cat_res = client.get("/api/log-catalog")
    assert cat_res.status_code == 200
    catalog = cat_res.json()
    assert "request_types" in catalog
    assert "formats" in catalog
    assert "attributes" in catalog
    assert len(catalog["attributes"]) >= 30
