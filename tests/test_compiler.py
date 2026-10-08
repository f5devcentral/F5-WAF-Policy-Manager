"""
Unit and integration tests for F5 WAF Compiler Service.
Verifies compiler execution, bundle creation (.tgz), diagnostics generation, and remediation guidance.
"""

import io
import json
import tarfile
import pytest
from f5_waf_editor.compiler.compiler_service import (
    WafCompilerService,
    compile_target,
    REMEDIATION_MAP,
)


def test_compiler_service_policy_success():
    service = WafCompilerService()
    policy_doc = {
        "policy": {
            "name": "unit_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "urls": [
                {"name": "/api/users", "type": "explicit", "method": "GET"},
                {"name": "/api/orders", "type": "explicit", "method": "POST"},
            ],
            "parameters": [
                {"name": "user_id", "type": "explicit", "valueType": "user-input"},
            ],
            "server-technologies": [
                {"serverTechnologyName": "Nginx"},
            ],
        }
    }

    result = service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="unit_test_policy",
        include_source=True,
    )

    assert result["success"] is True
    assert result["target_name"] == "unit_test_policy"
    assert result["target_type"] == "policy"
    assert result["bundle_id"] is not None
    assert result["bundle_size"] > 0
    assert result["bundle_sha256"] is not None
    assert len(result["errors"]) == 0

    # Verify bundle contents
    bundle = service.get_bundle(result["bundle_id"])
    assert bundle is not None
    tar_bytes = bundle["bytes"]
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "policy.json" in names

        manifest_file = tar.extractfile("manifest.json")
        manifest = json.loads(manifest_file.read().decode("utf-8"))
        assert manifest["name"] == "unit_test_policy"
        assert manifest["bundle_type"] == "policy"


def test_compiler_service_log_profile_success():
    service = WafCompilerService()
    profile_doc = {
        "filter": {
            "request_type": "all",
        },
        "content": {
            "format": "default",
            "max_request_size": "2k",
            "max_message_size": "10k",
        },
    }

    result = service.test_compilation(
        target_type="log_profile",
        content=profile_doc,
        target_name="unit_test_log_profile",
    )

    assert result["success"] is True
    assert result["bundle_id"] is not None
    assert result["bundle_name"] == "unit_test_log_profile_compiled.tgz"
    assert len(result["errors"]) == 0

    bundle = service.get_bundle(result["bundle_id"])
    with tarfile.open(fileobj=io.BytesIO(bundle["bytes"]), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "logging_profile.json" in names


def test_compiler_service_failure_diagnostics():
    service = WafCompilerService()
    # Invalid policy with duplicate URLs and duplicate parameters
    invalid_policy = {
        "policy": {
            "name": "invalid_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "urls": [
                {"name": "/api/v1/test", "type": "explicit", "protocol": "http"},
                {"name": "/api/v1/test", "type": "explicit", "protocol": "http"},
            ],
            "parameters": [
                {"name": "token", "parameterLocation": "query"},
                {"name": "token", "parameterLocation": "query"},
            ],
        }
    }

    result = service.test_compilation(
        target_type="policy",
        content=invalid_policy,
        target_name="invalid_policy",
    )

    assert result["success"] is False
    assert result["bundle_id"] is None
    assert len(result["errors"]) >= 2

    dup_url = next((e for e in result["errors"] if e["code"] == "ERR_DUPLICATE_URL"), None)
    assert dup_url is not None
    assert "/policy/urls/1" in dup_url["path"]
    assert dup_url["solution"] is not None

    dup_param = next((e for e in result["errors"] if e["code"] == "ERR_DUPLICATE_PARAMETER"), None)
    assert dup_param is not None
    assert "/policy/parameters/1" in dup_param["path"]
    assert dup_param["solution"] is not None


def test_compiler_convenience_function():
    policy_doc = {
        "policy": {
            "name": "conv_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
        }
    }
    result = compile_target("policy", policy_doc, "conv_policy")
    assert result["success"] is True
    assert result["bundle_name"] == "conv_policy_compiled.tgz"


def test_apcompile_service_container_server():
    """Test the dedicated apcompile service container HTTP API endpoints."""
    from fastapi.testclient import TestClient
    from f5_waf_editor.compiler.server import app as apcompile_app

    client = TestClient(apcompile_app)

    # 1. Health check
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"
    assert health_res.json()["service"] == "apcompile"

    # 2. Status
    status_res = client.get("/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["status"] == "ready"
    assert status_data["service"] == "apcompile"
    assert "version" in status_data
    assert "engine" in status_data

    # 3. Post compile
    policy_doc = {
        "policy": {
            "name": "remote_service_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
        }
    }
    compile_res = client.post(
        "/compile",
        json={
            "target_type": "policy",
            "content": policy_doc,
            "target_name": "remote_service_test_policy",
        },
    )
    assert compile_res.status_code == 200
    data = compile_res.json()
    assert data["success"] is True
    assert "bundle_base64" in data
    bundle_id = data["bundle_id"]
    assert bundle_id is not None

    # 4. Download bundle
    dl_res = client.get(f"/download/{bundle_id}")
    assert dl_res.status_code == 200
    assert dl_res.headers["Content-Type"] == "application/gzip"
    assert len(dl_res.content) > 0

    with tarfile.open(fileobj=io.BytesIO(dl_res.content), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "policy.json" in names

    # 5. Test v1/compile/policy (NAP-Compiler-REST-API compatible)
    v1_pol_res = client.post(
        "/v1/compile/policy",
        json={
            "policy": policy_doc,
            "target_name": "v1_compiled_policy",
        },
    )
    assert v1_pol_res.status_code == 200
    v1_pol_data = v1_pol_res.json()
    assert v1_pol_data["status"] == "success"
    assert v1_pol_data["bundle"] != ""
    bundle_b64 = v1_pol_data["bundle"]

    # 6. Test v1/compile/logprofile (NAP-Compiler-REST-API compatible)
    log_doc = {
        "filter": {"request_type": "all"},
        "content": {"format": "default"},
    }
    v1_log_res = client.post(
        "/v1/compile/logprofile",
        json={
            "logprofile": log_doc,
            "target_name": "v1_compiled_logprofile",
        },
    )
    assert v1_log_res.status_code == 200
    v1_log_data = v1_log_res.json()
    assert v1_log_data["status"] == "success"
    assert v1_log_data["bundle"] != ""

    # 7. Test v1/bundle/info (NAP-Compiler-REST-API compatible)
    info_res = client.post(
        "/v1/bundle/info",
        json={
            "bundle": bundle_b64,
        },
    )
    assert info_res.status_code == 200
    info_data = info_res.json()
    assert info_data["status"] == "success"
    assert "manifest" in info_data
    assert "files" in info_data
    assert "manifest.json" in info_data["files"]


def test_compiler_stdout_json_payload_format():
    """Verify that compiler stdout returns valid beautified JSON with completed_successfully and warnings."""
    service = WafCompilerService()

    # 1. Success case
    policy_doc = {
        "policy": {
            "name": "test_json_stdout_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
        }
    }
    success_result = service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="test_json_stdout_policy",
    )
    assert success_result["success"] is True
    assert success_result["stdout"] is not None
    success_json = json.loads(success_result["stdout"])
    assert success_json["completed_successfully"] is True
    assert "warnings" in success_json
    assert isinstance(success_json["warnings"], list)
    assert success_json["bundle_name"] == "test_json_stdout_policy_compiled.tgz"

    # 2. Failure case
    invalid_policy = {"not_a_valid_policy": 123}
    fail_result = service.test_compilation(
        target_type="policy",
        content=invalid_policy,
        target_name="invalid_policy",
    )
    assert fail_result["success"] is False
    assert fail_result["stdout"] is not None
    fail_json = json.loads(fail_result["stdout"])
    assert fail_json["completed_successfully"] is False
    assert "warnings" in fail_json
    assert "errors" in fail_json
    assert len(fail_json["errors"]) > 0


def test_compiler_remediation_foreign_key_signature_sets():
    service = WafCompilerService()
    # User's exact error message from apcompile SQLite BatchInsert failure
    error_msg = (
        "Failed to import policy from '/tmp/tmpvfz96g8h/policy.json' - Could not add the "
        "'/policy/signature-sets' element. Failed to insert to PLC.NEGSIG_SET_SIGNATURES "
        "(DBD::SQLite::db do failed: FOREIGN KEY constraint failed at /opt/app_protect/bin/../lib/perl/F5/BatchInsert.pm line 243.\n)"
    )

    formatted = service._format_cli_error(error_msg)
    assert formatted["code"] == "ERR_COMPILER_DIAGNOSTIC"
    assert formatted["path"] == "/policy/signature-sets"
    assert "FOREIGN KEY constraint failed" in formatted["message"]
    assert formatted["solution"] is not None
    assert "VIOL_THREAT_CAMPAIGN" in formatted["solution"]
    assert "Path Traversal Signatures" in formatted["solution"]




