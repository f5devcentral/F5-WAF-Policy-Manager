"""
Tests for Custom Signatures compilation and bundle packaging.
"""

import io
import json
import tarfile
from unittest.mock import MagicMock, patch
from f5_waf_editor.compiler.compiler_service import WafCompilerService
from f5_waf_editor.storage import init_storage


def test_compile_policy_with_custom_signatures_packages_signatures_file():
    init_storage(force_memory=True)
    compiler_service = WafCompilerService()

    policy_doc = {
        "policy": {
            "name": "custom_sigs_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "signature-requirements": [
                {
                    "tag": "Fruits",
                    "minRevisionDatetime": "2020-01-20T18:32:02Z",
                }
            ],
            "signatures": [
                {
                    "name": "Apple_medium_acc",
                    "tag": "Fruits",
                    "enabled": False,
                }
            ],
            "custom-signatures": [
                {
                    "name": "Apple_medium_acc",
                    "tag": "Fruits",
                    "rule": 'content:"apple"; nocase;',
                    "signatureType": "request",
                    "attackType": {"name": "Buffer Overflow"},
                    "systems": [{"name": "Microsoft Windows"}, {"name": "Unix/Linux"}],
                    "risk": "medium",
                    "accuracy": "medium",
                    "description": "Custom signature for Apple exploits",
                }
            ],
        }
    }

    res = compiler_service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="custom_sigs_test_policy",
    )

    assert res["success"] is True
    assert res["diagnostics"]["custom_signatures_count"] == 1
    assert res["diagnostics"]["signature_requirements_count"] == 1

    # Retrieve bundle and inspect contents
    bundle_id = res["bundle_id"]
    bundle_info = compiler_service.get_bundle(bundle_id)
    assert bundle_info is not None
    bundle_bytes = bundle_info["bytes"]

    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "policy.json" in names
        assert "user_defined_signatures.json" in names
        assert "user_defined_signatures_Fruits.json" in names

        # Verify policy.json inside the bundle NEVER contains custom-signatures
        pol_member = tar.extractfile("policy.json")
        pol_json = json.loads(pol_member.read().decode("utf-8"))
        pol_root = pol_json.get("policy", pol_json)
        assert "custom-signatures" not in pol_root
        assert "user-defined-signatures" not in pol_root
        # But signature-requirements is preserved!
        assert any(r.get("tag") == "Fruits" for r in pol_root.get("signature-requirements", []))

        # Verify user_defined_signatures.json
        sig_member = tar.extractfile("user_defined_signatures.json")
        sig_data = json.loads(sig_member.read().decode("utf-8"))
        assert sig_data["tag"] == "Fruits"
        assert len(sig_data["signatures"]) == 1
        assert sig_data["signatures"][0]["name"] == "Apple_medium_acc"


def test_compile_warns_on_missing_signature_requirement_tag():
    init_storage(force_memory=True)
    compiler_service = WafCompilerService()

    policy_doc = {
        "policy": {
            "name": "missing_tag_policy",
            "signature-requirements": [
                {
                    "tag": "NonExistentTag_XYZ_123",
                }
            ],
        }
    }

    res = compiler_service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="missing_tag_policy",
    )

    assert res["success"] is True
    assert any("NonExistentTag_XYZ_123" in w for w in res["warnings"])


def test_compile_via_cli_constructs_user_signature_flags():
    """Verify that _compile_via_cli properly passes -s user_signatures_<tag>.json to apcompile."""
    init_storage(force_memory=True)
    compiler_service = WafCompilerService()
    compiler_service.compiler_bin = "/mock/bin/apcompile"

    policy_doc = {
        "policy": {
            "name": "cli_sig_test",
            "signature-requirements": [{"tag": "Fruits"}],
            "custom-signatures": [
                {
                    "name": "Apple",
                    "tag": "Fruits",
                    "rule": 'content:"apple";',
                }
            ],
        }
    }

    captured_cmds = []

    def mock_popen(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("Success", "")
        # Create dummy output file
        out_idx = cmd.index("-o") + 1
        out_file = cmd[out_idx]
        with open(out_file, "wb") as f:
            f.write(b"dummy_tgz")
        return mock_proc

    with patch("subprocess.Popen", side_effect=mock_popen):
        res = compiler_service._compile_via_cli(
            target_type="policy",
            content=policy_doc,
            target_name="cli_sig_test",
            include_source=False,
            full_export=False,
            global_settings=None,
            start_time=0.0,
        )

    assert res["success"] is True
    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "-p" in cmd
    assert "-s" in cmd
    s_idx = cmd.index("-s")
    assert "user_signatures_Fruits.json" in cmd[s_idx + 1]


def test_compiler_service_parses_fruits_tag_error_with_remediation():
    """Test that compiler error for missing tag produces clear structured remediation."""
    compiler_service = WafCompilerService()

    raw_err = "Failed to import policy from '/tmp/tmp3l039oeh/policy.json' - Unknown path 'custom-signatures'\nCould not add the '/policy/signature-requirements' element. 'Fruits' tag does not exist."
    formatted = compiler_service._format_cli_error(raw_err)

    assert formatted["code"] == "ERR_COMPILER_CUSTOM_SIGNATURES"
    assert formatted["path"] == "/policy/signature-requirements"
    assert "Fruits" in formatted["solution"] or "user-defined signatures" in formatted["solution"]


def test_compiler_service_via_service_error_mapping():
    """Verify _compile_via_service parses container errors into structured diagnostics."""
    compiler_service = WafCompilerService()
    compiler_service.compiler_service_url = "http://mock-compiler:8000"

    mock_resp_json = {
        "error_message": "Failed to import policy from '/tmp/tmp3l039oeh/policy.json' - Unknown path 'custom-signatures'\nCould not add the '/policy/signature-requirements' element. 'Fruits' tag does not exist.",
        "compiler_engine": "full",
        "completed_successfully": False,
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_resp_json).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = compiler_service._compile_via_service(
            target_type="policy",
            content={"policy": {"name": "test_service_policy", "signature-requirements": [{"tag": "Fruits"}]}},
            target_name="test_service_policy",
            include_source=False,
            full_export=False,
            global_settings=None,
            start_time=0.0,
        )

    assert res is not None
    assert res["success"] is False
    assert len(res["errors"]) >= 1
    # Check that error was mapped to signature-requirements and has remediation
    sig_err = next((e for e in res["errors"] if e.get("path") == "/policy/signature-requirements"), None)
    assert sig_err is not None
    assert "Fruits" in sig_err["solution"] or "user-defined signatures" in sig_err["solution"]


def test_compiler_server_endpoints_with_user_signatures():
    """Test FastAPI compiler container server /compile and /v1/compile/policy endpoints."""
    from fastapi.testclient import TestClient
    from f5_waf_editor.compiler.server import app as server_app

    client = TestClient(server_app)

    policy_data = {
        "policy": {
            "name": "api_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-requirements": [{"tag": "Fruits"}],
        }
    }
    user_sigs = {
        "tag": "Fruits",
        "signatures": [
            {
                "name": "Apple_Sig",
                "tag": "Fruits",
                "rule": 'content:"apple";',
            }
        ],
    }

    # 1. Test /compile endpoint
    compile_payload = {
        "target_type": "policy",
        "content": policy_data,
        "target_name": "api_test_policy",
        "user_signatures": user_sigs,
    }
    res = client.post("/compile", json=compile_payload)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["success"] is True
    assert "bundle_base64" in res_data
    # Unpack base64 and verify policy.json has NO custom-signatures
    import base64
    bundle_bytes = base64.b64decode(res_data["bundle_base64"])
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        assert "policy.json" in names
        assert "user_defined_signatures.json" in names
        assert "user_defined_signatures_Fruits.json" in names
        pol_raw = json.loads(tar.extractfile("policy.json").read().decode("utf-8"))
        pol_root = pol_raw.get("policy", pol_raw)
        assert "custom-signatures" not in pol_root
        assert "user-defined-signatures" not in pol_root

    # 2. Test /v1/compile/policy endpoint
    v1_payload = {
        "policy": policy_data,
        "user-signatures": user_sigs,
        "target_name": "api_test_policy",
    }
    v1_res = client.post("/v1/compile/policy", json=v1_payload)
    assert v1_res.status_code == 200
    v1_data = v1_res.json()
    assert v1_data["status"] == "success"
    assert v1_data["bundle"] != ""
    bundle_bytes_v1 = base64.b64decode(v1_data["bundle"])
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes_v1), mode="r:gz") as tar:
        pol_raw_v1 = json.loads(tar.extractfile("policy.json").read().decode("utf-8"))
        pol_root_v1 = pol_raw_v1.get("policy", pol_raw_v1)
        assert "custom-signatures" not in pol_root_v1
        assert "user-defined-signatures" not in pol_root_v1
