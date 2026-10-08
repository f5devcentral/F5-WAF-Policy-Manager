"""
Unit and integration tests for URL-level parameters and signature set sanitization.
Verifies:
1. Scope-aware parameter duplication checks (multiple parameters with same name across different URLs/methods).
2. Detection of exact scope duplicates (same name, same URL, same method, same protocol).
3. Predefined signature set sanitization and foreign key protection against PLC.NEGSIG_SET_SIGNATURES failures.
4. REST API /api/policies/{name}/sanitize endpoint.
"""

import pytest
from fastapi.testclient import TestClient
from f5_waf_editor.app import app
from f5_waf_editor.storage import init_storage
from f5_waf_editor.compiler.compiler_service import WafCompilerService
from f5_waf_editor.schemas.waf_schema import sanitize_waf_policy


@pytest.fixture(autouse=True)
def setup_storage():
    init_storage(force_memory=True)


@pytest.fixture
def client():
    return TestClient(app)


def test_url_parameters_multi_endpoint_allowed():
    """Verify that multiple parameters with the same name on different URLs/methods are permitted."""
    service = WafCompilerService()
    policy_doc = {
        "policy": {
            "name": "multi_url_params_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "urls": [
                {"name": "/dibopcvm/asv*.png", "type": "wildcard", "method": "*"},
                {"name": "/api/users", "type": "explicit", "method": "POST"},
            ],
            "parameters": [
                # Parameter 1 on wildcard image URL
                {
                    "name": "xy",
                    "level": "url",
                    "type": "explicit",
                    "dataType": "alpha-numeric",
                    "url": {
                        "name": "/dibopcvm/asv*.png",
                        "method": "*",
                        "protocol": "http",
                        "type": "wildcard",
                    },
                    "valueType": "user-input",
                },
                # Parameter 2 on API POST URL
                {
                    "name": "xy",
                    "level": "url",
                    "type": "explicit",
                    "dataType": "integer",
                    "url": {
                        "name": "/api/users",
                        "method": "POST",
                        "protocol": "https",
                        "type": "explicit",
                    },
                    "valueType": "user-input",
                },
                # Parameter 3 global scope
                {
                    "name": "xy",
                    "level": "global",
                    "type": "explicit",
                    "dataType": "string",
                    "valueType": "user-input",
                },
            ],
        }
    }

    result = service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="multi_url_params_policy",
    )

    # Should succeed without duplicate parameter errors
    assert result["success"] is True
    duplicate_errors = [e for e in result["errors"] if e.get("code") == "ERR_DUPLICATE_PARAMETER"]
    assert len(duplicate_errors) == 0


def test_url_parameters_exact_duplicate_rejected():
    """Verify that true duplicate parameters (same name, level, URL, method, protocol) are rejected."""
    service = WafCompilerService()
    policy_doc = {
        "policy": {
            "name": "duplicate_url_param_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "parameters": [
                {
                    "name": "xy",
                    "level": "url",
                    "type": "explicit",
                    "url": {
                        "name": "/search",
                        "method": "GET",
                        "protocol": "http",
                        "type": "explicit",
                    },
                },
                {
                    "name": "xy",
                    "level": "url",
                    "type": "explicit",
                    "url": {
                        "name": "/search",
                        "method": "GET",
                        "protocol": "http",
                        "type": "explicit",
                    },
                },
            ],
        }
    }

    result = service.test_compilation(
        target_type="policy",
        content=policy_doc,
        target_name="duplicate_url_param_policy",
    )

    assert result["success"] is False
    duplicate_errors = [e for e in result["errors"] if e.get("code") == "ERR_DUPLICATE_PARAMETER"]
    assert len(duplicate_errors) == 1
    assert "xy" in duplicate_errors[0]["message"]
    assert "/search" in duplicate_errors[0]["message"]


def test_signature_sets_foreign_key_sanitization():
    """Verify that signature set sanitization prevents SQLite foreign key failures."""
    raw_policy = {
        "policy": {
            "name": "test_sig_set_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                {"name": "Threat Campaigns", "alarm": True, "block": True},
                {"name": "Directory Traversal Signatures", "alarm": True, "block": True},
                {"name": "Completely Bogus Non-Existent Signature Set", "alarm": True, "block": True},
                {"name": "High Accuracy Signatures", "alarm": True, "block": False},
            ],
        }
    }

    sanitized = sanitize_waf_policy(raw_policy)
    pol = sanitized["policy"]

    # Threat Campaigns must be moved to VIOL_THREAT_CAMPAIGN in blocking-settings
    sig_set_names = [s["name"] for s in pol["signature-sets"]]
    assert "Threat Campaigns" not in sig_set_names
    assert "Completely Bogus Non-Existent Signature Set" not in sig_set_names
    # Directory Traversal should be aliased to official Path Traversal Signatures
    assert "Path Traversal Signatures" in sig_set_names
    assert "High Accuracy Signatures" in sig_set_names

    # Check blocking settings for VIOL_THREAT_CAMPAIGN
    violations = pol.get("blocking-settings", {}).get("violations", [])
    tc_violation = next((v for v in violations if v.get("name") == "VIOL_THREAT_CAMPAIGN"), None)
    assert tc_violation is not None
    assert tc_violation["alarm"] is True
    assert tc_violation["block"] is True


def test_api_sanitize_policy_endpoint(client):
    """Verify the POST /api/policies/{name}/sanitize REST API endpoint."""
    from f5_waf_editor.storage import get_storage
    storage = get_storage()
    pol_name = "test_api_sanitize_policy"
    storage.save_policy(
        pol_name,
        {
            "policy": {
                "name": pol_name,
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "signature-sets": [
                    {"name": "threat-campaigns", "alarm": True, "block": True},
                    {"name": "XSS Signatures", "alarm": True, "block": True},
                ],
            }
        },
        pre_validated=True,
    )

    # Sanitize it
    resp = client.post(f"/api/policies/{pol_name}/sanitize")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "threat-campaigns" not in [s["name"] for s in data["policy"]["policy"].get("signature-sets", [])]
    violations = data["policy"]["policy"].get("blocking-settings", {}).get("violations", [])
    assert any(v.get("name") == "VIOL_THREAT_CAMPAIGN" for v in violations)


def test_sanitize_waf_policy_recursive_polymorphic_unwrapping():
    """Verify that sanitize_waf_policy cleanly unwraps arbitrary nesting of {"policy": {"policy": ...}}."""
    deeply_nested = {
        "policy": {
            "policy": {
                "policy": {
                    "name": "deeply_nested_policy",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                    "signature-sets": [
                        {"name": "Directory Traversal Signatures", "alarm": True, "block": True},
                        {"name": "Cross-Site Scripting Signatures", "alarm": True, "block": True},
                        {"name": "SQL-Injection Signatures", "alarm": True, "block": True},
                        {"name": "Threat Campaigns", "alarm": True, "block": True},
                        {"name": "NonExistentPredefinedSet", "alarm": True, "block": True},
                    ],
                }
            }
        }
    }

    sanitized = sanitize_waf_policy(deeply_nested)
    # Must be single-level {"policy": {...}}
    assert "policy" in sanitized
    assert "policy" not in sanitized["policy"]
    inner = sanitized["policy"]
    assert inner["name"] == "deeply_nested_policy"

    # Signature sets must be normalized and cleaned
    names = [s["name"] for s in inner["signature-sets"]]
    assert "Path Traversal Signatures" in names
    assert "Directory Traversal Signatures" not in names
    assert "Cross Site Scripting Signatures" in names
    assert "Cross-Site Scripting Signatures" not in names
    assert "SQL Injection Signatures" in names
    assert "SQL-Injection Signatures" not in names
    assert "Threat Campaigns" not in names
    assert "NonExistentPredefinedSet" not in names

    # Threat Campaigns violation must be created
    viols = inner.get("blocking-settings", {}).get("violations", [])
    assert any(v.get("name") == "VIOL_THREAT_CAMPAIGN" for v in viols)


def test_bigip_converter_omits_unrecognized_signature_sets():
    """Verify BIG-IP converter omits unknown predefined signature sets to prevent SQLite FK failures."""
    from f5_waf_editor.converters.bigip_converter import BigIpPolicyConverter

    bigip_policy = {
        "policy": {
            "name": "bigip_imported_policy",
            "enforcementMode": "blocking",
            "signature-sets": [
                {"name": "Directory Traversal Signatures", "alarm": True, "block": True},
                {"name": "Legacy Undefined ASM Signature Set", "alarm": True, "block": True},
                {"name": "High Accuracy Signatures", "alarm": True, "block": True},
            ],
        }
    }

    converter = BigIpPolicyConverter()
    result = converter.convert(bigip_policy)
    assert result["success"] is True

    converted_pol = result["policy"]["policy"]
    converted_sets = [s["name"] for s in converted_pol["signature-sets"]]
    assert "Path Traversal Signatures" in converted_sets
    assert "High Accuracy Signatures" in converted_sets
    assert "Legacy Undefined ASM Signature Set" not in converted_sets

    warnings = result.get("warnings", [])
    assert any("Legacy Undefined ASM Signature Set" in w for w in warnings)


def test_sanitize_waf_policy_strips_non_configurable_violations():
    """Verify that VIOL_ATTACK_SIGNATURE and VIOL_BOT_CLIENT are stripped from blocking-settings.violations."""
    policy = {
        "policy": {
            "name": "viol_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_DATA_GUARD", "alarm": True, "block": False},
                    {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                    {"name": "VIOL_BOT_CLIENT", "alarm": True, "block": True},
                    {"name": "VIOL_EVASION", "alarm": True, "block": True},
                ]
            }
        }
    }

    sanitized = sanitize_waf_policy(policy)
    violations = sanitized["policy"]["blocking-settings"]["violations"]
    viol_names = [v["name"] for v in violations]
    assert "VIOL_DATA_GUARD" in viol_names
    assert "VIOL_EVASION" in viol_names
    assert "VIOL_ATTACK_SIGNATURE" not in viol_names
    assert "VIOL_BOT_CLIENT" not in viol_names


def test_sanitize_waf_policy_normalizes_server_technologies():
    """Verify that server technologies are normalized with aliases and unknown ones are omitted."""
    policy = {
        "policy": {
            "name": "tech_test_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "server-technologies": [
                {"serverTechnologyName": "Apache"},
                {"serverTechnologyName": "Microsoft IIS"},
                {"serverTechnologyName": "node"},
                {"serverTechnologyName": "Nginx"},
                {"serverTechnologyName": "UnknownFakeTech123"},
                "postgres",
            ]
        }
    }

    sanitized = sanitize_waf_policy(policy)
    techs = sanitized["policy"]["server-technologies"]
    tech_names = [t["serverTechnologyName"] for t in techs]

    assert "Apache/NCSA HTTP Server" in tech_names
    assert "IIS" in tech_names
    assert "Node.js" in tech_names
    assert "Nginx" in tech_names
    assert "PostgreSQL" in tech_names
    assert "UnknownFakeTech123" not in tech_names
    assert "Apache" not in tech_names
    assert "Microsoft IIS" not in tech_names


def test_user_policy_full_sanitization():
    """Verify sanitization of the exact user policy from the error report."""
    user_policy = {
        "policy": {
            "name": "test-policy",
            "description": "Test full + dataguard",
            "template": {
                "name": "POLICY_TEMPLATE_NGINX_BASE"
            },
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "server-technologies": [
                {"serverTechnologyName": "Apache"},
                {"serverTechnologyName": "Microsoft Windows"},
                {"serverTechnologyName": "InvalidLegacyTechnology"},
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_RATING_NEED_EXAMINATION", "alarm": False, "block": False},
                    {"name": "VIOL_EVASION", "alarm": True, "block": False},
                    {"name": "VIOL_DATA_GUARD", "alarm": True, "block": False},
                    {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                    {"name": "VIOL_THREAT_CAMPAIGN", "alarm": True, "block": True},
                    {"name": "VIOL_BOT_CLIENT", "alarm": True, "block": True},
                    {"name": "VIOL_HTTP_PROTOCOL", "alarm": True, "block": False},
                ]
            }
        }
    }

    sanitized = sanitize_waf_policy(user_policy)
    pol = sanitized["policy"]

    # Verify violations
    viols = [v["name"] for v in pol["blocking-settings"]["violations"]]
    assert "VIOL_ATTACK_SIGNATURE" not in viols
    assert "VIOL_BOT_CLIENT" not in viols
    assert "VIOL_THREAT_CAMPAIGN" in viols
    assert "VIOL_DATA_GUARD" in viols
    assert "VIOL_EVASION" in viols

    # Verify server technologies
    techs = [t["serverTechnologyName"] for t in pol["server-technologies"]]
    assert "Apache/NCSA HTTP Server" in techs
    assert "Microsoft Windows" in techs
    assert "InvalidLegacyTechnology" not in techs
    assert "Apache" not in techs


def test_validator_warns_on_non_configurable_violations_and_server_techs():
    """Verify validator produces warnings for non-configurable violations and aliased/unknown server techs."""
    from f5_waf_editor.schemas.validator import validate_policy_json

    policy = {
        "policy": {
            "name": "validator_test",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "server-technologies": [
                {"serverTechnologyName": "Apache"},
                {"serverTechnologyName": "NonExistentTechXYZ"},
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                    {"name": "VIOL_BOT_CLIENT", "alarm": True, "block": True},
                ]
            }
        }
    }

    is_valid, errors, warnings, _ = validate_policy_json(policy)
    assert is_valid is True
    assert any("VIOL_ATTACK_SIGNATURE" in w and "cannot be configured" in w for w in warnings)
    assert any("VIOL_BOT_CLIENT" in w and "cannot be configured" in w for w in warnings)
    assert any("Apache" in w and "Apache/NCSA HTTP Server" in w for w in warnings)
    assert any("NonExistentTechXYZ" in w and "not recognized" in w for w in warnings)


def test_compiler_remediation_on_server_tech_and_violation_errors():
    """Verify compiler service returns actionable remediation for PL_SERVER_TECHNOLOGIES and cannot be configured."""
    from f5_waf_editor.compiler.compiler_service import WafCompilerService

    compiler = WafCompilerService()
    rem1 = compiler.get_remediation("Could not add the '/policy/server-technologies' element. Failed on insert to PLC.PL_SERVER_TECHNOLOGIES (DBD::SQLite::db do failed: NOT NULL constraint failed: PL_SERVER_TECHNOLOGIES.server_technology_id)")
    assert "Apache/NCSA HTTP Server" in rem1

    rem2 = compiler.get_remediation("/blocking-settings/violations/name value 'VIOL_ATTACK_SIGNATURE' cannot be configured.")
    assert "VIOL_ATTACK_SIGNATURE" in rem2


def test_sanitize_custom_and_manual_signature_sets():
    """Verify custom signature sets with root filters/signatures, string attackType, and integer lists are cleanly normalized."""
    policy = {
        "policy": {
            "name": "sig_sets_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                # 1. Custom set with root-level filter and string attackType
                {
                    "name": "Custom Filter Set",
                    "alarm": True,
                    "block": True,
                    "filter": {
                        "attackType": "SQL Injection",
                        "riskValue": "high",
                    },
                },
                # 2. Custom set with root-level signatures as list of ints/strings
                {
                    "name": "Custom Manual Set",
                    "alarm": True,
                    "block": False,
                    "signatures": [200001000, "200001001", {"signatureId": 200001002}],
                },
                # 3. Empty custom signatureSet (must be stripped)
                {
                    "name": "Empty Custom Set",
                    "alarm": True,
                    "block": True,
                    "signatureSet": {},
                },
                # 4. Unknown predefined set without signatureSet (must be stripped)
                {
                    "name": "FakePredefinedSet123",
                    "alarm": True,
                    "block": True,
                },
                # 5. Valid predefined set
                {
                    "name": "Command Execution Signatures",
                    "alarm": True,
                    "block": True,
                },
            ],
        }
    }

    sanitized = sanitize_waf_policy(policy)
    sets = sanitized["policy"]["signature-sets"]

    names = [s["name"] for s in sets]
    assert "Custom Filter Set" in names
    assert "Custom Manual Set" in names
    assert "Empty Custom Set" not in names
    assert "FakePredefinedSet123" not in names
    assert "Command Execution Signatures" in names

    # Verify Custom Filter Set has signatureSet with wrapped attackType
    c_filt = next(s for s in sets if s["name"] == "Custom Filter Set")
    assert "signatureSet" in c_filt
    assert c_filt["signatureSet"]["type"] == "filter-based"
    assert c_filt["signatureSet"]["filter"]["attackType"] == {"name": "SQL Injection"}
    assert "filter" not in c_filt

    # Verify Custom Manual Set has signatureSet with normalized signatures list
    c_man = next(s for s in sets if s["name"] == "Custom Manual Set")
    assert "signatureSet" in c_man
    assert c_man["signatureSet"]["type"] == "manual"
    assert c_man["signatureSet"]["signatures"] == [
        {"signatureId": 200001000},
        {"signatureId": 200001001},
        {"signatureId": 200001002},
    ]
    assert "signatures" not in c_man



