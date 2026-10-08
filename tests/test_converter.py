"""
Unit and integration tests for BIG-IP WAF Policy Converter.
Verifies conversion from BIG-IP ASM exported JSON policies to F5 WAF for NGINX declarative JSON policies.
"""

import gzip
import json
import pytest
from f5_waf_editor.converters.bigip_converter import (
    BigIpPolicyConverter,
    convert_bigip_policy,
    convert_bigip_policy_json,
    UNSUPPORTED_ASM_VIOLATIONS,
)


def test_converter_plain_json_basic():
    bigip_json = {
        "name": "my_bigip_app_sec",
        "description": "Imported policy description",
        "enforcementMode": "blocking",
        "applicationLanguage": "utf-8",
        "urls": [
            {"name": "/api/v1/auth", "type": "explicit", "protocol": "https"},
            {"name": "/*", "type": "wildcard", "protocol": "all"},
        ],
        "parameters": [
            {"name": "auth_token", "type": "explicit", "valueType": "alpha-numeric"},
            {"name": "*", "type": "wildcard"},
        ],
        "serverTechnologies": [
            {"serverTechnologyName": "Nginx"},
            {"serverTechnologyName": "Linux"},
        ],
    }

    converter = BigIpPolicyConverter()
    result = converter.convert(json.dumps(bigip_json).encode("utf-8"), target_name="custom_app_sec")

    assert result["success"] is True
    assert result["policy_name"] == "custom_app_sec"
    policy = result["policy"]["policy"]
    assert policy["name"] == "custom_app_sec"
    assert policy["description"] == "Imported policy description"
    assert policy["enforcementMode"] == "blocking"
    assert len(policy["urls"]) == 2
    assert len(policy["parameters"]) == 2
    assert len(policy["server-technologies"]) == 2


def test_converter_nested_policy_json():
    bigip_json = {
        "policy": {
            "name": "production_asm_policy",
            "enforcementMode": "transparent",
            "server-technologies": [
                {"serverTechnologyName": "Apache"},
            ],
            "signature-sets": [
                {"name": "High Accuracy Signatures", "alarm": True, "block": True}
            ],
            "urls": [
                {"name": "/checkout", "type": "explicit", "protocol": "https"}
            ],
            "parameters": [
                {"name": "cart_id", "type": "explicit", "valueType": "user-input"}
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True}
                ]
            }
        }
    }

    converter = BigIpPolicyConverter()
    result = converter.convert(bigip_json)

    assert result["success"] is True
    assert result["policy_name"] == "production_asm_policy"
    policy = result["policy"]["policy"]
    assert policy["enforcementMode"] == "transparent"
    assert len(policy["signature-sets"]) == 1
    assert len(policy["blocking-settings"]["violations"]) == 1
    assert policy["blocking-settings"]["violations"][0]["name"] == "VIOL_ATTACK_SIGNATURE"


def test_converter_gzipped_json():
    bigip_json = {
        "name": "gzipped_asm_export",
        "enforcementMode": "transparent",
        "signatureSets": [
            {"name": "High Accuracy Signatures", "alarm": True, "block": False}
        ],
    }
    raw_bytes = json.dumps(bigip_json).encode("utf-8")
    gz_bytes = gzip.compress(raw_bytes)

    converter = BigIpPolicyConverter()
    result = converter.convert(gz_bytes)

    assert result["success"] is True
    assert result["policy_name"] == "gzipped_asm_export"
    policy = result["policy"]["policy"]
    assert policy["enforcementMode"] == "transparent"
    assert len(policy.get("signature-sets", [])) == 1
    assert policy["signature-sets"][0]["name"] == "High Accuracy Signatures"


def test_converter_unsupported_json_features_warnings():
    bigip_json = {
        "name": "legacy_complex_policy",
        "enforcementMode": "blocking",
        "trafficLearning": {"enabled": True},
        "bruteForceProtection": {"enabled": True},
        "csrfProtection": {"enabled": True},
        "antivirus": {"enabled": True},
        "blockingSettings": {
            "violations": [
                {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                {"name": "VIOL_CSRF", "alarm": True, "block": True},
                {"name": "VIOL_LOGIN_URL_BYPASSED", "alarm": True, "block": True},
            ]
        },
    }

    converter = BigIpPolicyConverter()
    result = converter.convert(bigip_json)

    assert result["success"] is True
    warnings = result["warnings"]
    assert any("traffic" in w.lower() and "learning" in w.lower() for w in warnings)
    assert any("brute" in w.lower() for w in warnings)
    assert any("csrf" in w.lower() for w in warnings)
    assert any("antivirus" in w.lower() for w in warnings)
    assert any("VIOL_CSRF" in w for w in warnings)
    assert any("VIOL_LOGIN_URL_BYPASSED" in w for w in warnings)

    # VIOL_CSRF must be filtered out, VIOL_ATTACK_SIGNATURE must remain
    viols = result["policy"]["policy"]["blocking-settings"]["violations"]
    assert any(v["name"] == "VIOL_ATTACK_SIGNATURE" for v in viols)
    assert not any(v["name"] == "VIOL_CSRF" for v in viols)


def test_converter_convenience_function():
    bigip_json = {
        "name": "func_test",
        "enforcementMode": "blocking",
        "urls": [{"name": "/test", "type": "explicit", "protocol": "http"}],
    }

    result = convert_bigip_policy_json(bigip_json)
    assert result["success"] is True
    assert result["policy_name"] == "func_test"


def test_converter_xml_fallback():
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<policy>
    <name>fallback_xml_policy</name>
    <enforcement_mode>blocking</enforcement_mode>
    <urls>
        <url name="/api/v1/auth" type="explicit" protocol="https"/>
    </urls>
</policy>"""

    converter = BigIpPolicyConverter()
    result = converter.convert(xml_content.encode("utf-8"))
    assert result["success"] is True
    assert result["policy_name"] == "fallback_xml_policy"
    assert result["policy"]["policy"]["enforcementMode"] == "blocking"
