"""
Tests for User-Defined Signatures validation according to official F5 WAF for NGINX docs:
https://docs.nginx.com/waf/policies/user-signatures/#signatures
"""

import pytest
from f5_waf_editor.schemas.validator import (
    validate_policy_json,
    validate_user_defined_signatures_file,
)
from f5_waf_editor.schemas.waf_schema import DEFAULT_USER_SIGNATURE_DEFINITIONS


def test_validate_default_custom_signatures_file():
    """Verify that the official sample custom signatures definition file validates cleanly."""
    is_valid, errors, warnings, parsed = validate_user_defined_signatures_file(
        DEFAULT_USER_SIGNATURE_DEFINITIONS
    )
    assert is_valid is True
    assert len(errors) == 0
    assert parsed["tag"] == "Fruits"
    assert len(parsed["signatures"]) == 2
    assert parsed["signatures"][0]["name"] == "Apple_medium_acc"


def test_validate_custom_signatures_file_from_json_string():
    """Verify JSON string parsing and validation."""
    json_str = """
    {
      "softwareVersion": "15.1.0",
      "tag": "Banking",
      "revisionDatetime": "2026-10-01T12:00:00Z",
      "signatures": [
        {
          "name": "SQLi_Auth_Bypass",
          "description": "Custom SQLi check on auth endpoints",
          "rule": "content:\\"admin' --\\"; nocase;",
          "signatureType": "request",
          "attackType": { "name": "SQL Injection" },
          "systems": [ { "name": "MySQL" }, { "name": "Unix/Linux" } ],
          "risk": "high",
          "accuracy": "high"
        }
      ]
    }
    """
    is_valid, errors, warnings, parsed = validate_user_defined_signatures_file(json_str)
    assert is_valid is True
    assert len(errors) == 0
    assert parsed["tag"] == "Banking"
    assert len(parsed["signatures"]) == 1


def test_invalid_custom_signatures_file_missing_signatures():
    bad_doc = {"tag": "TestTag"}
    is_valid, errors, warnings, _ = validate_user_defined_signatures_file(bad_doc)
    assert is_valid is False
    assert any("Missing required 'signatures' array" in e for e in errors)


def test_invalid_custom_signatures_duplicate_names():
    bad_doc = {
        "tag": "Fruits",
        "signatures": [
            {
                "name": "Apple_sig",
                "rule": 'content:"apple"; nocase;',
                "signatureType": "request",
                "risk": "medium",
                "accuracy": "medium",
            },
            {
                "name": "Apple_sig",
                "rule": 'content:"apple2"; nocase;',
                "signatureType": "request",
                "risk": "medium",
                "accuracy": "medium",
            },
        ],
    }
    is_valid, errors, warnings, _ = validate_user_defined_signatures_file(bad_doc)
    assert is_valid is False
    assert any("Duplicate signature name 'Apple_sig'" in e for e in errors)


def test_invalid_custom_signatures_bad_enums():
    bad_doc = {
        "tag": "Fruits",
        "signatures": [
            {
                "name": "Bad_sig",
                "rule": 'content:"apple"; nocase;',
                "signatureType": "invalid_type",
                "risk": "extreme",
                "accuracy": "perfect",
            }
        ],
    }
    is_valid, errors, warnings, _ = validate_user_defined_signatures_file(bad_doc)
    assert is_valid is False
    assert any("'signatureType' must be 'request' or 'response'" in e for e in errors)
    assert any("'risk' must be 'low', 'medium', or 'high'" in e for e in errors)
    assert any("'accuracy' must be 'low', 'medium', or 'high'" in e for e in errors)


def test_policy_with_signature_requirements_and_custom_exceptions():
    """Verify policy validation when policy includes signature-requirements and custom signature overrides."""
    policy = {
        "policy": {
            "name": "user_defined_single_signature",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "signature-requirements": [
                {
                    "tag": "Fruits",
                    "minRevisionDatetime": "2020-01-20T18:32:02Z",
                    "maxRevisionDatetime": "2020-01-23T18:32:02Z",
                }
            ],
            "signatures": [
                {
                    "name": "Apple_medium_acc",
                    "tag": "Fruits",
                    "enabled": False,
                },
                {
                    "signatureId": 200001475,
                    "enabled": True,
                },
            ],
            "signature-sets": [
                {
                    "name": "Fruit_signature_set",
                    "block": True,
                    "alarm": True,
                    "signatureSet": {
                        "type": "filter-based",
                        "filter": {
                            "tagValue": "Fruits",
                            "tagFilter": "eq",
                        },
                    },
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
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert len(parsed["policy"]["signature-requirements"]) == 1
    assert len(parsed["policy"]["signatures"]) == 2
    assert len(parsed["policy"]["custom-signatures"]) == 1


def test_policy_invalid_signature_requirements():
    bad_policy = {
        "policy": {
            "name": "bad_req_policy",
            "signature-requirements": [
                {"minRevisionDatetime": "2020-01-20T18:32:02Z"}  # missing tag
            ],
        }
    }
    is_valid, errors, warnings, _ = validate_policy_json(bad_policy)
    assert is_valid is False
    assert any("missing a required non-empty 'tag'" in e for e in errors)
