"""
Tests for F5 WAF Logging Profile Validator.
"""

import pytest
from f5_waf_editor.schemas.logging_validator import validate_logging_profile_json


def test_valid_default_logging_profile():
    payload = {
        "filter": {"request_type": "illegal"},
        "content": {
            "format": "default",
            "max_request_size": "2k",
            "max_message_size": "32k",
        },
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is True
    assert len(errors) == 0
    assert parsed["filter"]["request_type"] == "illegal"


def test_valid_user_defined_logging_profile():
    payload = {
        "filter": {"request_type": "all"},
        "content": {
            "format": "user-defined",
            "format_string": "ip=%ip_client%,violations=%violations%,support_id=%support_id%",
            "max_request_size": "4k",
            "max_message_size": "48k",
            "escaping_characters": [{"from": '"', "to": '\\"'}],
        },
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_json_syntax():
    invalid_raw = '{"filter": {"request_type": "illegal",}'
    is_valid, errors, warnings, parsed = validate_logging_profile_json(invalid_raw)
    assert is_valid is False
    assert any("Invalid JSON syntax" in e for e in errors)


def test_missing_root_keys():
    payload = {"filter": {"request_type": "illegal"}}
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("Missing required top-level key: 'content'" in e for e in errors)


def test_invalid_request_type():
    payload = {
        "filter": {"request_type": "everything"},
        "content": {"format": "default"},
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("Invalid 'filter.request_type'" in e for e in errors)


def test_invalid_format():
    payload = {
        "filter": {"request_type": "illegal"},
        "content": {"format": "custom_csv"},
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("Invalid 'content.format'" in e for e in errors)


def test_user_defined_missing_format_string():
    payload = {
        "filter": {"request_type": "illegal"},
        "content": {"format": "user-defined"},
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("format_string' must be a non-empty string" in e for e in errors)


def test_invalid_buffer_limits():
    payload = {
        "filter": {"request_type": "illegal"},
        "content": {
            "format": "default",
            "max_message_size": "128k",  # exceeds 64k
            "max_request_size": "25k",  # exceeds 10k
        },
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("max_message_size" in e for e in errors)
    assert any("max_request_size" in e for e in errors)


def test_zero_or_negative_buffer_limits():
    payload = {
        "filter": {"request_type": "all"},
        "content": {
            "format": "default",
            "max_message_size": "0k",
            "max_request_size": 0,
        },
    }
    is_valid, errors, warnings, parsed = validate_logging_profile_json(payload)
    assert is_valid is False
    assert any("max_message_size" in e and "greater than zero" in e for e in errors)
    assert any("max_request_size" in e and "greater than zero" in e for e in errors)

