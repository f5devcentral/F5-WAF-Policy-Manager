"""
Unit tests for Snort Rule Syntax Validator, Parser, and Evaluator.
"""

import pytest
from f5_waf_editor.schemas.snort_validator import (
    validate_snort_rule,
    evaluate_snort_rule,
    decode_snort_hex,
    parse_snort_rule,
)


def test_decode_snort_hex():
    # Basic space
    decoded, err = decode_snort_hex("ABC|20|XYZ")
    assert err is None
    assert decoded == "ABC XYZ"

    # Multiple hex pairs and spaces
    decoded, err = decode_snort_hex("Hello|2C 20|World|21|")
    assert err is None
    assert decoded == "Hello, World!"

    # Escaped semicolon and quotes
    decoded, err = decode_snort_hex("cmd|3B 22|arg")
    assert err is None
    assert decoded == 'cmd;"arg'

    # Error handling: unclosed pipe
    _, err = decode_snort_hex("ABC|20XYZ")
    assert "Unclosed hex escape pipe symbol" in err

    # Error handling: invalid hex
    _, err = decode_snort_hex("ABC|ZZ|XYZ")
    assert "Invalid hex digits" in err

    # Error handling: odd digits
    _, err = decode_snort_hex("ABC|2|XYZ")
    assert "Odd number of hex digits" in err


def test_validate_official_examples():
    # 1. Official Apple signature rule from https://docs.nginx.com/waf/policies/user-signatures/#signatures
    rule1 = 'content:"apple"; nocase;'
    valid, errors, warnings, info = validate_snort_rule(rule1)
    assert valid is True
    assert len(errors) == 0
    assert info["decoded_patterns"][0]["decoded"] == "apple"

    # 2. URI match with objonly
    rule2 = 'uricontent:"/api/debug"; objonly; nocase;'
    valid, errors, warnings, info = validate_snort_rule(rule2)
    assert valid is True
    assert len(errors) == 0

    # 3. Parameter match (valuecontent) with norm
    rule3 = 'valuecontent:"admin=true"; norm; nocase;'
    valid, errors, warnings, info = validate_snort_rule(rule3)
    assert valid is True
    assert len(errors) == 0

    # 4. Header inspection with useragentonly
    rule4 = 'headercontent:"EvilBot"; useragentonly; nocase;'
    valid, errors, warnings, info = validate_snort_rule(rule4)
    assert valid is True
    assert len(errors) == 0

    # 5. PCRE regex
    rule5 = 'pcre:"/(?:select|union).*(?:from|where)/i";'
    valid, errors, warnings, info = validate_snort_rule(rule5)
    assert valid is True
    assert len(errors) == 0
    assert info["has_pcre"] is True

    # 6. RE2 regex
    rule6 = 're2:"/soda;\\s+bar/i";'
    valid, errors, warnings, info = validate_snort_rule(rule6)
    assert valid is True
    assert len(errors) == 0
    assert info["has_re2"] is True

    # 7. Reference option
    rule7 = 'content:"vulnerability_token"; reference:cve,2023-9999; nocase;'
    valid, errors, warnings, info = validate_snort_rule(rule7)
    assert valid is True
    assert len(errors) == 0


def test_validate_invalid_rules():
    # Empty rule
    valid, errors, _, _ = validate_snort_rule("")
    assert valid is False

    # Missing trailing semicolon
    valid, errors, _, _ = validate_snort_rule('content:"test"')
    assert valid is False
    assert any("missing trailing semicolon" in e for e in errors)

    # Modifier 'objonly' used without uricontent
    valid, errors, _, _ = validate_snort_rule('content:"test"; objonly;')
    assert valid is False
    assert any("objonly' can only be used with 'uricontent'" in e for e in errors)

    # Modifier 'norm' used without valuecontent
    valid, errors, _, _ = validate_snort_rule('uricontent:"/test"; norm;')
    assert valid is False
    assert any("norm' can only be used with 'valuecontent'" in e for e in errors)

    # Modifier 'useragentonly' used without headercontent/ipp
    valid, errors, _, _ = validate_snort_rule('content:"bot"; useragentonly;')
    assert valid is False
    assert any("useragentonly' can only be used with 'headercontent'" in e for e in errors)

    # Conflicting scopes: valuecontent mixed with content
    valid, errors, _, _ = validate_snort_rule('valuecontent:"foo"; content:"bar";')
    assert valid is False
    assert any("cannot be combined with other scopes" in e for e in errors)

    # Negative integer in modifier
    valid, errors, _, _ = validate_snort_rule('content:"test"; offset:-5;')
    assert valid is False
    assert any("non-negative" in e for e in errors)

    # Invalid regex in pcre
    valid, errors, _, _ = validate_snort_rule('pcre:"/[a-z/i";')
    assert valid is False
    assert any("Invalid regex in pcre" in e for e in errors)


def test_evaluate_snort_rule():
    rule = 'content:"apple"; nocase;'

    # Matching request
    res = evaluate_snort_rule(
        rule,
        {
            "uri": "/shop/cart",
            "body": "User selected one fresh Apple for checkout",
        },
    )
    assert res["matched"] is True
    assert res["details"][0]["found_in_input"] is True
    assert "Apple" in res["details"][0]["matched_snippet"]

    # Non-matching request
    res_no = evaluate_snort_rule(
        rule,
        {
            "uri": "/shop/cart",
            "body": "User selected one fresh Orange for checkout",
        },
    )
    assert res_no["matched"] is False

    # Case sensitive match
    rule_case = 'content:"Apple";'
    res_case_pass = evaluate_snort_rule(rule_case, {"body": "Here is Apple"})
    assert res_case_pass["matched"] is True

    res_case_fail = evaluate_snort_rule(rule_case, {"body": "Here is apple"})
    assert res_case_fail["matched"] is False

    # URI path with objonly
    rule_uri = 'uricontent:"/admin/login"; objonly; nocase;'
    res_uri_pass = evaluate_snort_rule(rule_uri, {"uri": "/admin/login?redirect=1"})
    assert res_uri_pass["matched"] is True

    res_uri_fail = evaluate_snort_rule(rule_uri, {"uri": "/home?return=/admin/login"})
    assert res_uri_fail["matched"] is False

    # Hex escaped characters
    rule_hex = 'content:"test|20|token"; nocase;'
    res_hex = evaluate_snort_rule(rule_hex, {"body": "found a test token in payload"})
    assert res_hex["matched"] is True

    # User-agent header
    rule_ua = 'headercontent:"MaliciousCrawler"; useragentonly; nocase;'
    res_ua = evaluate_snort_rule(
        rule_ua,
        {
            "headers": {"User-Agent": "Mozilla/5.0 MaliciousCrawler/2.1", "Host": "example.com"},
        },
    )
    assert res_ua["matched"] is True

    # Parameter valuecontent match
    rule_param = 'valuecontent:"token=secret123";'
    res_param = evaluate_snort_rule(
        rule_param,
        {
            "uri": "/verify?token=secret123&user=john",
        },
    )
    assert res_param["matched"] is True
