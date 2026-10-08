"""
Unit tests verifying that all built-in reference templates are valid F5 WAF policies.
"""

from f5_waf_editor.templates_catalog import list_templates, get_template_json
from f5_waf_editor.schemas.validator import validate_policy_json


def test_built_in_templates_exist():
    templates = list_templates()
    assert len(templates) >= 4
    ids = {t["id"] for t in templates}
    assert "default" in ids
    assert "strict" in ids
    assert "api_security" in ids
    assert "transparent" in ids
    assert "grpc_security" in ids


def test_built_in_templates_validity():
    for tmpl in list_templates():
        content = get_template_json(tmpl["id"])
        assert content is not None, f"Template {tmpl['id']} JSON could not be loaded"
        is_valid, errors, warnings, parsed = validate_policy_json(content)
        assert is_valid is True, f"Template {tmpl['id']} failed validation: {errors}"
        assert len(errors) == 0
        assert "policy" in parsed
        assert "name" in parsed["policy"]
        assert "template" in parsed["policy"]
