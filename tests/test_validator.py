"""
Unit tests for F5 WAF Policy JSON Schema Validator.
"""

import pytest
from f5_waf_editor.schemas.validator import validate_policy_json
from f5_waf_editor.schemas.waf_schema import extract_policy_metadata, sanitize_waf_policy


def test_valid_minimal_policy():
    policy = {
        "policy": {
            "name": "test_waf_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "applicationLanguage": "utf-8",
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert parsed["policy"]["name"] == "test_waf_policy"


def test_missing_policy_root():
    bad_data = {"name": "invalid_root"}
    is_valid, errors, warnings, parsed = validate_policy_json(bad_data)
    assert is_valid is False
    assert any("Missing required top-level key: 'policy'" in e for e in errors)


def test_invalid_policy_name():
    bad_name = {
        "policy": {
            "name": "invalid name with spaces & special characters!",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(bad_name)
    assert is_valid is False
    assert any("Invalid 'policy.name'" in e for e in errors)


def test_invalid_enforcement_mode():
    bad_mode = {
        "policy": {
            "name": "valid_name",
            "enforcementMode": "super_strict",
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(bad_mode)
    assert is_valid is False
    assert any("Invalid enforcementMode" in e for e in errors)


def test_valid_violations_blocking_settings():
    policy = {
        "policy": {
            "name": "strict_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                    {"name": "VIOL_DATA_GUARD", "alarm": True, "block": False},
                ]
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_json_string():
    raw_str = '{"policy": {"name": unquoted_val}}'
    is_valid, errors, warnings, parsed = validate_policy_json(raw_str)
    assert is_valid is False
    assert any("Invalid JSON syntax" in e for e in errors)


def test_valid_server_technologies():
    policy = {
        "policy": {
            "name": "tech_aware_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "server-technologies": [
                {"serverTechnologyName": "Nginx"},
                {"serverTechnologyName": "Unix/Linux"},
                {"serverTechnologyName": "Python"},
                {"name": "PostgreSQL"},
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert len(parsed["policy"]["server-technologies"]) == 4


def test_invalid_server_technologies():
    policy = {
        "policy": {
            "name": "bad_tech_policy",
            "server-technologies": "not-an-array",
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("'policy.server-technologies' must be an array" in e for e in errors)


def test_valid_signature_sets():
    policy = {
        "policy": {
            "name": "sigset_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                {
                    "name": "High Accuracy Signatures",
                    "alarm": True,
                    "block": True,
                },
                {
                    "name": "SQL Injection Signatures",
                    "alarm": True,
                    "block": True,
                },
                {
                    "name": "Custom_Filter_Set",
                    "alarm": True,
                    "block": False,
                    "signatureSet": {
                        "filter": {
                            "tagFilter": "eq",
                            "tagValue": "CustomAppTag",
                        }
                    },
                },
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert len(parsed["policy"]["signature-sets"]) == 3


def test_invalid_signature_sets():
    # Not an array
    p1 = {"policy": {"name": "bad_sig1", "signature-sets": "invalid"}}
    valid, errors, _, _ = validate_policy_json(p1)
    assert valid is False
    assert any("'policy.signature-sets' must be an array" in e for e in errors)

    # Missing name
    p2 = {"policy": {"name": "bad_sig2", "signature-sets": [{"alarm": True}]}}
    valid, errors, _, _ = validate_policy_json(p2)
    assert valid is False
    assert any("missing a valid 'name' string" in e for e in errors)

    # Non-boolean alarm/block
    p3 = {"policy": {"name": "bad_sig3", "signature-sets": [{"name": "Set1", "alarm": "yes"}]}}
    valid, errors, _, _ = validate_policy_json(p3)
    assert valid is False
    assert any("alarm property must be a boolean" in e for e in errors)


def test_valid_signatures_exceptions():
    policy = {
        "policy": {
            "name": "sig_exception_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signatures": [
                {
                    "signatureId": 200001475,
                    "enabled": False,
                    "tag": "False positive in legacy search endpoint",
                },
                {
                    "signatureId": 200000098,
                    "enabled": True,
                },
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert len(parsed["policy"]["signatures"]) == 2


def test_invalid_signatures_exceptions():
    # Missing signatureId
    p1 = {"policy": {"name": "bad_exc1", "signatures": [{"enabled": False}]}}
    valid, errors, _, _ = validate_policy_json(p1)
    assert valid is False
    assert any("missing 'signatureId'" in e for e in errors)

    # Non-numeric signatureId
    p2 = {"policy": {"name": "bad_exc2", "signatures": [{"signatureId": "abc"}]}}
    valid, errors, _, _ = validate_policy_json(p2)
    assert valid is False
    assert any("must be a numeric ID" in e for e in errors)

    # Non-boolean enabled
    p3 = {"policy": {"name": "bad_exc3", "signatures": [{"signatureId": 200001475, "enabled": "no"}]}}
    valid, errors, _, _ = validate_policy_json(p3)
    assert valid is False
    assert any("'enabled' must be a boolean" in e for e in errors)


def test_valid_openapi_files_url():
    policy = {
        "policy": {
            "name": "openapi_url_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {"link": "https://example.com/openapi.yaml"}
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_valid_openapi_files_local_file():
    policy = {
        "policy": {
            "name": "openapi_file_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {"link": "file:///etc/app_protect/conf/openapi.json"}
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_valid_openapi_file_reference_direct():
    policy = {
        "policy": {
            "name": "openapi_direct_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "openApiFileReference": {
                "link": "https://api.example.com/v3/openapi.json"
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_openapi_with_basic_auth_in_json():
    """F5 WAF for NGINX declarative policies do not support basicAuth in open-api-files."""
    policy = {
        "policy": {
            "name": "openapi_auth_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {
                    "link": "https://internal-api.corp/spec.yaml",
                    "basicAuth": {
                        "user": "spec_reader",
                        "passwordBase64": "c2VjcmV0MTIz",
                    },
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("not supported by F5 WAF for NGINX" in e for e in errors)


def test_invalid_openapi_multiple_files_error():
    policy = {
        "policy": {
            "name": "multi_openapi_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {"link": "https://api.example.com/spec1.yaml"},
                {"link": "https://api.example.com/spec2.yaml"},
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("supports only one OpenAPI specification" in e for e in errors)


def test_invalid_openapi_unsupported_scheme():
    policy = {
        "policy": {
            "name": "ftp_openapi_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {"link": "ftp://files.example.com/spec.yaml"}
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("must use 'http://', 'https://', or 'file:///'" in e for e in errors)


def test_sanitize_waf_policy_strips_openapi_basic_auth():
    from f5_waf_editor.schemas.waf_schema import sanitize_waf_policy

    policy = {
        "policy": {
            "name": "sanitize_auth_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "open-api-files": [
                {
                    "link": "https://api.example.com/spec.yaml",
                    "basicAuth": {
                        "user": "admin",
                        "passwordBase64": "c2VjcmV0",
                    },
                }
            ],
            "openApiFileReference": {
                "link": "https://api.example.com/spec.yaml",
                "basicAuth": {"user": "admin", "passwordBase64": "c2VjcmV0"},
            },
        }
    }
    sanitized = sanitize_waf_policy(policy)
    assert "basicAuth" not in sanitized["policy"]["open-api-files"][0]
    assert "basicAuth" not in sanitized["policy"]["openApiFileReference"]
    assert sanitized["policy"]["open-api-files"][0]["link"] == "https://api.example.com/spec.yaml"


def test_valid_grpc_single_proto():
    policy = {
        "policy": {
            "name": "grpc_single_proto_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "example_grpc_service_profile",
                    "description": "gRPC protection for Example gRPC service",
                    "associateUrls": True,
                    "attackSignaturesCheck": True,
                    "metacharCheck": True,
                    "decodeStringValuesAsBase64": "disabled",
                    "defenseAttributes": {
                        "maximumDataLength": 100000,
                        "allowUnknownFields": False,
                    },
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///examples/grpc/album.proto"
                            },
                            "isPrimary": True,
                        }
                    ],
                }
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_GRPC_MALFORMED", "alarm": True, "block": True},
                    {"name": "VIOL_GRPC_FORMAT", "alarm": True, "block": True},
                    {"name": "VIOL_GRPC_METHOD", "alarm": True, "block": True},
                ]
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0
    assert len(parsed["policy"]["grpc-profiles"]) == 1


def test_valid_grpc_archive_tgz():
    policy = {
        "policy": {
            "name": "grpc_archive_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "example_grpc_service_bundle_profile",
                    "defenseAttributes": {
                        "maximumDataLength": 250000,
                        "allowUnknownFields": True,
                    },
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///examples/grpc/album_service_files.tgz"
                            },
                            "primaryIdlFileName": "album_service.proto",
                        }
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_grpc_profile_missing_name():
    policy = {
        "policy": {
            "name": "bad_grpc_profile",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "description": "Missing name property",
                    "idlFiles": [
                        {"idlFile": {"$ref": "file:///service.proto"}}
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("missing required non-empty 'name'" in e for e in errors)


def test_invalid_grpc_defense_attributes():
    policy = {
        "policy": {
            "name": "bad_grpc_defense",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "profile1",
                    "defenseAttributes": {
                        "maximumDataLength": -5,
                        "allowUnknownFields": "not_a_bool",
                    },
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("maximumDataLength' must be a non-negative integer" in e for e in errors)
    assert any("allowUnknownFields' must be a boolean" in e for e in errors)


def test_invalid_grpc_archive_missing_primary_proto():
    policy = {
        "policy": {
            "name": "bad_archive_primary",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "profile_archive",
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///path/to/archive.tgz"
                            }
                        }
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("requires 'primaryIdlFileName'" in e for e in errors)


def test_invalid_grpc_unsupported_file_extension():
    policy = {
        "policy": {
            "name": "bad_idl_ext",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "profile_ext",
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///path/to/schema.xml"
                            }
                        }
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("unsupported file extension" in e for e in errors)


def test_grpc_metadata_extraction():
    policy = {
        "policy": {
            "name": "grpc_meta_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "grpc-profiles": [
                {
                    "name": "album_prof",
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///examples/grpc/album.proto"
                            },
                            "isPrimary": True,
                        }
                    ],
                }
            ],
        }
    }
    meta = extract_policy_metadata(policy)
    assert meta["hasGrpc"] is True
    assert meta["grpcProfilesCount"] == 1
    assert "album.proto" in meta["grpcPrimaryIdl"]
    assert meta["grpcFileType"] == "proto"


def test_bot_defense_metadata_extraction():
    # Enabled via settings.isEnabled
    policy_enabled = {
        "policy": {
            "name": "bot_policy",
            "bot-defense": {
                "settings": {
                    "isEnabled": True
                }
            }
        }
    }
    meta = extract_policy_metadata(policy_enabled)
    assert meta["botDefenseEnabled"] is True

    # Disabled
    policy_disabled = {
        "policy": {
            "name": "no_bot_policy",
            "bot-defense": {
                "settings": {
                    "isEnabled": False
                }
            }
        }
    }
    meta_dis = extract_policy_metadata(policy_disabled)
    assert meta_dis["botDefenseEnabled"] is False

    # Enabled via camelCase or direct boolean
    policy_bool = {
        "policy": {
            "name": "bool_bot_policy",
            "botDefense": True
        }
    }
    meta_bool = extract_policy_metadata(policy_bool)
    assert meta_bool["botDefenseEnabled"] is True


def test_valid_url_content_profiles():
    policy = {
        "policy": {
            "name": "api_url_profiles_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "urls": [
                {
                    "name": "/api/v1/users",
                    "type": "explicit",
                    "method": "POST",
                    "urlContentProfiles": [
                        {
                            "type": "json",
                            "headerName": "Content-Type",
                            "headerValue": "*json*",
                            "headerOrder": "default",
                            "contentProfile": {"name": "Default"},
                        },
                        {
                            "type": "xml",
                            "headerName": "Content-Type",
                            "headerValue": "*xml*",
                            "headerOrder": "1",
                            "contentProfile": {"name": "CustomXmlProfile"},
                        },
                        {
                            "type": "graphql",
                            "headerName": "Content-Type",
                            "headerValue": "*graphql*",
                            "headerOrder": "2",
                            "contentProfile": {"name": "GqlProfile"},
                        },
                        {
                            "type": "grpc",
                            "headerName": "Content-Type",
                            "headerValue": "*application/grpc*",
                            "headerOrder": "3",
                            "contentProfile": {"name": "GrpcProfile"},
                        },
                        {
                            "type": "form-data",
                            "headerName": "*",
                            "headerValue": "*",
                            "headerOrder": "default",
                        },
                        {
                            "type": "do-nothing",
                            "headerName": "Content-Type",
                            "headerValue": "*",
                            "headerOrder": "default",
                        },
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True, f"Validation errors: {errors}"
    assert len(errors) == 0

    meta = extract_policy_metadata(policy)
    assert meta["urlsCount"] == 1
    assert meta["urlContentProfilesCount"] == 6


def test_invalid_url_content_profile_type():
    policy = {
        "policy": {
            "name": "bad_profile_type",
            "urls": [
                {
                    "name": "/api/test",
                    "urlContentProfiles": [
                        {
                            "type": "unsupported-custom-type",
                            "headerName": "Content-Type",
                            "headerValue": "*",
                        }
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("Invalid content profile type 'unsupported-custom-type'" in e for e in errors)


def test_invalid_url_content_profile_missing_profile_name():
    policy = {
        "policy": {
            "name": "missing_profile_name",
            "urls": [
                {
                    "name": "/api/test",
                    "urlContentProfiles": [
                        {
                            "type": "json",
                            "headerName": "Content-Type",
                            "headerValue": "*json*",
                            # Missing contentProfile.name
                        }
                    ],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("must specify 'contentProfile.name'" in e for e in errors)


def test_valid_evasions_configuration():
    policy = {
        "policy": {
            "name": "evasions_policy",
            "blocking-settings": {
                "evasions": [
                    {"description": "Multiple decoding", "enabled": True, "maxDecodingPasses": 3},
                    {"description": "Directory traversals", "enabled": True},
                    {"description": "Bad unescape", "enabled": True},
                ]
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_evasion_technique_description():
    policy = {
        "policy": {
            "name": "bad_evasion",
            "blocking-settings": {
                "evasions": [
                    {"description": "Nonexistent evasion technique", "enabled": True}
                ]
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("Unknown or unsupported evasion technique" in e for e in errors)


def test_invalid_evasion_max_decoding_passes():
    policy = {
        "policy": {
            "name": "bad_decoding_passes",
            "blocking-settings": {
                "evasions": [
                    {"description": "Multiple decoding", "enabled": True, "maxDecodingPasses": -1}
                ]
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("maxDecodingPasses must be a positive integer" in e for e in errors)


def test_valid_ip_address_lists():
    policy = {
        "policy": {
            "name": "ip_lists_policy",
            "ip-address-lists": [
                {
                    "name": "corporate_whitelist",
                    "description": "Internal HQ and VPN gateways",
                    "blockRequests": "never",
                    "setGeolocation": "US",
                    "ipAddresses": [
                        {"ipAddress": "192.168.1.0/24"},
                        {"ipAddress": "10.0.0.1-10.0.0.50"},
                        {"ipAddress": "2001:db8::/32"},
                    ],
                },
                {
                    "name": "bad_actors_blocklist",
                    "blockRequests": "always",
                    "ipAddresses": [{"ipAddress": "203.0.113.42"}],
                },
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_ip_address_list_block_requests():
    policy = {
        "policy": {
            "name": "bad_ip_action",
            "ip-address-lists": [
                {
                    "name": "test_list",
                    "blockRequests": "drop_silently",  # Invalid action
                    "ipAddresses": [{"ipAddress": "10.0.0.1"}],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("Invalid blockRequests" in e for e in errors)


def test_invalid_ip_address_list_missing_name():
    policy = {
        "policy": {
            "name": "missing_ip_name",
            "ip-address-lists": [
                {
                    "ipAddresses": [{"ipAddress": "10.0.0.1"}],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("must contain a non-empty string 'name'" in e for e in errors)


def test_invalid_ip_address_list_geolocation():
    policy = {
        "policy": {
            "name": "bad_geoloc",
            "ip-address-lists": [
                {
                    "name": "test_list",
                    "setGeolocation": "USA",  # Needs to be 2 uppercase characters
                    "ipAddresses": [{"ipAddress": "10.0.0.1"}],
                }
            ],
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("must be a 2-letter uppercase ISO country code" in e for e in errors)


def test_valid_response_settings():
    policy = {
        "policy": {
            "name": "response_checked_policy",
            "general": {
                "responseCheck": True,
                "responseCheckLength": 10000,
                "allowedResponseCodes": [200, 201, 301, 302],
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_response_check_length():
    policy = {
        "policy": {
            "name": "bad_response_length",
            "general": {
                "responseCheck": True,
                "responseCheckLength": -500,
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("must be a non-negative integer" in e for e in errors)


def test_valid_data_guard_official_schema():
    policy = {
        "policy": {
            "name": "dataguard_policy",
            "data-guard": {
                "enabled": True,
                "maskData": True,
                "creditCardNumbers": True,
                "usSocialSecurityNumbers": True,
                "enforcementMode": "ignore-urls-in-list",
                "enforcementUrls": ["/api/v1/checkout"],
                "customPatterns": True,
                "customPatternsList": ["....-....-....-...."],
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0


def test_invalid_legacy_data_guard_fields():
    policy = {
        "policy": {
            "name": "bad_dataguard_policy",
            "data-guard": {
                "enabled": True,
                "maskCreditCardNumbersInResponse": True,
                "maskUssnInResponse": True,
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is False
    assert any("Unknown field 'maskCreditCardNumbersInResponse' in data-guard" in e for e in errors)
    assert any("Unknown field 'maskUssnInResponse' in data-guard" in e for e in errors)


def test_sanitize_waf_policy_normalizes_data_guard():
    from f5_waf_editor.schemas.waf_schema import sanitize_waf_policy

    legacy_policy = {
        "policy": {
            "name": "legacy_dataguard",
            "data-guard": {
                "enabled": True,
                "maskCreditCardNumbersInResponse": True,
                "maskUssnInResponse": True,
                "customPatterns": ["\\d{4}-\\d{4}"],
            },
        }
    }
    sanitized = sanitize_waf_policy(legacy_policy)
    dg = sanitized["policy"]["data-guard"]
    assert "maskCreditCardNumbersInResponse" not in dg
    assert "maskUssnInResponse" not in dg
    assert dg["creditCardNumbers"] is True
    assert dg["usSocialSecurityNumbers"] is True
    assert dg["maskData"] is True
    assert dg["enforcementMode"] == "ignore-urls-in-list"
    assert dg["customPatterns"] is True
    assert dg["customPatternsList"] == ["\\d{4}-\\d{4}"]


def test_signature_sets_threat_campaigns_validation_and_sanitization():
    from f5_waf_editor.schemas.waf_schema import sanitize_waf_policy

    # 1. Validation detects Threat Campaigns as an invalid signature-set
    policy_with_tc = {
        "policy": {
            "name": "policy_tc",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                {"name": "High Accuracy Signatures", "alarm": True, "block": True},
                {"name": "Threat Campaigns", "alarm": True, "block": True},
            ],
        }
    }
    is_valid, errors, warnings, _ = validate_policy_json(policy_with_tc)
    assert is_valid is False
    assert any("Threat Campaigns" in e and "VIOL_THREAT_CAMPAIGN" in e for e in errors)

    # 2. Sanitization automatically migrates Threat Campaigns out of signature-sets into blocking-settings.violations
    sanitized = sanitize_waf_policy(policy_with_tc)
    sig_set_names = [s["name"] for s in sanitized["policy"]["signature-sets"]]
    assert "Threat Campaigns" not in sig_set_names
    assert "High Accuracy Signatures" in sig_set_names

    violations = sanitized["policy"]["blocking-settings"]["violations"]
    tc_viol = next((v for v in violations if v["name"] == "VIOL_THREAT_CAMPAIGN"), None)
    assert tc_viol is not None
    assert tc_viol["alarm"] is True
    assert tc_viol["block"] is True


def test_signature_sets_legacy_aliases_validation_and_sanitization():
    from f5_waf_editor.schemas.waf_schema import sanitize_waf_policy

    # 1. Validation emits warnings for legacy aliases
    policy_aliases = {
        "policy": {
            "name": "policy_aliases",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                {"name": "Directory Traversal Signatures", "alarm": True, "block": True},
                {"name": "XML External Entity (XXE) Signatures", "alarm": True, "block": True},
                {"name": "Authentication / Authorization Attacks", "alarm": True, "block": False},
                {"name": "HTTP Parser Attack Signatures", "alarm": True, "block": True},
            ],
        }
    }
    is_valid, errors, warnings, _ = validate_policy_json(policy_aliases)
    assert is_valid is True
    assert len(warnings) >= 4
    assert any("Path Traversal Signatures" in w for w in warnings)
    assert any("XML External Entities (XXE) Signatures" in w for w in warnings)
    assert any("Authentication/Authorization Attack Signatures" in w for w in warnings)

    # 2. Sanitization replaces aliases with canonical names
    sanitized = sanitize_waf_policy(policy_aliases)
    names = [s["name"] for s in sanitized["policy"]["signature-sets"]]
    assert "Path Traversal Signatures" in names
    assert "Directory Traversal Signatures" not in names
    assert "XML External Entities (XXE) Signatures" in names
    assert "XML External Entity (XXE) Signatures" not in names
    assert "Authentication/Authorization Attack Signatures" in names
    assert "Generic Detection Signatures" in names


def test_signature_sets_unknown_name():
    policy_bad = {
        "policy": {
            "name": "policy_bad_sigset",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "signature-sets": [
                {"name": "Completely_Made_Up_Signature_Set", "alarm": True, "block": True},
            ],
        }
    }
    is_valid, errors, warnings, _ = validate_policy_json(policy_bad)
    assert is_valid is False
    assert any("Unknown predefined signature set" in e for e in errors)


def test_valid_cookies_configuration():
    policy = {
        "policy": {
            "name": "policy_with_cookies",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "cookies": [
                {
                    "name": "session_id",
                    "type": "explicit",
                    "enforcementType": "enforce",
                    "attackSignaturesCheck": True,
                    "maskValueInLogs": True,
                    "accessibleOnlyThroughTheHttpProtocol": True,
                },
                {
                    "name": "track_*",
                    "type": "wildcard",
                    "enforcementType": "allow",
                    "attackSignaturesCheck": False,
                    "wildcardOrder": 1,
                },
            ],
            "cookie-settings": {
                "maximumCookieHeaderLength": 8192,
            },
            "enforcer-settings": {
                "enforcerStateCookies": {
                    "httpOnlyAttribute": True,
                    "secureAttribute": "always",
                    "sameSiteAttribute": "strict",
                }
            },
        }
    }
    is_valid, errors, warnings, parsed = validate_policy_json(policy)
    assert is_valid is True
    assert len(errors) == 0

    meta = extract_policy_metadata(parsed)
    assert meta["cookiesCount"] == 2
    assert meta["hasCookies"] is True


def test_cookie_validation_errors():
    # 1. Missing cookie name
    p1 = {
        "policy": {
            "name": "bad_cookie_1",
            "cookies": [{"type": "explicit"}],
        }
    }
    is_valid, errors, _, _ = validate_policy_json(p1)
    assert is_valid is False
    assert any("must contain a non-empty string 'name'" in e for e in errors)

    # 2. Invalid cookie type
    p2 = {
        "policy": {
            "name": "bad_cookie_2",
            "cookies": [{"name": "my_cookie", "type": "invalid_type"}],
        }
    }
    is_valid, errors, _, _ = validate_policy_json(p2)
    assert is_valid is False
    assert any("invalid 'type'" in e for e in errors)

    # 3. Invalid enforcementType
    p3 = {
        "policy": {
            "name": "bad_cookie_3",
            "cookies": [{"name": "my_cookie", "enforcementType": "block_all"}],
        }
    }
    is_valid, errors, _, _ = validate_policy_json(p3)
    assert is_valid is False
    assert any("invalid 'enforcementType'" in e for e in errors)

    # 4. Invalid maximumCookieHeaderLength
    p4 = {
        "policy": {
            "name": "bad_cookie_settings",
            "cookie-settings": {"maximumCookieHeaderLength": -10},
        }
    }
    is_valid, errors, _, _ = validate_policy_json(p4)
    assert is_valid is False
    assert any("maximumCookieHeaderLength" in e for e in errors)

    # 5. Invalid enforcerStateCookies secureAttribute
    p5 = {
        "policy": {
            "name": "bad_enforcer_cookies",
            "enforcer-settings": {
                "enforcerStateCookies": {
                    "secureAttribute": "invalid_val",
                }
            },
        }
    }
    is_valid, errors, _, _ = validate_policy_json(p5)
    assert is_valid is False
    assert any("secureAttribute" in e for e in errors)


def test_cookie_sanitization():
    raw_policy = {
        "policy": {
            "name": "cookie_sanitize_test",
            "cookies": [
                {
                    "name": "  user_*  ",
                    # type omitted, should be inferred as wildcard due to '*'
                    "enforcementType": "ENFORCE",
                    "attackSignaturesCheck": 1,
                    "maskValueInLogs": 0,
                }
            ],
            "cookie-settings": {
                "maximumCookieHeaderLength": "4096",
            },
        }
    }
    sanitized = sanitize_waf_policy(raw_policy)
    cookie = sanitized["policy"]["cookies"][0]
    assert cookie["name"] == "user_*"
    assert cookie["type"] == "wildcard"
    assert cookie["enforcementType"] == "enforce"
    assert cookie["attackSignaturesCheck"] is True
    assert cookie["maskValueInLogs"] is False
    assert sanitized["policy"]["cookie-settings"]["maximumCookieHeaderLength"] == 4096







