"""
Unit tests for Policy Storage backends (Memory and Redis).
"""

import pytest
from f5_waf_editor.storage.memory_backend import MemoryPolicyStorage


def test_memory_storage_crud():
    storage = MemoryPolicyStorage(seed_templates=False)
    assert len(storage.list_policies()) == 0

    policy_data = {
        "policy": {
            "name": "ecommerce_waf",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "description": "Production E-commerce WAF policy",
        }
    }

    # Save
    meta = storage.save_policy("ecommerce_waf", policy_data)
    assert meta["name"] == "ecommerce_waf"
    assert storage.policy_exists("ecommerce_waf") is True
    assert len(storage.list_policies()) == 1

    # Get
    retrieved = storage.get_policy("ecommerce_waf")
    assert retrieved is not None
    assert retrieved["policy"]["name"] == "ecommerce_waf"
    assert retrieved["policy"]["enforcementMode"] == "blocking"

    # Clone
    clone_meta = storage.clone_policy("ecommerce_waf", "ecommerce_waf_staging")
    assert clone_meta["name"] == "ecommerce_waf_staging"
    assert storage.policy_exists("ecommerce_waf_staging") is True
    assert len(storage.list_policies()) == 2

    # Delete
    deleted = storage.delete_policy("ecommerce_waf")
    assert deleted is True
    assert storage.policy_exists("ecommerce_waf") is False
    assert len(storage.list_policies()) == 1

    # Health
    health = storage.get_health()
    assert health["connected"] is True
    assert health["backend"] == "in_memory"


def test_memory_storage_seed():
    storage = MemoryPolicyStorage(seed_templates=True)
    policies = storage.list_policies()
    assert len(policies) >= 4
    names = [p["name"] for p in policies]
    assert "app_protect_default_policy" in names


def test_storage_ignores_logging_profiles():
    storage = MemoryPolicyStorage(seed_templates=False)
    # Add a WAF policy
    storage.save_policy(
        "my_waf_policy",
        {
            "policy": {
                "name": "my_waf_policy",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": "blocking",
            }
        },
    )
    # Manually simulate a logging profile stored with log: prefix or non-policy format
    storage._store["log:my_log_profile"] = '{"filter":{"request_type":"illegal"},"content":{"format":"default"}}'

    # list_policies must NOT include log:my_log_profile
    policies = storage.list_policies()
    assert len(policies) == 1
    assert policies[0]["name"] == "my_waf_policy"

    # get_policy on log:my_log_profile must return None
    assert storage.get_policy("log:my_log_profile") is None
    assert storage.policy_exists("log:my_log_profile") is False

    # Attempting to save with log: prefix raises ValueError
    with pytest.raises(ValueError, match="reserved prefix 'log:'"):
        storage.save_policy(
            "log:illegal_policy_name",
            {
                "policy": {
                    "name": "log:illegal_policy_name",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                    "enforcementMode": "blocking",
                }
            },
        )


def test_memory_storage_rename():
    storage = MemoryPolicyStorage(seed_templates=False)
    storage.save_policy(
        "orig_policy",
        {
            "policy": {
                "name": "orig_policy",
                "description": "Original description",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": "blocking",
            }
        },
    )
    assert storage.policy_exists("orig_policy") is True
    assert storage.policy_exists("renamed_policy") is False

    # Rename with new description
    meta = storage.rename_policy(
        "orig_policy",
        "renamed_policy",
        {
            "policy": {
                "name": "renamed_policy",
                "description": "Updated description",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": "transparent",
            }
        },
    )
    assert meta["name"] == "renamed_policy"
    assert meta["description"] == "Updated description"
    assert meta["enforcementMode"] == "transparent"
    assert storage.policy_exists("orig_policy") is False
    assert storage.policy_exists("renamed_policy") is True

    # Policy content inside JSON must be updated to renamed_policy
    pol = storage.get_policy("renamed_policy")
    assert pol["policy"]["name"] == "renamed_policy"
    assert pol["policy"]["description"] == "Updated description"

    # Renaming non-existent source raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        storage.rename_policy("non_existent", "another_name")

    # Renaming to existing target raises FileExistsError
    storage.save_policy(
        "second_policy",
        {
            "policy": {
                "name": "second_policy",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                "enforcementMode": "blocking",
            }
        },
    )
    with pytest.raises(FileExistsError):
        storage.rename_policy("renamed_policy", "second_policy")

    # Renaming to invalid log: prefix raises ValueError
    with pytest.raises(ValueError, match="reserved prefix 'log:'"):
        storage.rename_policy("renamed_policy", "log:invalid_name")


