"""
Tests for F5 WAF Logging Profile Storage Engines.
"""

import pytest
from f5_waf_editor.storage.memory_logging_backend import MemoryLoggingStorage


def test_memory_storage_preseeded():
    storage = MemoryLoggingStorage(seed_templates=True)
    profiles = storage.list_profiles()
    assert len(profiles) >= 5

    names = [p["name"] for p in profiles]
    assert "log_default" in names
    assert "log_splunk" in names
    assert "log_arcsight" in names


def test_memory_storage_crud():
    storage = MemoryLoggingStorage(seed_templates=False)
    assert len(storage.list_profiles()) == 0

    doc = {
        "filter": {"request_type": "illegal"},
        "content": {"format": "default", "max_message_size": "32k"},
    }

    # Save
    meta = storage.save_profile("test_profile", doc)
    assert meta["name"] == "test_profile"
    assert storage.profile_exists("test_profile")

    # Get
    retrieved = storage.get_profile("test_profile")
    assert retrieved is not None
    assert retrieved["filter"]["request_type"] == "illegal"

    # Clone
    clone_meta = storage.clone_profile("test_profile", "cloned_profile")
    assert clone_meta["name"] == "cloned_profile"
    assert storage.profile_exists("cloned_profile")

    # Delete
    deleted = storage.delete_profile("test_profile")
    assert deleted is True
    assert not storage.profile_exists("test_profile")
    assert storage.profile_exists("cloned_profile")
