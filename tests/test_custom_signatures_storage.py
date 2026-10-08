"""
Tests for Custom Signatures Storage backends (Memory & Redis).
"""

from f5_waf_editor.schemas.waf_schema import DEFAULT_USER_SIGNATURE_DEFINITIONS
from f5_waf_editor.storage.memory_custom_signatures_backend import MemoryCustomSignaturesStorage


def test_memory_storage_seeding_and_list():
    storage = MemoryCustomSignaturesStorage(seed_sample=True)
    files = storage.list_signature_files()
    assert len(files) == 1
    assert files[0]["tag"] == "Fruits"
    assert files[0]["signatures_count"] == 2


def test_memory_storage_crud():
    storage = MemoryCustomSignaturesStorage(seed_sample=False)
    assert len(storage.list_signature_files()) == 0

    custom_doc = {
        "tag": "APISecurity",
        "softwareVersion": "15.1.0",
        "revisionDatetime": "2026-10-01T12:00:00Z",
        "signatures": [
            {
                "name": "GraphQL_Introspection_Probe",
                "rule": 'content:"__schema"; nocase;',
                "signatureType": "request",
                "attackType": {"name": "Information Leakage"},
                "systems": [{"name": "Node.js"}],
                "risk": "medium",
                "accuracy": "high",
            }
        ],
    }

    # Save
    res = storage.save_signature_file("APISecurity", custom_doc)
    assert res["tag"] == "APISecurity"

    # Get
    saved = storage.get_signature_file("APISecurity")
    assert saved is not None
    assert saved["tag"] == "APISecurity"
    assert len(saved["signatures"]) == 1
    assert saved["signatures"][0]["name"] == "GraphQL_Introspection_Probe"

    # Flattened list
    all_sigs = storage.get_all_signatures()
    assert len(all_sigs) == 1
    assert all_sigs[0]["tag"] == "APISecurity"

    # Delete
    deleted = storage.delete_signature_file("APISecurity")
    assert deleted is True
    assert storage.get_signature_file("APISecurity") is None
