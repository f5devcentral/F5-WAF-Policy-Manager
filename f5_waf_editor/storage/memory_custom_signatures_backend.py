"""
In-memory fallback backend for F5 WAF User-Defined Signatures.
Pre-seeded with official F5 WAF for NGINX user-defined signature definitions.
"""

from copy import deepcopy
import json
from typing import Any, Dict, List, Optional, Union

from f5_waf_editor.schemas.waf_schema import (
    DEFAULT_USER_SIGNATURE_DEFINITIONS,
    extract_custom_signatures_metadata,
)
from f5_waf_editor.schemas.validator import validate_user_defined_signatures_file
from f5_waf_editor.storage.custom_signatures_base import CustomSignaturesStorage


class MemoryCustomSignaturesStorage(CustomSignaturesStorage):
    """In-memory custom signatures storage for local testing and zero-dependency execution."""

    def __init__(self, seed_sample: bool = True):
        self._store: Dict[str, str] = {}
        if seed_sample:
            self._seed()

    def _seed(self):
        """Seed storage with the official sample custom signatures definition."""
        sample = deepcopy(DEFAULT_USER_SIGNATURE_DEFINITIONS)
        tag = sample.get("tag", "Fruits")
        self._store[tag] = json.dumps(sample, indent=2, ensure_ascii=False)

    def list_signature_files(self) -> List[Dict[str, Any]]:
        results = []
        for tag in sorted(self._store.keys()):
            raw = self._store[tag]
            try:
                data = json.loads(raw)
            except Exception:
                data = None
            meta = extract_custom_signatures_metadata(data, size_bytes=len(raw.encode("utf-8")))
            meta["tag"] = tag
            results.append(meta)
        return results

    def get_signature_file(self, tag: str) -> Optional[Dict[str, Any]]:
        raw = self.get_raw_signature_file(tag)
        if raw is None:
            return None
        return json.loads(raw)

    def get_raw_signature_file(self, tag: str) -> Optional[str]:
        return self._store.get(tag)

    def save_signature_file(self, tag: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        is_valid, errors, warnings, parsed = validate_user_defined_signatures_file(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid user-defined signature definition JSON: {'; '.join(errors)}")

        effective_tag = tag.strip() if tag else parsed.get("tag", "user-defined-signatures").strip()
        parsed["tag"] = effective_tag

        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        self._store[effective_tag] = formatted

        meta = extract_custom_signatures_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["tag"] = effective_tag
        return {
            "tag": effective_tag,
            "metadata": meta,
            "warnings": warnings,
        }

    def delete_signature_file(self, tag: str) -> bool:
        if tag in self._store:
            del self._store[tag]
            return True
        return False

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        all_sigs = []
        for tag, raw in self._store.items():
            try:
                doc = json.loads(raw)
                for s in doc.get("signatures", []):
                    if isinstance(s, dict):
                        sig_copy = deepcopy(s)
                        sig_copy["tag"] = tag
                        sig_copy["source_file"] = f"{tag}.json"
                        all_sigs.append(sig_copy)
            except Exception:
                continue
        return all_sigs
