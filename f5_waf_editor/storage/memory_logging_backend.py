"""
In-memory fallback backend for F5 WAF Logging Profiles.
Pre-seeded with official F5 WAF for NGINX logging profile templates.
"""

import json
from typing import Any, Dict, List, Optional, Union
from f5_waf_editor.schemas.logging_schema import extract_logging_metadata
from f5_waf_editor.schemas.logging_validator import validate_logging_profile_json
from f5_waf_editor.storage.logging_base import LoggingProfileStorage
from f5_waf_editor.templates_catalog.logging import list_logging_templates, get_logging_template_json


class MemoryLoggingStorage(LoggingProfileStorage):
    """In-memory logging profile storage for zero-dependency execution and testing."""

    def __init__(self, seed_templates: bool = True):
        self._store: Dict[str, str] = {}
        if seed_templates:
            self._seed()

    def _seed(self):
        """Seed storage with built-in logging templates."""
        for tmpl in list_logging_templates():
            content = get_logging_template_json(tmpl["id"])
            if content:
                try:
                    parsed = json.loads(content)
                    self._store[tmpl["id"]] = json.dumps(parsed, indent=2, ensure_ascii=False)
                except Exception:
                    self._store[tmpl["id"]] = content

    def list_profiles(self) -> List[Dict[str, Any]]:
        profiles = []
        for name in sorted(self._store.keys()):
            raw = self._store[name]
            try:
                data = json.loads(raw)
            except Exception:
                data = None
            meta = extract_logging_metadata(data, size_bytes=len(raw.encode("utf-8")))
            meta["name"] = name
            profiles.append(meta)
        return profiles

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        raw = self.get_raw_profile(name)
        if raw is None:
            return None
        return json.loads(raw)

    def get_raw_profile(self, name: str) -> Optional[str]:
        return self._store.get(name)

    def save_profile(self, name: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        is_valid, errors, warnings, parsed = validate_logging_profile_json(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid logging profile JSON: {'; '.join(errors)}")

        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        self._store[name] = formatted

        meta = extract_logging_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["name"] = name
        return meta

    def delete_profile(self, name: str) -> bool:
        if name in self._store:
            del self._store[name]
            return True
        return False

    def clone_profile(self, source_name: str, new_name: str) -> Dict[str, Any]:
        if source_name not in self._store:
            raise KeyError(f"Source logging profile '{source_name}' does not exist")
        if new_name in self._store:
            raise ValueError(f"Target logging profile '{new_name}' already exists")

        parsed = json.loads(self._store[source_name])
        return self.save_profile(new_name, parsed)

    def profile_exists(self, name: str) -> bool:
        return name in self._store
