"""
Resilient In-Memory storage backend for F5 WAF Policies.
Acts as a zero-dependency fallback when Redis is not running or during local tests.
Pre-seeds with reference templates.
"""

import json
from typing import Any, Dict, List, Optional

from .base import PolicyStorage
from ..schemas.validator import validate_policy_json
from ..schemas.waf_schema import extract_policy_metadata, sanitize_waf_policy
from ..templates_catalog import get_template_json, list_templates


class MemoryPolicyStorage(PolicyStorage):
    """In-memory policy storage with identical semantics to Redis backend."""

    def __init__(self, seed_templates: bool = True):
        self._store: Dict[str, str] = {}
        self._meta_cache: Dict[str, Dict[str, Any]] = {}
        if seed_templates:
            self._seed_initial_policies()

    def _seed_initial_policies(self) -> None:
        """Seed storage with built-in templates so the UI is immediately usable."""
        for tmpl in list_templates():
            content = get_template_json(tmpl["id"])
            if content:
                policy_name = content.get("policy", {}).get("name", tmpl["id"])
                json_str = json.dumps(content, indent=2, ensure_ascii=False)
                json_bytes = json_str.encode("utf-8")
                self._store[policy_name] = json_str
                meta = extract_policy_metadata(content, len(json_bytes))
                meta["name"] = policy_name
                meta["key"] = policy_name
                self._meta_cache[policy_name] = meta

    def list_policies(self) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        for name, raw_val in self._store.items():
            if name.startswith("log:"):
                continue

            cached = self._meta_cache.get(name)
            if cached is not None:
                policies.append(dict(cached))
                continue

            try:
                parsed = json.loads(raw_val)
                if not isinstance(parsed, dict) or "policy" not in parsed:
                    continue
                meta = extract_policy_metadata(parsed, len(raw_val.encode("utf-8")))
                meta["name"] = name
                meta["key"] = name
                self._meta_cache[name] = meta
                policies.append(dict(meta))
            except Exception:
                continue

        policies.sort(key=lambda x: x["name"].lower())
        return policies

    def get_policy(self, name: str) -> Optional[Dict[str, Any]]:
        if name.startswith("log:"):
            return None
        raw_val = self._store.get(name)
        if raw_val is None:
            return None
        try:
            parsed = json.loads(raw_val)
            if not isinstance(parsed, dict) or "policy" not in parsed:
                return None
            return sanitize_waf_policy(parsed)
        except Exception:
            return None

    def get_raw_policy(self, name: str) -> Optional[str]:
        if name.startswith("log:"):
            return None
        return self._store.get(name)

    def save_policy(self, name: str, policy_content: Any, pre_validated: bool = False) -> Dict[str, Any]:
        if name.startswith("log:"):
            raise ValueError("Policy name cannot start with reserved prefix 'log:'")

        if pre_validated and isinstance(policy_content, dict):
            parsed = sanitize_waf_policy(policy_content)
            warnings: List[str] = []
        else:
            if isinstance(policy_content, dict):
                policy_content = sanitize_waf_policy(policy_content)

            is_valid, errors, warnings, parsed = validate_policy_json(policy_content)
            if not is_valid or parsed is None:
                raise ValueError(f"Policy validation failed: {'; '.join(errors)}")

        if "policy" in parsed and isinstance(parsed["policy"], dict):
            parsed["policy"]["name"] = name

        json_str = json.dumps(parsed, indent=2, ensure_ascii=False)
        json_bytes = json_str.encode("utf-8")
        self._store[name] = json_str

        meta = extract_policy_metadata(parsed, len(json_bytes))
        meta["warnings"] = warnings
        meta["name"] = name
        meta["key"] = name
        self._meta_cache[name] = meta
        return meta

    def delete_policy(self, name: str) -> bool:
        if name.startswith("log:"):
            return False
        self._meta_cache.pop(name, None)
        if name in self._store:
            del self._store[name]
            return True
        return False

    def policy_exists(self, name: str) -> bool:
        if name.startswith("log:"):
            return False
        return name in self._store

    def clone_policy(self, source_name: str, new_name: str) -> Dict[str, Any]:
        if source_name.startswith("log:") or new_name.startswith("log:"):
            raise ValueError("Policy name cannot start with reserved prefix 'log:'")

        source_policy = self.get_policy(source_name)
        if not source_policy:
            raise FileNotFoundError(f"Source policy '{source_name}' not found")

        if self.policy_exists(new_name):
            raise FileExistsError(f"Target policy '{new_name}' already exists")

        if "policy" in source_policy and isinstance(source_policy["policy"], dict):
            source_policy["policy"]["name"] = new_name
            desc = source_policy["policy"].get("description", "")
            source_policy["policy"]["description"] = f"{desc} (Clone of {source_name})"

        return self.save_policy(new_name, source_policy)

    def rename_policy(self, old_name: str, new_name: str, policy_content: Optional[Any] = None) -> Dict[str, Any]:
        if old_name.startswith("log:") or new_name.startswith("log:"):
            raise ValueError("Policy name cannot start with reserved prefix 'log:'")

        if not self.policy_exists(old_name):
            raise FileNotFoundError(f"Source policy '{old_name}' not found")

        if old_name != new_name and self.policy_exists(new_name):
            raise FileExistsError(f"Target policy '{new_name}' already exists")

        content_to_save = policy_content
        if content_to_save is None:
            raw = self.get_raw_policy(old_name)
            if not raw:
                raise FileNotFoundError(f"Source policy '{old_name}' not found")
            try:
                content_to_save = json.loads(raw)
            except Exception as e:
                raise ValueError(f"Failed to parse source policy JSON: {e}")

        if isinstance(content_to_save, dict) and "policy" in content_to_save and isinstance(content_to_save["policy"], dict):
            content_to_save["policy"]["name"] = new_name

        meta = self.save_policy(new_name, content_to_save)
        if old_name != new_name:
            self.delete_policy(old_name)
        return meta

    def get_health(self) -> Dict[str, Any]:
        policy_count = len([k for k in self._store if not k.startswith("log:")])
        return {
            "status": "fallback",
            "backend": "in_memory",
            "connected": True,
            "latency_ms": 0.05,
            "total_policies": policy_count,
            "note": "Running in-memory storage fallback. Changes will reset on restart. Start Redis for persistence.",
        }
