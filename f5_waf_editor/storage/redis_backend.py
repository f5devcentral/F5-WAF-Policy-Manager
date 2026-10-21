"""
Redis backend implementation for F5 WAF Policy Storage.
Stores policies directly in Redis where each key is a policy name and value is the JSON document.
"""

import json
import time
from typing import Any, Dict, List, Optional
import redis

from .base import PolicyStorage
from ..schemas.validator import validate_policy_json
from ..schemas.waf_schema import extract_policy_metadata, sanitize_waf_policy


class RedisPolicyStorage(PolicyStorage):
    """Storage backend backed by a Redis server."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ssl: bool = False,
        key_prefix: str = "",
        socket_timeout: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.ssl = ssl
        self.key_prefix = key_prefix
        self.client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            ssl=ssl,
            decode_responses=True,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
        )

    def _format_key(self, name: str) -> str:
        if self.key_prefix:
            return f"{self.key_prefix}{name}"
        return name

    def _strip_prefix(self, key: str) -> str:
        if self.key_prefix and key.startswith(self.key_prefix):
            return key[len(self.key_prefix) :]
        return key

    def _meta_key(self, name: str) -> str:
        return self._format_key(f"__meta__:{name}")

    def list_policies(self) -> List[Dict[str, Any]]:
        search_pattern = f"{self.key_prefix}*" if self.key_prefix else "*"
        keys = self.client.keys(search_pattern)
        policies: List[Dict[str, Any]] = []

        policy_keys = [
            k for k in keys
            if not self._strip_prefix(k).startswith("log:")
            and not self._strip_prefix(k).startswith("sig:")
            and not self._strip_prefix(k).startswith("__meta__:")
            and not self._strip_prefix(k).startswith("__clickhouse__:")
            and not self._strip_prefix(k).startswith("__github_")
        ]
        if not policy_keys:
            return []

        # Batch lookup cached metadata using mget to avoid reading full policy payloads
        meta_keys = [self._meta_key(self._strip_prefix(k)) for k in policy_keys]
        try:
            cached_metas = self.client.mget(meta_keys)
        except Exception:
            cached_metas = [None] * len(policy_keys)

        for idx, k in enumerate(policy_keys):
            policy_name = self._strip_prefix(k)
            cached_raw = cached_metas[idx] if idx < len(cached_metas) else None
            if cached_raw:
                try:
                    meta = json.loads(cached_raw)
                    policies.append(meta)
                    continue
                except Exception:
                    pass

            raw_val = self.client.get(k)
            if not raw_val:
                continue

            try:
                parsed = json.loads(raw_val)
                # Ensure the document is an actual F5 WAF policy (has 'policy' root key)
                if not isinstance(parsed, dict) or "policy" not in parsed:
                    continue

                raw_bytes = raw_val.encode("utf-8") if isinstance(raw_val, str) else raw_val
                meta = extract_policy_metadata(parsed, len(raw_bytes))
                meta["name"] = policy_name
                meta["key"] = k
                try:
                    self.client.set(self._meta_key(policy_name), json.dumps(meta, ensure_ascii=False))
                except Exception:
                    pass
                policies.append(meta)
            except Exception:
                continue

        policies.sort(key=lambda x: x["name"].lower())
        return policies

    def get_policy(self, name: str) -> Optional[Dict[str, Any]]:
        if (
            name.startswith("log:")
            or name.startswith("sig:")
            or name.startswith("__clickhouse__:")
            or name.startswith("__github_")
        ):
            return None
        key = self._format_key(name)
        raw_val = self.client.get(key)
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
        key = self._format_key(name)
        return self.client.get(key)

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

        # Ensure policy name in JSON matches target name
        if "policy" in parsed and isinstance(parsed["policy"], dict):
            parsed["policy"]["name"] = name

        json_str = json.dumps(parsed, indent=2, ensure_ascii=False)
        json_bytes = json_str.encode("utf-8")
        key = self._format_key(name)
        meta_key = self._meta_key(name)
        self.client.set(key, json_bytes)

        meta = extract_policy_metadata(parsed, len(json_bytes))
        meta["warnings"] = warnings
        meta["name"] = name
        meta["key"] = key
        try:
            self.client.set(meta_key, json.dumps(meta, ensure_ascii=False))
        except Exception:
            pass
        return meta

    def delete_policy(self, name: str) -> bool:
        if name.startswith("log:"):
            return False
        key = self._format_key(name)
        meta_key = self._meta_key(name)
        count = self.client.delete(key, meta_key)
        return count > 0

    def policy_exists(self, name: str) -> bool:
        if name.startswith("log:"):
            return False
        key = self._format_key(name)
        return bool(self.client.exists(key))

    def clone_policy(self, source_name: str, new_name: str) -> Dict[str, Any]:
        if source_name.startswith("log:") or new_name.startswith("log:"):
            raise ValueError("Policy name cannot start with reserved prefix 'log:'")

        source_policy = self.get_policy(source_name)
        if not source_policy:
            raise FileNotFoundError(f"Source policy '{source_name}' not found")

        if self.policy_exists(new_name):
            raise FileExistsError(f"Target policy '{new_name}' already exists")

        # Update name inside JSON
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
        t0 = time.time()
        try:
            self.client.ping()
            latency_ms = round((time.time() - t0) * 1000, 2)
            search_pattern = f"{self.key_prefix}*" if self.key_prefix else "*"
            all_keys = self.client.keys(search_pattern)
            policy_keys = [
                k for k in all_keys
                if not self._strip_prefix(k).startswith("log:")
                and not self._strip_prefix(k).startswith("__meta__:")
            ]
            keys_count = len(policy_keys)
            info = self.client.info()
            return {
                "status": "connected",
                "backend": "redis",
                "host": self.host,
                "port": self.port,
                "db": self.db,
                "connected": True,
                "latency_ms": latency_ms,
                "redis_version": info.get("redis_version", "unknown"),
                "total_policies": keys_count,
            }
        except Exception as exc:
            return {
                "status": "disconnected",
                "backend": "redis",
                "host": self.host,
                "port": self.port,
                "db": self.db,
                "connected": False,
                "error": str(exc),
            }
