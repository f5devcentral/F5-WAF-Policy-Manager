"""
Redis backend implementation for F5 WAF Logging Profiles.
Stores each profile where Redis key is "log:<profile_name>" (or with custom prefix)
and value is the JSON logging profile document.
"""

import json
from typing import Any, Dict, List, Optional, Union
import redis
from f5_waf_editor.config import Settings, settings
from f5_waf_editor.schemas.logging_schema import extract_logging_metadata
from f5_waf_editor.schemas.logging_validator import validate_logging_profile_json
from f5_waf_editor.storage.logging_base import LoggingProfileStorage


class RedisLoggingStorage(LoggingProfileStorage):
    """Stores F5 WAF Logging Profiles in Redis under 'log:<name>' keys."""

    def __init__(self, app_settings: Optional[Settings] = None, redis_client: Optional[redis.Redis] = None):
        self.settings = app_settings or settings
        self.key_prefix = f"{self.settings.redis_key_prefix}log:"
        if redis_client:
            self.client = redis_client
        else:
            self.client = redis.Redis(
                host=self.settings.redis_host,
                port=self.settings.redis_port,
                db=self.settings.redis_db,
                password=self.settings.redis_password,
                ssl=self.settings.redis_ssl,
                decode_responses=True,
                socket_timeout=self.settings.redis_timeout,
            )

    def _full_key(self, name: str) -> str:
        return f"{self.key_prefix}{name}"

    def _extract_name_from_key(self, full_key: str) -> str:
        if full_key.startswith(self.key_prefix):
            return full_key[len(self.key_prefix) :]
        return full_key

    def list_profiles(self) -> List[Dict[str, Any]]:
        keys = self.client.keys(f"{self.key_prefix}*")
        profiles: List[Dict[str, Any]] = []

        for k in sorted(keys):
            name = self._extract_name_from_key(k)
            raw = self.client.get(k)
            if not raw:
                continue

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
        return self.client.get(self._full_key(name))

    def save_profile(self, name: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        is_valid, errors, warnings, parsed = validate_logging_profile_json(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid logging profile JSON: {'; '.join(errors)}")

        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        self.client.set(self._full_key(name), formatted)

        meta = extract_logging_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["name"] = name
        return meta

    def delete_profile(self, name: str) -> bool:
        res = self.client.delete(self._full_key(name))
        return bool(res > 0)

    def clone_profile(self, source_name: str, new_name: str) -> Dict[str, Any]:
        raw = self.get_raw_profile(source_name)
        if raw is None:
            raise KeyError(f"Source logging profile '{source_name}' does not exist")
        if self.profile_exists(new_name):
            raise ValueError(f"Target logging profile '{new_name}' already exists")

        parsed = json.loads(raw)
        return self.save_profile(new_name, parsed)

    def profile_exists(self, name: str) -> bool:
        return bool(self.client.exists(self._full_key(name)))
