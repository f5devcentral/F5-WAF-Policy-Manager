"""
Redis backend implementation for F5 WAF User-Defined Signatures.
Stores each file under "custom_sig:<tag>" key where value is the JSON definition document.
"""

from copy import deepcopy
import json
from typing import Any, Dict, List, Optional, Union
import redis

from f5_waf_editor.config import Settings, settings
from f5_waf_editor.schemas.waf_schema import (
    DEFAULT_USER_SIGNATURE_DEFINITIONS,
    extract_custom_signatures_metadata,
)
from f5_waf_editor.schemas.validator import validate_user_defined_signatures_file
from f5_waf_editor.storage.custom_signatures_base import CustomSignaturesStorage


class RedisCustomSignaturesStorage(CustomSignaturesStorage):
    """Stores F5 WAF User-Defined Signatures definition files in Redis under 'custom_sig:<tag>' keys."""

    def __init__(
        self,
        app_settings: Optional[Settings] = None,
        redis_client: Optional[redis.Redis] = None,
        seed_sample: bool = True,
    ):
        self.settings = app_settings or settings
        self.key_prefix = f"{self.settings.redis_key_prefix}custom_sig:"
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
        if seed_sample and not self.list_signature_files():
            self._seed()

    def _seed(self):
        """Seed storage with sample user-defined signatures if empty."""
        sample = deepcopy(DEFAULT_USER_SIGNATURE_DEFINITIONS)
        tag = sample.get("tag", "Fruits")
        self.save_signature_file(tag, sample)

    def _full_key(self, tag: str) -> str:
        return f"{self.key_prefix}{tag}"

    def _extract_tag_from_key(self, full_key: str) -> str:
        if full_key.startswith(self.key_prefix):
            return full_key[len(self.key_prefix) :]
        return full_key

    def list_signature_files(self) -> List[Dict[str, Any]]:
        keys = self.client.keys(f"{self.key_prefix}*")
        files: List[Dict[str, Any]] = []

        for k in sorted(keys):
            tag = self._extract_tag_from_key(k)
            raw = self.client.get(k)
            if not raw:
                continue

            try:
                data = json.loads(raw)
            except Exception:
                data = None

            meta = extract_custom_signatures_metadata(data, size_bytes=len(raw.encode("utf-8")))
            meta["tag"] = tag
            files.append(meta)

        return files

    def get_signature_file(self, tag: str) -> Optional[Dict[str, Any]]:
        raw = self.get_raw_signature_file(tag)
        if raw is None:
            return None
        return json.loads(raw)

    def get_raw_signature_file(self, tag: str) -> Optional[str]:
        return self.client.get(self._full_key(tag))

    def save_signature_file(self, tag: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        is_valid, errors, warnings, parsed = validate_user_defined_signatures_file(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid user-defined signature definition JSON: {'; '.join(errors)}")

        effective_tag = tag.strip() if tag else parsed.get("tag", "user-defined-signatures").strip()
        parsed["tag"] = effective_tag

        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        self.client.set(self._full_key(effective_tag), formatted)

        meta = extract_custom_signatures_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["tag"] = effective_tag
        return {
            "tag": effective_tag,
            "metadata": meta,
            "warnings": warnings,
        }

    def delete_signature_file(self, tag: str) -> bool:
        deleted_count = self.client.delete(self._full_key(tag))
        return bool(deleted_count > 0)

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        keys = self.client.keys(f"{self.key_prefix}*")
        all_sigs = []
        for k in sorted(keys):
            tag = self._extract_tag_from_key(k)
            raw = self.client.get(k)
            if not raw:
                continue
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
