"""
GitHub GitOps storage backend for F5 WAF User-Defined Signatures (Custom Signatures).
Uses GitHub repository as code (Source of Truth) while utilizing local Redis
(or resilient Memory storage) as an intermediate staging cache for uncommitted working drafts.
"""

from copy import deepcopy
import json
import logging
from typing import Any, Dict, List, Optional, Union

from .custom_signatures_base import CustomSignaturesStorage
from .github_client import GitHubClient
from ..schemas.waf_schema import extract_custom_signatures_metadata
from ..schemas.validator import validate_user_defined_signatures_file

logger = logging.getLogger("f5_waf_editor.storage.github_custom_signatures")


class GitHubCustomSignaturesStorage(CustomSignaturesStorage):
    """
    F5 WAF user-defined signatures storage engine backed by GitHub REST API
    with local Redis (or Memory) intermediate staging cache for drafts.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        local_storage: Optional[CustomSignaturesStorage] = None,
        custom_sigs_path: str = "custom-signatures",
    ):
        self.client = github_client
        self.local_storage = local_storage
        self.custom_sigs_path = custom_sigs_path.strip("/")
        self._sha_content_cache: Dict[str, str] = {}
        self._sha_meta_cache: Dict[str, Dict[str, Any]] = {}
        self._tag_to_sha: Dict[str, str] = {}
        self._dirty_tags: set[str] = set()

    def _dirty_set_key(self) -> str:
        prefix = getattr(self.local_storage, "key_prefix", "") if self.local_storage else ""
        return f"{prefix}__github_dirty_custom_sigs__"

    def _is_dirty(self, tag: str) -> bool:
        if tag in self._dirty_tags:
            return True
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "sismember"):
                    return bool(redis_c.sismember(self._dirty_set_key(), tag))
            except Exception:
                pass
        return False

    def _mark_dirty(self, tag: str) -> None:
        self._dirty_tags.add(tag)
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "sadd"):
                    redis_c.sadd(self._dirty_set_key(), tag)
            except Exception:
                pass

    def _unmark_dirty(self, tag: str) -> None:
        self._dirty_tags.discard(tag)
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "srem"):
                    redis_c.srem(self._dirty_set_key(), tag)
            except Exception:
                pass

    def _get_all_dirty(self) -> set[str]:
        dirty = set(self._dirty_tags)
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "smembers"):
                    members = redis_c.smembers(self._dirty_set_key())
                    if members:
                        for m in members:
                            dirty.add(m.decode("utf-8") if isinstance(m, bytes) else str(m))
            except Exception:
                pass
        return dirty

    def _file_path_for(self, tag: str) -> str:
        clean_tag = tag.strip()
        if not clean_tag.endswith(".json"):
            clean_tag = f"{clean_tag}.json"
        return f"{self.custom_sigs_path}/{clean_tag}" if self.custom_sigs_path else clean_tag

    def list_signature_files(self) -> List[Dict[str, Any]]:
        """List all custom signature definition files from GitHub repository and local drafts."""
        files = self.client.list_files(self.custom_sigs_path)
        results: List[Dict[str, Any]] = []

        active_tags = set()
        for f in files:
            file_name = f.get("name", "")
            if not file_name.endswith(".json") or file_name.startswith("."):
                continue

            tag = file_name[:-5]
            active_tags.add(tag)
            sha = f.get("sha")
            file_path = f.get("path", self._file_path_for(tag))

            meta = None
            if sha and sha in self._sha_meta_cache:
                meta = dict(self._sha_meta_cache[sha])
            else:
                try:
                    raw_content, blob_sha = self.client.get_file(file_path)
                    if raw_content:
                        parsed = json.loads(raw_content)
                        current_sha = blob_sha or sha or ""
                        meta = extract_custom_signatures_metadata(parsed, size_bytes=len(raw_content.encode("utf-8")))
                        meta["github_path"] = file_path
                        meta["github_sha"] = current_sha
                        if current_sha:
                            self._sha_content_cache[current_sha] = raw_content
                            self._sha_meta_cache[current_sha] = dict(meta)
                            self._tag_to_sha[tag] = current_sha
                except Exception as exc:
                    logger.warning("Failed to parse custom signature file '%s' from GitHub: %s", file_name, exc)
                    continue

            if meta is None:
                meta = {
                    "tag": tag,
                    "signatures_count": 0,
                    "sizeBytes": 0,
                    "github_path": file_path,
                }

            meta["tag"] = tag

            if self._is_dirty(tag) and self.local_storage is not None:
                meta["uncommitted_changes"] = True
                meta["status"] = "modified"
                local_raw = self.local_storage.get_raw_signature_file(tag)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        local_meta = extract_custom_signatures_metadata(local_parsed, size_bytes=len(local_raw.encode("utf-8")))
                        meta.update(local_meta)
                        meta["tag"] = tag
                        meta["uncommitted_changes"] = True
                        meta["status"] = "modified"
                    except Exception:
                        pass
            else:
                meta["uncommitted_changes"] = False
                meta["status"] = "synced"

            results.append(meta)

        stale = [t for t in self._tag_to_sha if t not in active_tags]
        for t in stale:
            self._tag_to_sha.pop(t, None)

        # Include newly created local sets in Redis
        all_dirty = self._get_all_dirty()
        for dirty_tag in all_dirty:
            if dirty_tag not in active_tags and self.local_storage is not None:
                local_raw = self.local_storage.get_raw_signature_file(dirty_tag)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        meta = extract_custom_signatures_metadata(local_parsed, size_bytes=len(local_raw.encode("utf-8")))
                        meta["tag"] = dirty_tag
                        meta["uncommitted_changes"] = True
                        meta["status"] = "new_uncommitted"
                        meta["github_path"] = self._file_path_for(dirty_tag)
                        results.append(meta)
                    except Exception:
                        pass

        results.sort(key=lambda x: x["tag"].lower())
        return results

    def get_signature_file(self, tag: str) -> Optional[Dict[str, Any]]:
        raw = self.get_raw_signature_file(tag)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def get_raw_signature_file(self, tag: str) -> Optional[str]:
        if self._is_dirty(tag) and self.local_storage is not None:
            local_raw = self.local_storage.get_raw_signature_file(tag)
            if local_raw:
                return local_raw

        file_path = self._file_path_for(tag)
        raw_content, blob_sha = self.client.get_file(file_path)
        if raw_content is not None:
            if blob_sha:
                self._sha_content_cache[blob_sha] = raw_content
                self._tag_to_sha[tag] = blob_sha
            if self.local_storage is not None and not self.local_storage.signature_file_exists(tag):
                try:
                    parsed = json.loads(raw_content)
                    self.local_storage.save_signature_file(tag, parsed)
                except Exception:
                    pass
            return raw_content

        if self.local_storage is not None:
            return self.local_storage.get_raw_signature_file(tag)

        return None

    def save_signature_file(self, tag: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        is_valid, errors, _, parsed = validate_user_defined_signatures_file(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid user-defined signature definition JSON: {'; '.join(errors)}")

        effective_tag = tag.strip() if tag else parsed.get("tag", "user-defined-signatures").strip()
        parsed["tag"] = effective_tag

        if self.local_storage is not None:
            meta = self.local_storage.save_signature_file(effective_tag, parsed)
            self._mark_dirty(effective_tag)
            meta["tag"] = effective_tag
            meta["saved_to"] = "redis"
            meta["uncommitted_changes"] = True
            meta["status"] = "modified"
            meta["github_path"] = self._file_path_for(effective_tag)
            meta["message"] = f"Custom signatures '{effective_tag}' saved to local Redis (uncommitted draft)"
            return meta

        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        file_path = self._file_path_for(effective_tag)

        existing_sha = self._tag_to_sha.get(effective_tag)
        is_update = existing_sha is not None or self.signature_file_exists(effective_tag)
        action_verb = "update" if is_update else "create"
        commit_msg = f"feat(waf): {action_verb} custom signatures '{effective_tag}'"

        commit_result = self.client.put_file(
            file_path=file_path,
            content_str=formatted,
            message=commit_msg,
            sha=existing_sha,
        )

        new_sha = commit_result.get("content", {}).get("sha", "")
        if new_sha:
            self._tag_to_sha[effective_tag] = new_sha
            self._sha_content_cache[new_sha] = formatted

        meta = extract_custom_signatures_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["tag"] = effective_tag
        meta["github_path"] = file_path
        meta["github_sha"] = new_sha

        if new_sha:
            self._sha_meta_cache[new_sha] = meta

        return meta

    def push_to_github(self, tag: str, message: Optional[str] = None) -> Dict[str, Any]:
        raw_val = None
        if self.local_storage is not None:
            raw_val = self.local_storage.get_raw_signature_file(tag)
        if not raw_val:
            raw_val = self.get_raw_signature_file(tag)
        if not raw_val:
            raise FileNotFoundError(f"Custom signatures '{tag}' not found to commit to GitHub")

        try:
            parsed = json.loads(raw_val)
            formatted_json = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            formatted_json = raw_val

        file_path = self._file_path_for(tag)
        existing_sha = self._tag_to_sha.get(tag)
        if not existing_sha:
            _, remote_sha = self.client.get_file(file_path)
            if remote_sha:
                existing_sha = remote_sha

        commit_msg = (message or "").strip() or f"feat(waf): update custom signatures '{tag}'"
        commit_res = self.client.put_file(
            file_path=file_path,
            content_str=formatted_json,
            message=commit_msg,
            sha=existing_sha,
        )

        new_sha = commit_res.get("content", {}).get("sha", "")
        if new_sha:
            self._tag_to_sha[tag] = new_sha
            self._sha_content_cache[new_sha] = formatted_json

        self._unmark_dirty(tag)

        commit_data = commit_res.get("commit", {})
        commit_sha = commit_data.get("sha", "")
        short_sha = commit_sha[:7] if commit_sha else ""

        return {
            "success": True,
            "tag": tag,
            "path": file_path,
            "commit_sha": commit_sha,
            "short_sha": short_sha,
            "commit_html_url": commit_data.get("html_url", ""),
            "message": commit_msg,
            "branch": self.client.branch,
            "repo": f"{self.client.owner}/{self.client.repo}",
        }

    def delete_signature_file(self, tag: str) -> bool:
        self._unmark_dirty(tag)
        if self.local_storage is not None:
            try:
                self.local_storage.delete_signature_file(tag)
            except Exception:
                pass

        file_path = self._file_path_for(tag)
        existing_sha = self._tag_to_sha.get(tag)
        if not existing_sha:
            _, existing_sha = self.client.get_file(file_path)

        deleted = False
        if existing_sha:
            commit_msg = f"chore(waf): delete custom signatures '{tag}'"
            deleted = self.client.delete_file(
                file_path=file_path,
                message=commit_msg,
                sha=existing_sha,
            )
            old_sha = self._tag_to_sha.pop(tag, None)
            if old_sha:
                self._sha_content_cache.pop(old_sha, None)
                self._sha_meta_cache.pop(old_sha, None)
        else:
            deleted = True

        return deleted

    def signature_file_exists(self, tag: str) -> bool:
        if self._is_dirty(tag):
            return True
        if tag in self._tag_to_sha:
            return True
        file_path = self._file_path_for(tag)
        _, sha = self.client.get_file(file_path)
        if sha:
            self._tag_to_sha[tag] = sha
            return True
        if self.local_storage is not None and self.local_storage.signature_file_exists(tag):
            return True
        return False

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        files = self.list_signature_files()
        all_sigs = []
        for f in files:
            tag = f.get("tag")
            file_data = self.get_signature_file(tag)
            if not file_data or "signatures" not in file_data:
                continue
            for sig in file_data.get("signatures", []):
                sig_copy = deepcopy(sig)
                sig_copy["tag"] = tag
                all_sigs.append(sig_copy)
        return all_sigs
