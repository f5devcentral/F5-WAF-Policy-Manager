"""
GitHub GitOps storage backend for F5 WAF Logging Profiles.
Uses GitHub repository as code (Source of Truth) while utilizing local Redis
(or resilient Memory storage) as an intermediate staging cache for uncommitted working drafts.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

from .logging_base import LoggingProfileStorage
from .github_client import GitHubClient
from ..schemas.logging_schema import extract_logging_metadata
from ..schemas.logging_validator import validate_logging_profile_json

logger = logging.getLogger("f5_waf_editor.storage.github_logging")


class GitHubLoggingStorage(LoggingProfileStorage):
    """
    F5 WAF logging profile storage engine backed by GitHub REST API (GitOps Source of Truth)
    with local Redis (or Memory) intermediate staging cache for drafts.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        local_storage: Optional[LoggingProfileStorage] = None,
        log_profiles_path: str = "log-profiles",
    ):
        self.client = github_client
        self.local_storage = local_storage
        self.log_profiles_path = log_profiles_path.strip("/")
        self._sha_content_cache: Dict[str, str] = {}
        self._sha_meta_cache: Dict[str, Dict[str, Any]] = {}
        self._name_to_sha: Dict[str, str] = {}
        self._dirty_profiles: set[str] = set()

    def _dirty_set_key(self) -> str:
        prefix = getattr(self.local_storage, "key_prefix", "") if self.local_storage else ""
        return f"{prefix}__github_dirty_log_profiles__"

    def _is_dirty(self, name: str) -> bool:
        if name in self._dirty_profiles:
            return True
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "sismember"):
                    return bool(redis_c.sismember(self._dirty_set_key(), name))
            except Exception:
                pass
        return False

    def _mark_dirty(self, name: str) -> None:
        self._dirty_profiles.add(name)
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "sadd"):
                    redis_c.sadd(self._dirty_set_key(), name)
            except Exception:
                pass

    def _unmark_dirty(self, name: str) -> None:
        self._dirty_profiles.discard(name)
        if self.local_storage is not None and hasattr(self.local_storage, "redis_client"):
            try:
                redis_c = getattr(self.local_storage, "redis_client")
                if hasattr(redis_c, "srem"):
                    redis_c.srem(self._dirty_set_key(), name)
            except Exception:
                pass

    def _get_all_dirty(self) -> set[str]:
        dirty = set(self._dirty_profiles)
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

    def _file_path_for(self, name: str) -> str:
        clean_name = name.strip()
        if not clean_name.endswith(".json"):
            clean_name = f"{clean_name}.json"
        return f"{self.log_profiles_path}/{clean_name}" if self.log_profiles_path else clean_name

    def list_profiles(self) -> List[Dict[str, Any]]:
        """
        List all logging profiles as they exist on the GitHub repository.
        If a profile has intermediate uncommitted edits in local Redis,
        its status reflects that it has local draft changes.
        Any newly created uncommitted profiles in Redis are also included.
        """
        files = self.client.list_files(self.log_profiles_path)
        profiles: List[Dict[str, Any]] = []
        active_names = set()

        for f in files:
            file_name = f.get("name", "")
            if not file_name.endswith(".json") or file_name.startswith("."):
                continue

            profile_name = file_name[:-5]
            active_names.add(profile_name)
            sha = f.get("sha")
            file_path = f.get("path", self._file_path_for(profile_name))

            meta = None
            if sha and sha in self._sha_meta_cache:
                meta = dict(self._sha_meta_cache[sha])
            else:
                try:
                    raw_content, blob_sha = self.client.get_file(file_path)
                    if raw_content:
                        parsed = json.loads(raw_content)
                        current_sha = blob_sha or sha or ""
                        meta = extract_logging_metadata(parsed, size_bytes=len(raw_content.encode("utf-8")))
                        meta["github_path"] = file_path
                        meta["github_sha"] = current_sha
                        if current_sha:
                            self._sha_content_cache[current_sha] = raw_content
                            self._sha_meta_cache[current_sha] = dict(meta)
                            self._name_to_sha[profile_name] = current_sha
                except Exception as exc:
                    logger.warning("Failed to parse logging profile '%s' from GitHub: %s", file_name, exc)
                    continue

            if meta is None:
                meta = {
                    "name": profile_name,
                    "request_type": "all",
                    "format": "default",
                    "sizeBytes": 0,
                    "github_path": file_path,
                }

            meta["name"] = profile_name

            # Check if this profile has uncommitted local draft changes in Redis
            if self._is_dirty(profile_name) and self.local_storage is not None:
                meta["uncommitted_changes"] = True
                meta["status"] = "modified"
                local_raw = self.local_storage.get_raw_profile(profile_name)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        local_meta = extract_logging_metadata(local_parsed, size_bytes=len(local_raw.encode("utf-8")))
                        meta.update(local_meta)
                        meta["name"] = profile_name
                        meta["uncommitted_changes"] = True
                        meta["status"] = "modified"
                    except Exception:
                        pass
            else:
                meta["uncommitted_changes"] = False
                meta["status"] = "synced"

            profiles.append(meta)

        stale = [name for name in self._name_to_sha if name not in active_names]
        for name in stale:
            self._name_to_sha.pop(name, None)

        # Include any newly created local profiles in Redis that do not exist on GitHub yet
        all_dirty = self._get_all_dirty()
        for dirty_name in all_dirty:
            if dirty_name not in active_names and self.local_storage is not None:
                local_raw = self.local_storage.get_raw_profile(dirty_name)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        meta = extract_logging_metadata(local_parsed, size_bytes=len(local_raw.encode("utf-8")))
                        meta["name"] = dirty_name
                        meta["uncommitted_changes"] = True
                        meta["status"] = "new_uncommitted"
                        meta["github_path"] = self._file_path_for(dirty_name)
                        profiles.append(meta)
                    except Exception:
                        pass

        profiles.sort(key=lambda x: x["name"].lower())
        return profiles

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve parsed logging profile JSON from draft (Redis) or GitHub."""
        raw_val = self.get_raw_profile(name)
        if raw_val is None:
            return None
        try:
            return json.loads(raw_val)
        except Exception as exc:
            logger.error("Failed to parse logging profile JSON for '%s': %s", name, exc)
            return None

    def get_raw_profile(self, name: str) -> Optional[str]:
        """
        Retrieve raw logging profile JSON string.
        If an uncommitted draft exists in local Redis, returns that draft.
        Otherwise fetches from GitHub and caches in local Redis.
        """
        if self._is_dirty(name) and self.local_storage is not None:
            local_raw = self.local_storage.get_raw_profile(name)
            if local_raw:
                return local_raw

        file_path = self._file_path_for(name)
        raw_content, blob_sha = self.client.get_file(file_path)
        if raw_content is not None:
            if blob_sha:
                self._sha_content_cache[blob_sha] = raw_content
                self._name_to_sha[name] = blob_sha
            if self.local_storage is not None and not self.local_storage.profile_exists(name):
                try:
                    parsed = json.loads(raw_content)
                    self.local_storage.save_profile(name, parsed)
                except Exception:
                    pass
            return raw_content

        if self.local_storage is not None:
            return self.local_storage.get_raw_profile(name)

        return None

    def save_profile(self, name: str, content: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Save logging profile.
        When local_storage (Redis) is present:
            Writes intermediate edits strictly to local Redis as an uncommitted draft.
            Marks profile as dirty/uncommitted. Does NOT commit to GitHub.
        When local_storage is None:
            Commits directly to GitHub.
        """
        is_valid, errors, _, parsed = validate_logging_profile_json(content)
        if not is_valid or parsed is None:
            raise ValueError(f"Invalid logging profile JSON: {'; '.join(errors)}")

        # 1. If local_storage (Redis) is configured: save to local Redis
        if self.local_storage is not None:
            meta = self.local_storage.save_profile(name, parsed)
            self._mark_dirty(name)
            meta["name"] = name
            meta["saved_to"] = "redis"
            meta["uncommitted_changes"] = True
            meta["status"] = "modified"
            meta["github_path"] = self._file_path_for(name)
            meta["message"] = f"Logging profile '{name}' saved to local Redis (uncommitted draft)"
            return meta

        # 2. Standalone fallback (direct GitHub commit)
        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        file_path = self._file_path_for(name)

        existing_sha = self._name_to_sha.get(name)
        is_update = existing_sha is not None or self.profile_exists(name)
        action_verb = "update" if is_update else "create"
        commit_msg = f"feat(waf): {action_verb} logging profile '{name}'"

        commit_result = self.client.put_file(
            file_path=file_path,
            content_str=formatted,
            message=commit_msg,
            sha=existing_sha,
        )

        new_sha = commit_result.get("content", {}).get("sha", "")
        if new_sha:
            self._name_to_sha[name] = new_sha
            self._sha_content_cache[new_sha] = formatted

        meta = extract_logging_metadata(parsed, size_bytes=len(formatted.encode("utf-8")))
        meta["name"] = name
        meta["github_path"] = file_path
        meta["github_sha"] = new_sha
        if "commit" in commit_result:
            meta["commit_sha"] = commit_result["commit"].get("sha")
            meta["commit_html_url"] = commit_result["commit"].get("html_url")

        if new_sha:
            self._sha_meta_cache[new_sha] = meta

        return meta

    def push_to_github(self, name: str, message: Optional[str] = None) -> Dict[str, Any]:
        """
        Commit and push a logging profile draft from local Redis to the GitHub repository.
        Clears the local dirty/uncommitted flag on success.
        """
        raw_val = None
        if self.local_storage is not None:
            raw_val = self.local_storage.get_raw_profile(name)
        if not raw_val:
            raw_val = self.get_raw_profile(name)
        if not raw_val:
            raise FileNotFoundError(f"Logging profile '{name}' not found to commit to GitHub")

        try:
            parsed = json.loads(raw_val)
            formatted_json = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            formatted_json = raw_val

        file_path = self._file_path_for(name)
        existing_sha = self._name_to_sha.get(name)
        remote_content = None
        if not existing_sha:
            remote_content, remote_sha = self.client.get_file(file_path)
            if remote_sha:
                existing_sha = remote_sha
        elif existing_sha in self._sha_content_cache:
            remote_content = self._sha_content_cache[existing_sha]
        elif not remote_content:
            try:
                remote_content, _ = self.client.get_file(file_path)
            except Exception:
                remote_content = None

        if not message or message.strip() in ("", f"feat(waf): update logging profile '{name}'", f"feat(logging): update logging profile '{name}'", f"feat(logging): commit logging profile '{name}'"):
            from .diff_summary import summarize_log_profile_changes
            commit_msg = summarize_log_profile_changes(remote_content, formatted_json, name)
        else:
            commit_msg = message.strip()

        commit_res = self.client.put_file(
            file_path=file_path,
            content_str=formatted_json,
            message=commit_msg,
            sha=existing_sha,
        )

        new_sha = commit_res.get("content", {}).get("sha", "")
        if new_sha:
            self._name_to_sha[name] = new_sha
            self._sha_content_cache[new_sha] = formatted_json

        self._unmark_dirty(name)

        commit_data = commit_res.get("commit", {})
        commit_sha = commit_data.get("sha", "")
        short_sha = commit_sha[:7] if commit_sha else ""

        try:
            parsed_doc = json.loads(formatted_json)
            meta = extract_logging_metadata(parsed_doc, size_bytes=len(formatted_json.encode("utf-8")))
            meta["name"] = name
            meta["github_path"] = file_path
            meta["github_sha"] = new_sha
            meta["commit_sha"] = commit_sha
            meta["uncommitted_changes"] = False
            meta["status"] = "synced"
            if new_sha:
                self._sha_meta_cache[new_sha] = meta
            if self.local_storage is not None:
                self.local_storage.save_profile(name, parsed_doc)
        except Exception:
            pass

        return {
            "success": True,
            "name": name,
            "path": file_path,
            "commit_sha": commit_sha,
            "short_sha": short_sha,
            "commit_html_url": commit_data.get("html_url", ""),
            "message": commit_msg,
            "branch": self.client.branch,
            "repo": f"{self.client.owner}/{self.client.repo}",
        }

    def revert_from_github(self, name: str) -> Dict[str, Any]:
        """
        Discard local intermediate Redis changes and reset logging profile to the version in GitHub.
        """
        file_path = self._file_path_for(name)
        raw_content, blob_sha = self.client.get_file(file_path)
        if not raw_content:
            raise FileNotFoundError(f"Logging profile '{name}' not found on GitHub to revert to")

        parsed = json.loads(raw_content)
        if self.local_storage is not None:
            self.local_storage.save_profile(name, parsed)

        self._unmark_dirty(name)
        if blob_sha:
            self._name_to_sha[name] = blob_sha
            self._sha_content_cache[blob_sha] = raw_content

        return {
            "success": True,
            "status": "reverted",
            "message": f"Logging profile '{name}' successfully reverted to GitHub version",
            "name": name,
            "profile": parsed,
        }

    def delete_profile(self, name: str) -> bool:
        """Delete logging profile from local Redis and GitHub repository."""
        self._unmark_dirty(name)
        if self.local_storage is not None:
            try:
                self.local_storage.delete_profile(name)
            except Exception:
                pass

        file_path = self._file_path_for(name)
        existing_sha = self._name_to_sha.get(name)
        if not existing_sha:
            _, existing_sha = self.client.get_file(file_path)

        deleted = False
        if existing_sha:
            commit_msg = f"chore(waf): delete logging profile '{name}'"
            deleted = self.client.delete_file(
                file_path=file_path,
                message=commit_msg,
                sha=existing_sha,
            )
            old_sha = self._name_to_sha.pop(name, None)
            if old_sha:
                self._sha_content_cache.pop(old_sha, None)
                self._sha_meta_cache.pop(old_sha, None)
        else:
            deleted = True

        return deleted

    def clone_profile(self, source_name: str, new_name: str) -> Dict[str, Any]:
        """Clone an existing logging profile into a new profile in local Redis."""
        source = self.get_profile(source_name)
        if not source:
            raise ValueError(f"Source logging profile '{source_name}' not found")
        return self.save_profile(new_name, source)

    def profile_exists(self, name: str) -> bool:
        """Check if logging profile exists on GitHub or as a local uncommitted draft in Redis."""
        if self._is_dirty(name):
            return True
        if name in self._name_to_sha:
            return True
        file_path = self._file_path_for(name)
        _, sha = self.client.get_file(file_path)
        if sha:
            self._name_to_sha[name] = sha
            return True
        if self.local_storage is not None and self.local_storage.profile_exists(name):
            return True
        return False
