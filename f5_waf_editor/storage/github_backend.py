"""
GitHub GitOps storage backend for F5 WAF policies.
Uses GitHub repository as code (Source of Truth) while utilizing local Redis
(or resilient Memory storage) as an intermediate staging cache for uncommitted working drafts.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base import PolicyStorage
from .github_client import GitHubClient
from ..schemas.validator import validate_policy_json
from ..schemas.waf_schema import extract_policy_metadata, sanitize_waf_policy

logger = logging.getLogger("f5_waf_editor.storage.github")


class GitHubPolicyStorage(PolicyStorage):
    """
    F5 WAF policy storage engine backed by GitHub REST API (GitOps Source of Truth)
    with local Redis (or Memory) intermediate staging cache for drafts.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        local_storage: Optional[PolicyStorage] = None,
        policies_path: str = "policies",
    ):
        self.client = github_client
        self.local_storage = local_storage
        self.policies_path = policies_path.strip("/")
        # Local metadata and content cache keyed by blob SHA to minimize GitHub API rate limit usage
        self._sha_content_cache: Dict[str, str] = {}
        self._sha_meta_cache: Dict[str, Dict[str, Any]] = {}
        self._name_to_sha: Dict[str, str] = {}
        self._dirty_policies: set[str] = set()

    def _dirty_set_key(self) -> str:
        prefix = getattr(self.local_storage, "key_prefix", "") if self.local_storage else ""
        return f"{prefix}__github_dirty_policies__"

    def _is_dirty(self, name: str) -> bool:
        if name in self._dirty_policies:
            return True
        if self.local_storage is not None and hasattr(self.local_storage, "client"):
            try:
                redis_c = getattr(self.local_storage, "client")
                if hasattr(redis_c, "sismember"):
                    return bool(redis_c.sismember(self._dirty_set_key(), name))
            except Exception:
                pass
        return False

    def _mark_dirty(self, name: str) -> None:
        self._dirty_policies.add(name)
        if self.local_storage is not None and hasattr(self.local_storage, "client"):
            try:
                redis_c = getattr(self.local_storage, "client")
                if hasattr(redis_c, "sadd"):
                    redis_c.sadd(self._dirty_set_key(), name)
            except Exception:
                pass

    def _unmark_dirty(self, name: str) -> None:
        self._dirty_policies.discard(name)
        if self.local_storage is not None and hasattr(self.local_storage, "client"):
            try:
                redis_c = getattr(self.local_storage, "client")
                if hasattr(redis_c, "srem"):
                    redis_c.srem(self._dirty_set_key(), name)
            except Exception:
                pass

    def _get_all_dirty(self) -> set[str]:
        dirty = set(self._dirty_policies)
        if self.local_storage is not None and hasattr(self.local_storage, "client"):
            try:
                redis_c = getattr(self.local_storage, "client")
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
        return f"{self.policies_path}/{clean_name}" if self.policies_path else clean_name

    def list_policies(self) -> List[Dict[str, Any]]:
        """
        List all policies as they exist on the GitHub repository.
        If a policy has intermediate uncommitted edits in local Redis,
        its status reflects that it has local draft changes.
        Any newly created uncommitted policies in Redis are also included.
        """
        files = self.client.list_files(self.policies_path)
        policies: List[Dict[str, Any]] = []
        active_names = set()

        for f in files:
            file_name = f.get("name", "")
            if not file_name.endswith(".json") or file_name.startswith("."):
                continue

            policy_name = file_name[:-5]  # strip .json
            active_names.add(policy_name)
            sha = f.get("sha")
            file_path = f.get("path", self._file_path_for(policy_name))

            meta = None
            if sha and sha in self._sha_meta_cache:
                meta = dict(self._sha_meta_cache[sha])
            else:
                try:
                    raw_content, blob_sha = self.client.get_file(file_path)
                    if raw_content:
                        parsed = json.loads(raw_content)
                        if isinstance(parsed, dict) and "policy" in parsed:
                            current_sha = blob_sha or sha or ""
                            meta = extract_policy_metadata(parsed, len(raw_content.encode("utf-8")))
                            meta["github_path"] = file_path
                            meta["github_sha"] = current_sha
                            if current_sha:
                                self._sha_content_cache[current_sha] = raw_content
                                self._sha_meta_cache[current_sha] = dict(meta)
                                self._name_to_sha[policy_name] = current_sha
                except Exception as exc:
                    logger.warning("Failed to parse policy file '%s' from GitHub: %s", file_name, exc)
                    continue

            if meta is None:
                meta = {
                    "name": policy_name,
                    "enforcementMode": "unknown",
                    "description": "",
                    "sizeBytes": 0,
                    "github_path": file_path,
                }

            meta["name"] = policy_name
            meta["key"] = policy_name

            # Check if this policy has uncommitted local draft changes in Redis
            if self._is_dirty(policy_name) and self.local_storage is not None:
                meta["uncommitted_changes"] = True
                meta["status"] = "modified"
                local_raw = self.local_storage.get_raw_policy(policy_name)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        local_meta = extract_policy_metadata(local_parsed, len(local_raw.encode("utf-8")))
                        meta.update(local_meta)
                        meta["name"] = policy_name
                        meta["key"] = policy_name
                        meta["uncommitted_changes"] = True
                        meta["status"] = "modified"
                    except Exception:
                        pass
            else:
                meta["uncommitted_changes"] = False
                meta["status"] = "synced"

            policies.append(meta)

        # Clean up stale cache keys
        stale = [name for name in self._name_to_sha if name not in active_names]
        for name in stale:
            self._name_to_sha.pop(name, None)

        # Include any newly created local policies in Redis that do not exist on GitHub yet
        all_dirty = self._get_all_dirty()
        for dirty_name in all_dirty:
            if dirty_name not in active_names and self.local_storage is not None:
                local_raw = self.local_storage.get_raw_policy(dirty_name)
                if local_raw:
                    try:
                        local_parsed = json.loads(local_raw)
                        meta = extract_policy_metadata(local_parsed, len(local_raw.encode("utf-8")))
                        meta["name"] = dirty_name
                        meta["key"] = dirty_name
                        meta["uncommitted_changes"] = True
                        meta["status"] = "new_uncommitted"
                        meta["github_path"] = self._file_path_for(dirty_name)
                        policies.append(meta)
                    except Exception:
                        pass

        policies.sort(key=lambda x: x["name"].lower())
        return policies

    def get_policy(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve parsed and sanitized policy JSON from working draft (Redis) or GitHub."""
        raw_val = self.get_raw_policy(name)
        if raw_val is None:
            return None
        try:
            parsed = json.loads(raw_val)
            if not isinstance(parsed, dict) or "policy" not in parsed:
                return None
            return sanitize_waf_policy(parsed)
        except Exception as exc:
            logger.error("Failed to parse policy JSON for '%s': %s", name, exc)
            return None

    def get_raw_policy(self, name: str) -> Optional[str]:
        """
        Retrieve raw policy JSON string.
        If an uncommitted draft exists in local Redis, returns that draft.
        Otherwise fetches from GitHub and caches in local Redis.
        """
        # If uncommitted draft in local storage, return that draft
        if self._is_dirty(name) and self.local_storage is not None:
            local_raw = self.local_storage.get_raw_policy(name)
            if local_raw:
                return local_raw

        # Fetch from GitHub
        file_path = self._file_path_for(name)
        raw_content, blob_sha = self.client.get_file(file_path)
        if raw_content is not None:
            if blob_sha:
                self._sha_content_cache[blob_sha] = raw_content
                self._name_to_sha[name] = blob_sha
            # Populate local storage as working baseline if local storage is available
            if self.local_storage is not None and not self.local_storage.policy_exists(name):
                try:
                    parsed = json.loads(raw_content)
                    self.local_storage.save_policy(name, parsed, pre_validated=True)
                except Exception:
                    pass
            return raw_content

        # Fallback to local storage if not on GitHub (e.g. newly created uncommitted)
        if self.local_storage is not None:
            return self.local_storage.get_raw_policy(name)

        return None

    def save_policy(
        self,
        name: str,
        policy_content: Any,
        pre_validated: bool = False,
    ) -> Dict[str, Any]:
        """
        Save policy.
        When local_storage (Redis) is present:
            Writes intermediate edits strictly to local Redis as an uncommitted draft.
            Marks policy as dirty/uncommitted. Does NOT commit to GitHub.
        When local_storage is None:
            Commits directly to GitHub.
        """
        if name.startswith("log:"):
            raise ValueError("Policy name cannot start with reserved prefix 'log:'")

        if pre_validated and isinstance(policy_content, dict):
            parsed = sanitize_waf_policy(policy_content)
        else:
            if isinstance(policy_content, dict):
                policy_content = sanitize_waf_policy(policy_content)

            is_valid, errors, _, parsed = validate_policy_json(policy_content)
            if not is_valid or parsed is None:
                raise ValueError(f"Policy validation failed: {'; '.join(errors)}")

        if "policy" in parsed and isinstance(parsed["policy"], dict):
            parsed["policy"]["name"] = name

        # 1. If local_storage (Redis) is configured: save to local Redis
        if self.local_storage is not None:
            meta = self.local_storage.save_policy(name, parsed, pre_validated=True)
            self._mark_dirty(name)
            meta["name"] = name
            meta["key"] = name
            meta["saved_to"] = "redis"
            meta["uncommitted_changes"] = True
            meta["status"] = "modified"
            meta["github_path"] = self._file_path_for(name)
            meta["message"] = f"Policy '{name}' saved to local Redis (uncommitted draft)"
            return meta

        # 2. Standalone fallback (direct GitHub commit)
        json_str = json.dumps(parsed, indent=2, ensure_ascii=False)
        file_path = self._file_path_for(name)

        existing_sha = self._name_to_sha.get(name)
        is_update = existing_sha is not None or self.policy_exists(name)
        action_verb = "update" if is_update else "create"
        commit_msg = f"feat(waf): {action_verb} policy '{name}'"

        commit_result = self.client.put_file(
            file_path=file_path,
            content_str=json_str,
            message=commit_msg,
            sha=existing_sha,
        )

        new_sha = commit_result.get("content", {}).get("sha", "")
        if new_sha:
            self._name_to_sha[name] = new_sha
            self._sha_content_cache[new_sha] = json_str

        meta = extract_policy_metadata(parsed, len(json_str.encode("utf-8")))
        meta["name"] = name
        meta["key"] = name
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
        Commit and push a policy draft from local Redis to the GitHub repository.
        Clears the local dirty/uncommitted flag on success.
        """
        raw_val = None
        if self.local_storage is not None:
            raw_val = self.local_storage.get_raw_policy(name)
        if not raw_val:
            raw_val = self.get_raw_policy(name)
        if not raw_val:
            raise FileNotFoundError(f"Policy '{name}' not found to commit to GitHub")

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

        if not message or message.strip() in ("", f"feat(waf): update policy '{name}'", f"feat(waf): commit policy '{name}'"):
            from .diff_summary import summarize_policy_changes
            commit_msg = summarize_policy_changes(remote_content, formatted_json, name)
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

        # Clear dirty flag now that changes are pushed to GitHub
        self._unmark_dirty(name)

        commit_data = commit_res.get("commit", {})
        commit_sha = commit_data.get("sha", "")
        short_sha = commit_sha[:7] if commit_sha else ""

        # Update metadata cache
        try:
            parsed_doc = json.loads(formatted_json)
            meta = extract_policy_metadata(parsed_doc, len(formatted_json.encode("utf-8")))
            meta["name"] = name
            meta["key"] = name
            meta["github_path"] = file_path
            meta["github_sha"] = new_sha
            meta["commit_sha"] = commit_sha
            meta["uncommitted_changes"] = False
            meta["status"] = "synced"
            if new_sha:
                self._sha_meta_cache[new_sha] = meta
            if self.local_storage is not None:
                self.local_storage.save_policy(name, parsed_doc, pre_validated=True)
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
        Discard local intermediate Redis changes and reset policy to the version in GitHub.
        """
        file_path = self._file_path_for(name)
        raw_content, blob_sha = self.client.get_file(file_path)
        if not raw_content:
            raise FileNotFoundError(f"Policy '{name}' not found on GitHub to revert to")

        parsed = json.loads(raw_content)
        if self.local_storage is not None:
            self.local_storage.save_policy(name, parsed, pre_validated=True)

        self._unmark_dirty(name)
        if blob_sha:
            self._name_to_sha[name] = blob_sha
            self._sha_content_cache[blob_sha] = raw_content

        return {
            "success": True,
            "status": "reverted",
            "message": f"Policy '{name}' successfully reverted to GitHub version",
            "name": name,
            "policy": parsed,
        }

    def delete_policy(self, name: str) -> bool:
        """Delete policy from local Redis and GitHub repository."""
        self._unmark_dirty(name)
        if self.local_storage is not None:
            try:
                self.local_storage.delete_policy(name)
            except Exception:
                pass

        file_path = self._file_path_for(name)
        existing_sha = self._name_to_sha.get(name)
        if not existing_sha:
            _, existing_sha = self.client.get_file(file_path)

        deleted = False
        if existing_sha:
            commit_msg = f"chore(waf): delete policy '{name}'"
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

    def policy_exists(self, name: str) -> bool:
        """Check if policy exists on GitHub or as a local uncommitted draft in Redis."""
        if self._is_dirty(name):
            return True
        if name in self._name_to_sha:
            return True
        file_path = self._file_path_for(name)
        _, sha = self.client.get_file(file_path)
        if sha:
            self._name_to_sha[name] = sha
            return True
        if self.local_storage is not None and self.local_storage.policy_exists(name):
            return True
        return False

    def clone_policy(self, source_name: str, new_name: str) -> Dict[str, Any]:
        """Clone an existing policy into a new policy in local Redis (uncommitted draft)."""
        source = self.get_policy(source_name)
        if not source:
            raise ValueError(f"Source policy '{source_name}' not found")

        source["policy"]["name"] = new_name
        return self.save_policy(new_name, source, pre_validated=False)

    def rename_policy(
        self,
        old_name: str,
        new_name: str,
        policy_content: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Rename policy: saves new name to local Redis and removes old name."""
        if policy_content is not None:
            content_to_save = policy_content
        else:
            existing = self.get_policy(old_name)
            if not existing:
                raise ValueError(f"Source policy '{old_name}' not found")
            content_to_save = existing

        if isinstance(content_to_save, dict) and "policy" in content_to_save:
            content_to_save["policy"]["name"] = new_name

        meta = self.save_policy(new_name, content_to_save, pre_validated=False)
        self.delete_policy(old_name)
        return meta

    def get_health(self) -> Dict[str, Any]:
        """Get GitHub connectivity health and repository metadata."""
        health = self.client.ping()
        health["backend"] = "github"
        health["backend_type"] = "github"
        health["policies_path"] = self.policies_path
        health["owner"] = self.client.owner
        health["repo"] = self.client.repo
        health["branch"] = self.client.branch
        health["total_policies"] = len(self._name_to_sha)
        health["uncommitted_policies"] = len(self._get_all_dirty())
        health["local_cache"] = "redis" if (self.local_storage and hasattr(self.local_storage, "client")) else "memory"
        return health
