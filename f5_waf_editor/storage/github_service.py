"""
GitHub GitOps synchronization and push service for F5 WAF Policy Manager.
Handles:
- Retrieving policies and log profiles from GitHub into Redis (e.g. on startup or on-demand pull).
- Pushing/committing edited policies and log profiles from Redis to GitHub on demand.
- GitHub connection health inspection.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
import httpx

from ..config import settings
from .base import PolicyStorage
from .logging_base import LoggingProfileStorage
from .custom_signatures_base import CustomSignaturesStorage
from .github_client import GitHubClient

logger = logging.getLogger("f5_waf_editor.storage.github_service")

# Global cached GitHubClient instance
_cached_client: Optional[GitHubClient] = None


def is_github_configured() -> bool:
    """Return True if GitHub owner, repo, and PAT token are configured."""
    return bool(settings.github_owner and settings.github_repo and settings.github_token)


def get_github_client(
    force_refresh: bool = False,
    transport: Optional[httpx.BaseTransport] = None,
    verify_ssl: Optional[bool] = None,
) -> Optional[GitHubClient]:
    """Return or initialize the GitHubClient with current settings."""
    global _cached_client

    if not is_github_configured():
        return None

    resolved_verify_ssl = settings.github_verify_ssl if verify_ssl is None else bool(verify_ssl)

    if _cached_client is None or force_refresh:
        _cached_client = GitHubClient(
            owner=settings.github_owner,
            repo=settings.github_repo,
            token=settings.github_token,
            branch=settings.github_branch or "main",
            api_url=settings.github_api_url or "https://api.github.com",
            verify_ssl=resolved_verify_ssl,
            transport=transport,
        )
    else:
        if transport is not None and _cached_client.transport is None:
            _cached_client.transport = transport
        if verify_ssl is not None:
            _cached_client.verify_ssl = bool(verify_ssl)

    return _cached_client


def set_github_client(client: Optional[GitHubClient]) -> None:
    """Explicitly set or reset the cached GitHubClient (used in tests or reconfig)."""
    global _cached_client
    _cached_client = client


def get_github_status() -> Dict[str, Any]:
    """Check and return status and connectivity to the configured GitHub repository."""
    if not is_github_configured():
        return {
            "configured": False,
            "connected": False,
            "owner": settings.github_owner or "",
            "repo": settings.github_repo or "",
            "branch": settings.github_branch or "main",
            "api_url": settings.github_api_url or "https://api.github.com",
            "verify_ssl": settings.github_verify_ssl,
            "disable_ssl_verify": not settings.github_verify_ssl,
            "policies_path": settings.github_policies_path or "policies",
            "log_profiles_path": settings.github_log_profiles_path or "log-profiles",
            "custom_sigs_path": settings.github_custom_sigs_path or "custom-signatures",
            "message": "GitHub is not configured. Set GITHUB_OWNER, GITHUB_REPO, and GITHUB_TOKEN.",
        }

    client = get_github_client()
    if not client:
        return {
            "configured": True,
            "connected": False,
            "owner": settings.github_owner,
            "repo": settings.github_repo,
            "verify_ssl": settings.github_verify_ssl,
            "disable_ssl_verify": not settings.github_verify_ssl,
            "error": "Failed to initialize GitHub client",
        }

    try:
        ping_res = client.ping()
        v_ssl = getattr(client, "verify_ssl", settings.github_verify_ssl)
        return {
            "configured": True,
            "connected": True,
            "owner": client.owner,
            "repo": client.repo,
            "branch": client.branch,
            "full_name": ping_res.get("full_name"),
            "latency_ms": ping_res.get("latency_ms"),
            "verify_ssl": v_ssl,
            "disable_ssl_verify": not v_ssl,
            "policies_path": settings.github_policies_path or "policies",
            "log_profiles_path": settings.github_log_profiles_path or "log-profiles",
            "custom_sigs_path": settings.github_custom_sigs_path or "custom-signatures",
        }
    except Exception as exc:
        return {
            "configured": True,
            "connected": False,
            "owner": settings.github_owner,
            "repo": settings.github_repo,
            "branch": settings.github_branch or "main",
            "verify_ssl": settings.github_verify_ssl,
            "disable_ssl_verify": not settings.github_verify_ssl,
            "error": str(exc),
        }


def get_pull_conflicts(
    policy_storage: Optional[PolicyStorage] = None,
    log_storage: Optional[LoggingProfileStorage] = None,
) -> Dict[str, Any]:
    """
    Check for conflicts between GitHub repository files and local Redis draft copies.
    A conflict occurs when an item exists on GitHub AND also exists in local Redis
    in 'draft' status (i.e. has uncommitted local modifications / dirty flag).
    """
    if not is_github_configured():
        return {"has_conflicts": False, "conflicts": []}

    client = get_github_client()
    if not client:
        return {"has_conflicts": False, "conflicts": []}

    from . import get_storage, get_logging_storage
    pol_store = policy_storage or get_storage()
    logging_store = log_storage or get_logging_storage()

    policies_path = settings.github_policies_path or "policies"
    log_profiles_path = settings.github_log_profiles_path or "log-profiles"

    conflicts: List[Dict[str, Any]] = []

    # 1. Check policies
    try:
        policy_files = client.list_files(policies_path)
        for item in policy_files:
            file_name = item.get("name", "")
            if not file_name.endswith(".json") or file_name.startswith("."):
                continue
            pol_name = file_name[:-5]
            path = item.get("path") or f"{policies_path}/{file_name}"

            is_draft = False
            for s_inst in (pol_store, getattr(pol_store, "local_storage", None)):
                if s_inst is not None:
                    if hasattr(s_inst, "_is_dirty") and s_inst._is_dirty(pol_name):
                        is_draft = True
                        break
                    if hasattr(s_inst, "_get_all_dirty") and pol_name in s_inst._get_all_dirty():
                        is_draft = True
                        break

            if is_draft:
                conflicts.append({
                    "type": "policy",
                    "name": pol_name,
                    "status": "draft",
                    "github_path": path,
                })
    except Exception as exc:
        logger.warning("Error checking GitHub policy conflicts: %s", exc)

    # 2. Check logging profiles
    try:
        log_files = client.list_files(log_profiles_path)
        for item in log_files:
            file_name = item.get("name", "")
            if not file_name.endswith(".json") or file_name.startswith("."):
                continue
            prof_name = file_name[:-5]
            path = item.get("path") or f"{log_profiles_path}/{file_name}"

            is_draft = False
            for l_inst in (logging_store, getattr(logging_store, "local_storage", None)):
                if l_inst is not None:
                    if hasattr(l_inst, "_is_dirty") and l_inst._is_dirty(prof_name):
                        is_draft = True
                        break
                    if hasattr(l_inst, "_get_all_dirty") and prof_name in l_inst._get_all_dirty():
                        is_draft = True
                        break

            if is_draft:
                conflicts.append({
                    "type": "logging",
                    "name": prof_name,
                    "status": "draft",
                    "github_path": path,
                })
    except Exception as exc:
        logger.warning("Error checking GitHub logging profile conflicts: %s", exc)

    return {
        "has_conflicts": len(conflicts) > 0,
        "conflicts": conflicts,
    }


def pull_from_github(
    policy_storage: Optional[PolicyStorage] = None,
    log_storage: Optional[LoggingProfileStorage] = None,
    custom_sig_storage: Optional[CustomSignaturesStorage] = None,
    resolutions: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Retrieve all WAF policies and logging profiles from GitHub and populate them into Redis.
    Called upon startup if GitHub is configured, or on-demand via API.
    If conflict resolutions are provided, local drafts can be preserved according to user choice.
    """
    from . import get_storage, get_logging_storage, get_custom_signatures_storage

    client = get_github_client()
    if not client:
        raise ValueError("GitHub is not configured; cannot pull policies from GitHub")

    pol_store = policy_storage or get_storage()
    logging_store = log_storage or get_logging_storage()
    custom_store = custom_sig_storage or get_custom_signatures_storage()

    policies_path = settings.github_policies_path or "policies"
    log_profiles_path = settings.github_log_profiles_path or "log-profiles"
    custom_sigs_path = settings.github_custom_sigs_path or "custom-signatures"

    pulled_policies: List[str] = []
    pulled_log_profiles: List[str] = []
    pulled_custom_sigs: List[str] = []
    preserved_policies: List[str] = []
    preserved_log_profiles: List[str] = []

    # 1. Pull WAF Policies from GitHub -> Redis
    try:
        policy_files = client.list_files(policies_path)
        for item in policy_files:
            file_name = item.get("name", "")
            if not file_name.endswith(".json"):
                continue
            path = item.get("path") or f"{policies_path}/{file_name}"
            content_str, sha = client.get_file(path)
            if not content_str:
                continue

            try:
                data = json.loads(content_str)
                # Determine policy name from JSON or filename
                pol_name = None
                if isinstance(data, dict) and "policy" in data and isinstance(data["policy"], dict):
                    pol_name = data["policy"].get("name")
                if not pol_name:
                    pol_name = file_name[:-5]
                    if isinstance(data, dict):
                        if "policy" not in data or not isinstance(data["policy"], dict):
                            data["policy"] = {}
                        data["policy"]["name"] = pol_name

                # Check if this policy is currently in draft status in Redis
                is_draft = False
                for s_inst in (pol_store, getattr(pol_store, "local_storage", None)):
                    if s_inst is not None:
                        if hasattr(s_inst, "_is_dirty") and s_inst._is_dirty(pol_name):
                            is_draft = True
                            break
                        if hasattr(s_inst, "_get_all_dirty") and pol_name in s_inst._get_all_dirty():
                            is_draft = True
                            break

                pol_res = None
                if resolutions:
                    pol_res = (
                        resolutions.get("policies", {}).get(pol_name)
                        or resolutions.get(f"policy:{pol_name}")
                        or resolutions.get(pol_name)
                    )

                if is_draft and pol_res == "keep_local":
                    logger.info("Preserving local Redis draft for policy '%s' per conflict resolution", pol_name)
                    preserved_policies.append(pol_name)
                    continue

                # Save into Redis (overwrites whatever copy exists in Redis)
                target_local = getattr(pol_store, "local_storage", None) or pol_store
                target_local.save_policy(pol_name, data, pre_validated=True)

                # Clear dirty status on GitHub storage backends and update SHA cache
                from . import _current_storage, _current_logging_storage, _current_custom_signatures_storage
                for s_inst in (pol_store, _current_storage):
                    if s_inst is not None:
                        if hasattr(s_inst, "_unmark_dirty"):
                            s_inst._unmark_dirty(pol_name)
                        if sha:
                            if hasattr(s_inst, "_name_to_sha"):
                                s_inst._name_to_sha[pol_name] = sha
                            if hasattr(s_inst, "_sha_content_cache"):
                                s_inst._sha_content_cache[sha] = content_str

                pulled_policies.append(pol_name)
                logger.info("Pulled policy '%s' from GitHub into Redis (%s)", pol_name, path)
            except Exception as e:
                logger.warning("Failed to parse and save GitHub policy '%s': %s", path, e)
    except Exception as exc:
        logger.warning("Error listing GitHub policies directory '%s': %s", policies_path, exc)

    # 2. Pull Logging Profiles from GitHub -> Redis
    try:
        log_files = client.list_files(log_profiles_path)
        for item in log_files:
            file_name = item.get("name", "")
            if not file_name.endswith(".json"):
                continue
            path = item.get("path") or f"{log_profiles_path}/{file_name}"
            content_str, sha = client.get_file(path)
            if not content_str:
                continue

            try:
                data = json.loads(content_str)
                prof_name = None
                if isinstance(data, dict) and "filter" in data and isinstance(data["filter"], dict):
                    prof_name = data["filter"].get("name")
                if not prof_name:
                    prof_name = file_name[:-5]
                    if isinstance(data, dict):
                        if "filter" not in data or not isinstance(data["filter"], dict):
                            data["filter"] = {}
                        data["filter"]["name"] = prof_name

                # Check if this logging profile is currently in draft status in Redis
                is_draft = False
                for l_inst in (logging_store, getattr(logging_store, "local_storage", None)):
                    if l_inst is not None:
                        if hasattr(l_inst, "_is_dirty") and l_inst._is_dirty(prof_name):
                            is_draft = True
                            break
                        if hasattr(l_inst, "_get_all_dirty") and prof_name in l_inst._get_all_dirty():
                            is_draft = True
                            break

                prof_res = None
                if resolutions:
                    prof_res = (
                        resolutions.get("log_profiles", {}).get(prof_name)
                        or resolutions.get(f"logging:{prof_name}")
                        or resolutions.get(prof_name)
                    )

                if is_draft and prof_res == "keep_local":
                    logger.info("Preserving local Redis draft for logging profile '%s' per conflict resolution", prof_name)
                    preserved_log_profiles.append(prof_name)
                    continue

                # Save into Redis (overwrites whatever copy exists in Redis)
                target_local_log = getattr(logging_store, "local_storage", None) or logging_store
                target_local_log.save_profile(prof_name, data)

                # Clear dirty status on GitHub logging storage backends and update SHA cache
                for l_inst in (logging_store, _current_logging_storage):
                    if l_inst is not None:
                        if hasattr(l_inst, "_unmark_dirty"):
                            l_inst._unmark_dirty(prof_name)
                        if sha:
                            if hasattr(l_inst, "_name_to_sha"):
                                l_inst._name_to_sha[prof_name] = sha
                            if hasattr(l_inst, "_sha_content_cache"):
                                l_inst._sha_content_cache[sha] = content_str

                pulled_log_profiles.append(prof_name)
                logger.info("Pulled logging profile '%s' from GitHub into Redis (%s)", prof_name, path)
            except Exception as e:
                logger.warning("Failed to parse and save GitHub logging profile '%s': %s", path, e)
    except Exception as exc:
        logger.warning("Error listing GitHub log profiles directory '%s': %s", log_profiles_path, exc)

    # 3. Pull Custom Signatures from GitHub -> Redis (if any)
    try:
        sig_files = client.list_files(custom_sigs_path)
        for item in sig_files:
            file_name = item.get("name", "")
            if not file_name.endswith(".json"):
                continue
            path = item.get("path") or f"{custom_sigs_path}/{file_name}"
            content_str, sha = client.get_file(path)
            if not content_str:
                continue

            try:
                data = json.loads(content_str)
                tag = data.get("tag") or file_name[:-5]

                # Save into Redis (overwrites whatever copy exists in Redis)
                target_local_sig = getattr(custom_store, "local_storage", None) or custom_store
                target_local_sig.save_set(tag, data)

                # Clear dirty status on GitHub custom sigs backends and update SHA cache
                for c_inst in (custom_store, _current_custom_signatures_storage):
                    if c_inst is not None:
                        if hasattr(c_inst, "_unmark_dirty"):
                            c_inst._unmark_dirty(tag)
                        if sha:
                            if hasattr(c_inst, "_name_to_sha"):
                                c_inst._name_to_sha[tag] = sha
                            if hasattr(c_inst, "_sha_content_cache"):
                                c_inst._sha_content_cache[sha] = content_str

                pulled_custom_sigs.append(tag)
                logger.info("Pulled custom signature set '%s' from GitHub into Redis (%s)", tag, path)
            except Exception as e:
                logger.warning("Failed to parse and save GitHub custom signature set '%s': %s", path, e)
    except Exception as exc:
        logger.debug("Listing custom signatures from GitHub: %s", exc)

    return {
        "success": True,
        "message": f"Successfully retrieved {len(pulled_policies)} policies and {len(pulled_log_profiles)} log profiles from GitHub into Redis",
        "policies_pulled": pulled_policies,
        "policies_preserved": preserved_policies,
        "log_profiles_pulled": pulled_log_profiles,
        "log_profiles_preserved": preserved_log_profiles,
        "custom_signatures_pulled": pulled_custom_sigs,
        "count_policies": len(pulled_policies),
        "count_log_profiles": len(pulled_log_profiles),
    }


def push_policy_to_github(
    name: str,
    message: Optional[str] = None,
    policy_storage: Optional[PolicyStorage] = None,
) -> Dict[str, Any]:
    """
    Take a policy from Redis storage and commit/push it to the configured GitHub repository.
    """
    from . import get_storage

    client = get_github_client()
    if not client:
        raise ValueError("GitHub is not configured. Define GITHUB_OWNER, GITHUB_REPO, and GITHUB_TOKEN.")

    store = policy_storage or get_storage()
    if hasattr(store, "push_to_github"):
        return store.push_to_github(name, message)

    raw = store.get_raw_policy(name)
    if not raw:
        raise FileNotFoundError(f"Policy '{name}' not found in Redis storage")

    # Ensure nicely formatted JSON
    try:
        parsed = json.loads(raw)
        formatted_content = json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception:
        formatted_content = raw

    policies_path = settings.github_policies_path or "policies"
    file_path = f"{policies_path}/{name}.json"
    if not message or message.strip() in ("", f"feat(waf): commit policy '{name}'", f"feat(waf): update policy '{name}'"):
        from .diff_summary import summarize_policy_changes
        remote_content = None
        try:
            remote_content, _ = client.get_file(file_path)
        except Exception:
            remote_content = None
        commit_msg = summarize_policy_changes(remote_content, formatted_content, name)
    else:
        commit_msg = message.strip()

    commit_res = client.put_file(
        file_path=file_path,
        content_str=formatted_content,
        message=commit_msg,
    )

    commit_data = commit_res.get("commit", {})
    commit_sha = commit_data.get("sha", "")
    short_sha = commit_sha[:7] if commit_sha else ""

    # Clear dirty flag in Redis / local metadata cache if present
    try:
        r_client = getattr(store, "client", None)
        r_prefix = getattr(store, "key_prefix", "")
        if r_client is not None:
            r_client.srem(f"{r_prefix}__github_dirty_policies__", name)
            meta_key = f"{r_prefix}__meta__:{name}"
            raw_meta = r_client.get(meta_key)
            if raw_meta:
                meta_obj = json.loads(raw_meta)
                if isinstance(meta_obj, dict):
                    meta_obj["uncommitted_changes"] = False
                    meta_obj["status"] = "synced"
                    r_client.set(meta_key, json.dumps(meta_obj, ensure_ascii=False))
        if hasattr(store, "_meta_cache") and isinstance(getattr(store, "_meta_cache", None), dict):
            meta_entry = store._meta_cache.get(name)
            if isinstance(meta_entry, dict):
                meta_entry["uncommitted_changes"] = False
                meta_entry["status"] = "synced"
    except Exception:
        pass

    logger.info("Committed policy '%s' to GitHub %s (commit: %s)", name, file_path, short_sha)

    return {
        "success": True,
        "name": name,
        "path": file_path,
        "commit_sha": commit_sha,
        "short_sha": short_sha,
        "commit_html_url": commit_data.get("html_url", ""),
        "message": commit_msg,
        "branch": client.branch,
        "repo": f"{client.owner}/{client.repo}",
    }


def push_log_profile_to_github(
    name: str,
    message: Optional[str] = None,
    log_storage: Optional[LoggingProfileStorage] = None,
) -> Dict[str, Any]:
    """
    Take a logging profile from Redis storage and commit/push it to the configured GitHub repository.
    """
    from . import get_logging_storage

    client = get_github_client()
    if not client:
        raise ValueError("GitHub is not configured. Define GITHUB_OWNER, GITHUB_REPO, and GITHUB_TOKEN.")

    store = log_storage or get_logging_storage()
    if hasattr(store, "push_to_github"):
        return store.push_to_github(name, message)

    prof = store.get_profile(name)
    if not prof:
        raise FileNotFoundError(f"Logging profile '{name}' not found in Redis storage")

    formatted_content = json.dumps(prof, indent=2, ensure_ascii=False)
    log_profiles_path = settings.github_log_profiles_path or "log-profiles"
    file_path = f"{log_profiles_path}/{name}.json"
    if not message or message.strip() in ("", f"feat(waf): commit logging profile '{name}'", f"feat(logging): update logging profile '{name}'", f"feat(logging): commit logging profile '{name}'"):
        from .diff_summary import summarize_log_profile_changes
        remote_content = None
        try:
            remote_content, _ = client.get_file(file_path)
        except Exception:
            remote_content = None
        commit_msg = summarize_log_profile_changes(remote_content, formatted_content, name)
    else:
        commit_msg = message.strip()

    commit_res = client.put_file(
        file_path=file_path,
        content_str=formatted_content,
        message=commit_msg,
    )

    commit_data = commit_res.get("commit", {})
    commit_sha = commit_data.get("sha", "")
    short_sha = commit_sha[:7] if commit_sha else ""

    logger.info("Committed logging profile '%s' to GitHub %s (commit: %s)", name, file_path, short_sha)

    return {
        "success": True,
        "name": name,
        "path": file_path,
        "commit_sha": commit_sha,
        "short_sha": short_sha,
        "commit_html_url": commit_data.get("html_url", ""),
        "message": commit_msg,
        "branch": client.branch,
        "repo": f"{client.owner}/{client.repo}",
    }


def push_custom_signatures_to_github(
    tag: str,
    message: Optional[str] = None,
    custom_sig_storage: Optional[CustomSignaturesStorage] = None,
) -> Dict[str, Any]:
    """
    Take a custom signature set from Redis storage and commit/push it to GitHub.
    """
    from . import get_custom_signatures_storage

    client = get_github_client()
    if not client:
        raise ValueError("GitHub is not configured.")

    store = custom_sig_storage or get_custom_signatures_storage()
    if hasattr(store, "push_to_github"):
        return store.push_to_github(tag, message)

    sig_set = store.get_set(tag)
    if not sig_set:
        raise FileNotFoundError(f"Custom signature set '{tag}' not found in Redis storage")

    formatted_content = json.dumps(sig_set, indent=2, ensure_ascii=False)
    custom_sigs_path = settings.github_custom_sigs_path or "custom-signatures"
    file_path = f"{custom_sigs_path}/{tag}.json"
    commit_msg = (message or "").strip() or f"feat(waf): commit custom signatures '{tag}'"

    commit_res = client.put_file(
        file_path=file_path,
        content_str=formatted_content,
        message=commit_msg,
    )

    commit_data = commit_res.get("commit", {})
    commit_sha = commit_data.get("sha", "")
    short_sha = commit_sha[:7] if commit_sha else ""

    return {
        "success": True,
        "name": tag,
        "path": file_path,
        "commit_sha": commit_sha,
        "short_sha": short_sha,
        "commit_html_url": commit_data.get("html_url", ""),
        "message": commit_msg,
        "branch": client.branch,
        "repo": f"{client.owner}/{client.repo}",
    }
