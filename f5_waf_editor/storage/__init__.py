"""
Storage manager and factory for F5 WAF Policy and Logging Profile Storage.
Supports Redis, GitHub (GitOps), and Resilient In-Memory storage backends.
"""

import logging
from typing import Any, Dict, Optional
from .base import PolicyStorage
from .redis_backend import RedisPolicyStorage
from .memory_backend import MemoryPolicyStorage
from .logging_base import LoggingProfileStorage
from .redis_logging_backend import RedisLoggingStorage
from .memory_logging_backend import MemoryLoggingStorage
from .custom_signatures_base import CustomSignaturesStorage
from .redis_custom_signatures_backend import RedisCustomSignaturesStorage
from .memory_custom_signatures_backend import MemoryCustomSignaturesStorage
from .github_client import GitHubClient
from .github_backend import GitHubPolicyStorage
from .github_logging_backend import GitHubLoggingStorage
from .github_custom_signatures_backend import GitHubCustomSignaturesStorage
from ..config import settings

logger = logging.getLogger("f5_waf_editor.storage")

_current_storage: Optional[PolicyStorage] = None
_current_logging_storage: Optional[LoggingProfileStorage] = None
_current_custom_signatures_storage: Optional[CustomSignaturesStorage] = None

_local_storage: Optional[PolicyStorage] = None
_local_logging_storage: Optional[LoggingProfileStorage] = None
_local_custom_signatures_storage: Optional[CustomSignaturesStorage] = None


from .github_service import (
    is_github_configured,
    get_github_client,
    set_github_client,
    get_github_status,
    pull_from_github,
    get_pull_conflicts,
    push_policy_to_github,
    push_log_profile_to_github,
    push_custom_signatures_to_github,
)
from .diff_summary import (
    summarize_policy_changes,
    summarize_log_profile_changes,
    summarize_custom_signatures_changes,
)


def init_github_storage(
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    token: Optional[str] = None,
    branch: Optional[str] = None,
    api_url: Optional[str] = None,
    verify_ssl: Optional[bool] = None,
    disable_ssl_verify: Optional[bool] = None,
    policies_path: Optional[str] = None,
    log_profiles_path: Optional[str] = None,
    custom_sigs_path: Optional[str] = None,
    transport: Optional[Any] = None,
    auto_pull: bool = True,
) -> PolicyStorage:
    """Initialize and verify GitHub GitOps integration with intermediate Redis staging."""
    global _current_storage, _current_logging_storage, _current_custom_signatures_storage
    global _local_storage, _local_logging_storage, _local_custom_signatures_storage

    o = owner or settings.github_owner
    r = repo or settings.github_repo
    t = token or settings.github_token
    b = branch or settings.github_branch or "main"
    api = api_url or settings.github_api_url or "https://api.github.com"
    pol_path = policies_path or settings.github_policies_path or "policies"
    log_path = log_profiles_path or settings.github_log_profiles_path or "log-profiles"
    sig_path = custom_sigs_path or settings.github_custom_sigs_path or "custom-signatures"

    if disable_ssl_verify is not None:
        v_ssl = not disable_ssl_verify
    elif verify_ssl is not None:
        v_ssl = bool(verify_ssl)
    else:
        v_ssl = settings.github_verify_ssl

    if not o or not r or not t:
        raise ValueError("GitHub storage requires owner/organization, repository name, and personal access token (PAT)")

    client = GitHubClient(
        owner=o,
        repo=r,
        token=t,
        branch=b,
        api_url=api,
        verify_ssl=v_ssl,
        transport=transport,
    )
    health = client.ping()
    logger.info("Successfully connected to GitHub repository '%s/%s' on branch '%s'", o, r, client.branch)
    set_github_client(client)

    # Synchronize runtime settings object
    settings.github_owner = o
    settings.github_repo = r
    settings.github_token = t
    settings.github_branch = b
    settings.github_api_url = api
    settings.github_verify_ssl = v_ssl
    settings.github_policies_path = pol_path
    settings.github_log_profiles_path = log_path
    settings.github_custom_sigs_path = sig_path
    settings.storage_backend = "github"

    # Ensure local store (Redis or memory) is ready
    if _local_storage is None:
        init_storage()

    _current_storage = GitHubPolicyStorage(
        github_client=client,
        local_storage=_local_storage,
        policies_path=pol_path,
    )
    _current_logging_storage = GitHubLoggingStorage(
        github_client=client,
        local_storage=_local_logging_storage,
        log_profiles_path=log_path,
    )
    _current_custom_signatures_storage = GitHubCustomSignaturesStorage(
        github_client=client,
        local_storage=_local_custom_signatures_storage,
        custom_sigs_path=sig_path,
    )

    # Pull policies and log profiles from GitHub into Redis so local working copy is populated
    if auto_pull:
        try:
            pull_from_github(_local_storage, _local_logging_storage, _local_custom_signatures_storage)
        except Exception as exc:
            logger.warning("Could not auto-pull from GitHub on connect: %s", exc)

    return _current_storage


def init_storage(
    host: Optional[str] = None,
    port: Optional[int] = None,
    db: Optional[int] = None,
    password: Optional[str] = None,
    ssl: Optional[bool] = None,
    key_prefix: Optional[str] = None,
    force_memory: bool = False,
    backend: Optional[str] = None,
) -> PolicyStorage:
    """Initialize or reconfigure the active storage engine (Redis with In-Memory fallback)."""
    global _current_storage, _current_logging_storage, _current_custom_signatures_storage
    global _local_storage, _local_logging_storage, _local_custom_signatures_storage

    if backend == "github":
        return init_github_storage(auto_pull=True)

    if force_memory or backend in ("memory", "in_memory"):
        logger.info("Initializing In-Memory policy, logging, and custom signatures storage engines")
        _local_storage = MemoryPolicyStorage()
        _local_logging_storage = MemoryLoggingStorage()
        _local_custom_signatures_storage = MemoryCustomSignaturesStorage()
        _current_storage = _local_storage
        _current_logging_storage = _local_logging_storage
        _current_custom_signatures_storage = _local_custom_signatures_storage
        settings.storage_backend = "memory"
        return _current_storage

    h = host if host is not None else settings.redis_host
    p = port if port is not None else settings.redis_port
    d = db if db is not None else settings.redis_db
    pwd = password if password is not None else settings.redis_password
    s = ssl if ssl is not None else settings.redis_ssl
    prefix = key_prefix if key_prefix is not None else settings.redis_key_prefix

    try:
        redis_storage = RedisPolicyStorage(
            host=h,
            port=p,
            db=d,
            password=pwd,
            ssl=s,
            key_prefix=prefix,
        )
        health = redis_storage.get_health()
        if health.get("connected"):
            logger.info("Successfully connected to Redis at %s:%s", h, p)
            _local_storage = redis_storage
            _local_logging_storage = RedisLoggingStorage(redis_client=redis_storage.client)
            _local_custom_signatures_storage = RedisCustomSignaturesStorage(redis_client=redis_storage.client)

            if backend != "redis" and settings.storage_backend == "github" and is_github_configured():
                return init_github_storage(auto_pull=False)

            _current_storage = _local_storage
            _current_logging_storage = _local_logging_storage
            _current_custom_signatures_storage = _local_custom_signatures_storage
            settings.storage_backend = "redis"
            return _current_storage
        else:
            raise ConnectionError(health.get("error", "Failed to ping Redis"))
    except Exception as exc:
        if settings.enable_memory_fallback:
            logger.warning(
                "Redis connection failed (%s). Falling back to resilient In-Memory storage.",
                exc,
            )
            _local_storage = MemoryPolicyStorage()
            _local_logging_storage = MemoryLoggingStorage()
            _local_custom_signatures_storage = MemoryCustomSignaturesStorage()

            if backend != "redis" and settings.storage_backend == "github" and is_github_configured():
                return init_github_storage(auto_pull=False)

            _current_storage = _local_storage
            _current_logging_storage = _local_logging_storage
            _current_custom_signatures_storage = _local_custom_signatures_storage
            settings.storage_backend = "memory"
            return _current_storage
        raise exc


def get_storage() -> PolicyStorage:
    """Get the active policy storage instance, initializing default if not already initialized."""
    global _current_storage
    if _current_storage is None:
        init_storage()
    return _current_storage


def get_logging_storage() -> LoggingProfileStorage:
    """Get the active logging profile storage instance."""
    global _current_logging_storage
    if _current_logging_storage is None:
        init_storage()
    return _current_logging_storage


def get_custom_signatures_storage() -> CustomSignaturesStorage:
    """Get the active custom signatures storage instance."""
    global _current_custom_signatures_storage
    if _current_custom_signatures_storage is None:
        init_storage()
    return _current_custom_signatures_storage


def get_local_storage() -> PolicyStorage:
    """Get the underlying local Redis or Memory storage instance."""
    global _local_storage
    if _local_storage is None:
        init_storage()
    return _local_storage


def get_storage_backend_type() -> str:
    """Return 'github', 'redis', or 'in_memory' depending on the active storage backend."""
    storage = get_storage()
    if isinstance(storage, GitHubPolicyStorage):
        return "github"
    if isinstance(storage, RedisPolicyStorage):
        return "redis"
    return "in_memory"


def get_storage_health() -> Dict[str, Any]:
    """Return health and connection metadata for the currently active storage backend and GitHub GitOps remote."""
    storage = get_storage()
    health = storage.get_health()
    b_type = get_storage_backend_type()
    health["backend"] = b_type
    health["backend_type"] = b_type
    health["github"] = get_github_status()
    health["github_configured"] = is_github_configured()
    if isinstance(storage, GitHubPolicyStorage):
        health["owner"] = storage.client.owner
        health["repo"] = storage.client.repo
        health["branch"] = storage.client.branch
        health["verify_ssl"] = getattr(storage.client, "verify_ssl", settings.github_verify_ssl)
        health["disable_ssl_verify"] = not getattr(storage.client, "verify_ssl", settings.github_verify_ssl)
    return health
