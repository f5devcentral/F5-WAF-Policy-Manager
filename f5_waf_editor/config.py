"""
Configuration settings for F5 WAF Policy Manager.
Supports environment variables and runtime reconfiguration.
"""

import os
from pydantic import BaseModel, Field


class Settings(BaseModel):
    # Web server settings
    app_host: str = Field(default=os.getenv("APP_HOST", "0.0.0.0"))
    app_port: int = Field(default=int(os.getenv("APP_PORT", "8000")))
    app_debug: bool = Field(default=os.getenv("APP_DEBUG", "false").lower() == "true")

    # Redis settings
    redis_host: str = Field(default=os.getenv("REDIS_HOST", "localhost"))
    redis_port: int = Field(default=int(os.getenv("REDIS_PORT", "6379")))
    redis_db: int = Field(default=int(os.getenv("REDIS_DB", "0")))
    redis_password: str | None = Field(default=os.getenv("REDIS_PASSWORD", None) or None)
    redis_ssl: bool = Field(default=os.getenv("REDIS_SSL", "false").lower() == "true")
    redis_key_prefix: str = Field(default=os.getenv("REDIS_KEY_PREFIX", ""))
    
    # Storage backend settings: 'redis' | 'github' | 'memory'
    storage_backend: str = Field(default=os.getenv("STORAGE_BACKEND", "redis"))

    # When True, if Redis is unavailable, automatically fall back to resilient in-memory store
    enable_memory_fallback: bool = Field(default=os.getenv("ENABLE_MEMORY_FALLBACK", "true").lower() == "true")

    # GitHub settings
    github_owner: str | None = Field(default=os.getenv("GITHUB_OWNER", None) or os.getenv("GITHUB_ORG", None) or None)
    github_repo: str | None = Field(default=os.getenv("GITHUB_REPO", None) or None)
    github_token: str | None = Field(default=os.getenv("GITHUB_TOKEN", None) or os.getenv("GITHUB_PAT", None) or None)
    github_branch: str = Field(default=os.getenv("GITHUB_BRANCH", "main"))
    github_api_url: str = Field(default=os.getenv("GITHUB_API_URL", "https://api.github.com"))
    github_policies_path: str = Field(default=os.getenv("GITHUB_POLICIES_PATH", "policies"))
    github_log_profiles_path: str = Field(default=os.getenv("GITHUB_LOG_PROFILES_PATH", "log-profiles"))
    github_custom_sigs_path: str = Field(default=os.getenv("GITHUB_CUSTOM_SIGS_PATH", "custom-signatures"))
    github_verify_ssl: bool = Field(
        default=os.getenv("GITHUB_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
        and os.getenv("GITHUB_DISABLE_SSL_VERIFY", "false").lower() not in ("true", "1", "yes")
    )

    # Compiler Service settings (apcompile container)
    compiler_service_url: str = Field(default=os.getenv("COMPILER_SERVICE_URL", ""))


settings = Settings()
