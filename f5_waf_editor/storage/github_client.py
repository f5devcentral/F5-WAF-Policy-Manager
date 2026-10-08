"""
GitHub REST API client for F5 WAF Policy Manager.
Handles repository inspection, listing, reading, committing, and deleting files.
"""

import base64
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx

logger = logging.getLogger("f5_waf_editor.storage.github")


class GitHubClient:
    """Wrapper for GitHub Contents and Repository REST APIs."""

    def __init__(
        self,
        owner: str,
        repo: str,
        token: str,
        branch: str = "main",
        api_url: str = "https://api.github.com",
        timeout: float = 15.0,
        verify_ssl: bool = True,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.owner = (owner or "").strip()
        self.repo = (repo or "").strip()
        self.token = (token or "").strip()
        self.branch = (branch or "main").strip()
        raw_api = (api_url or "https://api.github.com").strip().rstrip("/")
        if raw_api and "api.github.com" not in raw_api:
            if not raw_api.endswith("/api/v3"):
                if raw_api.endswith("/api"):
                    raw_api = f"{raw_api}/v3"
                else:
                    raw_api = f"{raw_api}/api/v3"
        self.api_url = raw_api
        self.timeout = timeout
        self.verify_ssl = bool(verify_ssl)
        self.transport = transport

        if not self.owner:
            raise ValueError("GitHub owner/organization is required")
        if not self.repo:
            raise ValueError("GitHub repository name is required")
        if not self.token:
            raise ValueError("GitHub Personal Access Token (PAT) is required")

    def _client(self) -> httpx.Client:
        """Create an httpx.Client configured with timeout, SSL verification, and custom transport if set."""
        return httpx.Client(
            timeout=self.timeout,
            verify=self.verify_ssl,
            transport=self.transport,
        )

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "F5-WAF-Policy-Manager",
        }

    def _url(self, path: str) -> str:
        clean_path = path.lstrip("/")
        return f"{self.api_url}/{clean_path}"

    def ping(self) -> Dict[str, Any]:
        """Verify repository access and credentials, measure latency, and detect default branch."""
        start_time = time.time()
        url = self._url(f"repos/{self.owner}/{self.repo}")
        try:
            with self._client() as client:
                res = client.get(url, headers=self.headers)
            latency_ms = round((time.time() - start_time) * 1000, 2)

            if res.status_code == 401:
                raise PermissionError("GitHub authentication failed: Bad credentials or expired token")
            if res.status_code == 404:
                raise FileNotFoundError(
                    f"GitHub repository '{self.owner}/{self.repo}' not found or token lacks access permissions"
                )
            if res.status_code >= 400:
                raise RuntimeError(f"GitHub API error ({res.status_code}): {res.text}")

            data = res.json()
            default_branch = data.get("default_branch", "main")
            if not self.branch:
                self.branch = default_branch

            return {
                "connected": True,
                "backend": "github",
                "owner": self.owner,
                "repo": self.repo,
                "branch": self.branch,
                "default_branch": default_branch,
                "full_name": data.get("full_name", f"{self.owner}/{self.repo}"),
                "private": data.get("private", True),
                "permissions": data.get("permissions", {}),
                "latency_ms": latency_ms,
                "api_url": self.api_url,
                "verify_ssl": self.verify_ssl,
                "disable_ssl_verify": not self.verify_ssl,
            }
        except (PermissionError, FileNotFoundError, RuntimeError):
            raise
        except Exception as exc:
            raise ConnectionError(f"Failed to connect to GitHub endpoint: {str(exc)}") from exc

    def list_files(self, directory: str = "") -> List[Dict[str, Any]]:
        """List all files in a specific repository directory on the configured branch."""
        clean_dir = directory.strip("/")
        endpoint = f"repos/{self.owner}/{self.repo}/contents/{clean_dir}" if clean_dir else f"repos/{self.owner}/{self.repo}/contents"
        url = self._url(endpoint)
        params = {"ref": self.branch} if self.branch else {}

        with self._client() as client:
            res = client.get(url, headers=self.headers, params=params)

        if res.status_code == 404:
            # Directory does not exist yet in repo; return empty list
            return []
        if res.status_code >= 400:
            raise RuntimeError(f"Failed to list directory '{clean_dir}': {res.text}")

        data = res.json()
        if not isinstance(data, list):
            # Single file returned instead of directory
            if isinstance(data, dict) and data.get("type") == "file":
                return [data]
            return []

        return [item for item in data if isinstance(item, dict) and item.get("type") == "file"]

    def get_file(self, file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieve raw file content (UTF-8 string) and its blob SHA.
        Returns (content, sha) or (None, None) if file does not exist.
        """
        clean_path = file_path.strip("/")
        url = self._url(f"repos/{self.owner}/{self.repo}/contents/{clean_path}")
        params = {"ref": self.branch} if self.branch else {}

        with self._client() as client:
            res = client.get(url, headers=self.headers, params=params)

        if res.status_code == 404:
            return None, None
        if res.status_code >= 400:
            raise RuntimeError(f"Failed to fetch file '{clean_path}': {res.text}")

        data = res.json()
        if not isinstance(data, dict):
            return None, None

        sha = data.get("sha")
        content_b64 = data.get("content", "")
        encoding = data.get("encoding", "base64")

        if encoding == "base64" and content_b64:
            try:
                # Remove any newlines from base64 string
                decoded_bytes = base64.b64decode(content_b64.replace("\n", ""))
                return decoded_bytes.decode("utf-8"), sha
            except Exception as exc:
                logger.error("Failed to decode base64 content for %s: %s", clean_path, exc)
                return None, sha

        return None, sha

    def put_file(
        self,
        file_path: str,
        content_str: str,
        message: str,
        sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create or update a file in the repository, generating a Git commit.
        Automatically resolves the current file SHA if not explicitly provided.
        """
        clean_path = file_path.strip("/")
        url = self._url(f"repos/{self.owner}/{self.repo}/contents/{clean_path}")

        # If sha is not provided, check if file exists to supply required sha on update
        target_sha = sha
        if not target_sha:
            _, existing_sha = self.get_file(clean_path)
            if existing_sha:
                target_sha = existing_sha

        b64_content = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
        payload: Dict[str, Any] = {
            "message": message,
            "content": b64_content,
            "branch": self.branch,
        }
        if target_sha:
            payload["sha"] = target_sha

        with self._client() as client:
            res = client.put(url, headers=self.headers, json=payload)

        if res.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to commit file '{clean_path}' to GitHub ({res.status_code}): {res.text}"
            )

        return res.json()

    def delete_file(
        self,
        file_path: str,
        message: str,
        sha: Optional[str] = None,
    ) -> bool:
        """
        Delete a file from the repository, generating a Git commit.
        Returns True if deleted, False if file was not found.
        """
        clean_path = file_path.strip("/")
        target_sha = sha
        if not target_sha:
            _, existing_sha = self.get_file(clean_path)
            if not existing_sha:
                return False
            target_sha = existing_sha

        url = self._url(f"repos/{self.owner}/{self.repo}/contents/{clean_path}")
        payload = {
            "message": message,
            "sha": target_sha,
            "branch": self.branch,
        }

        with self._client() as client:
            res = client.request("DELETE", url, headers=self.headers, json=payload)

        if res.status_code == 404:
            return False
        if res.status_code >= 400:
            raise RuntimeError(f"Failed to delete file '{clean_path}': {res.text}")

        return True
