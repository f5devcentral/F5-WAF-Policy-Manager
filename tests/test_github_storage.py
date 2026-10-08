"""
Tests for GitHub GitOps Storage Backends (Policies, Logging Profiles, Custom Signatures)
and GitHub configuration API endpoints.
"""

import base64
import json
from unittest.mock import patch, MagicMock
import httpx
import pytest
from fastapi.testclient import TestClient

from f5_waf_editor.app import app
from f5_waf_editor.storage.github_client import GitHubClient
from f5_waf_editor.storage.github_backend import GitHubPolicyStorage
from f5_waf_editor.storage.github_logging_backend import GitHubLoggingStorage
from f5_waf_editor.storage.github_custom_signatures_backend import GitHubCustomSignaturesStorage
from f5_waf_editor.storage import init_github_storage, init_storage, get_storage, get_logging_storage


class MockGitHubTransport(httpx.BaseTransport):
    """Mock in-memory HTTP transport simulating the GitHub REST API."""

    def __init__(self, owner: str = "acme-corp", repo: str = "waf-policies", branch: str = "main"):
        self.owner = owner
        self.repo = repo
        self.branch = branch
        # In-memory filesystem: path -> (b64_content, sha)
        self.files: dict[str, tuple[str, str]] = {}
        self.commit_count = 0
        self.commits: list[dict] = []

    def add_file(self, path: str, content_str: str, sha: str = "initial-sha-123"):
        clean_path = path.strip("/")
        b64 = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
        self.files[clean_path] = (b64, sha)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        method = request.method

        # 1. Ping / Repo info: /repos/{owner}/{repo}
        if url_path == f"/repos/{self.owner}/{self.repo}" and method == "GET":
            return httpx.Response(
                200,
                json={
                    "full_name": f"{self.owner}/{self.repo}",
                    "default_branch": self.branch,
                    "private": True,
                    "permissions": {"push": True, "pull": True, "admin": False},
                },
            )

        # 2. Contents API: /repos/{owner}/{repo}/contents/{path}
        prefix = f"/repos/{self.owner}/{self.repo}/contents"
        if url_path.startswith(prefix):
            target_path = url_path[len(prefix):].strip("/")

            if method == "GET":
                # Check if exact file match
                if target_path in self.files:
                    b64, sha = self.files[target_path]
                    file_name = target_path.split("/")[-1]
                    return httpx.Response(
                        200,
                        json={
                            "name": file_name,
                            "path": target_path,
                            "sha": sha,
                            "size": len(base64.b64decode(b64)),
                            "type": "file",
                            "encoding": "base64",
                            "content": b64,
                        },
                    )

                # Check if directory match
                dir_prefix = f"{target_path}/" if target_path else ""
                matched_items = []
                for p, (b64, sha) in self.files.items():
                    if p.startswith(dir_prefix):
                        sub = p[len(dir_prefix):]
                        if "/" not in sub:  # direct child file
                            matched_items.append(
                                {
                                    "name": sub,
                                    "path": p,
                                    "sha": sha,
                                    "size": len(base64.b64decode(b64)),
                                    "type": "file",
                                    "download_url": f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.branch}/{p}",
                                }
                            )

                if matched_items or target_path == "":
                    return httpx.Response(200, json=matched_items)

                return httpx.Response(404, json={"message": "Not Found"})

            elif method == "PUT":
                self.commit_count += 1
                body = json.loads(request.content.decode("utf-8"))
                content_b64 = body.get("content", "")
                commit_msg = body.get("message", "Commit message")
                new_sha = f"commit-sha-{self.commit_count}"
                self.files[target_path] = (content_b64, new_sha)
                self.commits.append({"path": target_path, "message": commit_msg, "sha": new_sha})
                return httpx.Response(
                    201,
                    json={
                        "content": {
                            "name": target_path.split("/")[-1],
                            "path": target_path,
                            "sha": new_sha,
                        },
                        "commit": {
                            "sha": f"git-commit-{self.commit_count}",
                            "message": commit_msg,
                            "html_url": f"https://github.com/{self.owner}/{self.repo}/commit/git-commit-{self.commit_count}",
                        },
                    },
                )

            elif method == "DELETE":
                if target_path in self.files:
                    del self.files[target_path]
                    self.commit_count += 1
                    return httpx.Response(
                        200,
                        json={
                            "commit": {
                                "sha": f"delete-commit-{self.commit_count}",
                                "message": "Delete file",
                            }
                        },
                    )
                return httpx.Response(404, json={"message": "Not Found"})

        return httpx.Response(404, json={"message": "Not Found"})


@pytest.fixture
def mock_github():
    transport = MockGitHubTransport(owner="f5-corp", repo="nginx-waf-gitops", branch="main")
    client = GitHubClient(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test_mock_token_12345",
        branch="main",
        transport=transport,
    )

    original_init = GitHubClient.__init__

    def patched_init(self, *args, **kwargs):
        if kwargs.get("transport") is None:
            kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    from f5_waf_editor.storage.github_service import set_github_client
    set_github_client(client)

    with patch("f5_waf_editor.storage.GitHubClient.__init__", patched_init), \
         patch("f5_waf_editor.storage.github_client.GitHubClient.__init__", patched_init):
        yield transport, client

    set_github_client(None)


def test_github_client_ping_and_files(mock_github):
    transport, client = mock_github
    ping = client.ping()
    assert ping["connected"] is True
    assert ping["backend"] == "github"
    assert ping["owner"] == "f5-corp"
    assert ping["repo"] == "nginx-waf-gitops"
    assert ping["branch"] == "main"

    # Put a file
    result = client.put_file("policies/test.json", '{"hello": "world"}', "Add test policy")
    assert result["content"]["path"] == "policies/test.json"
    assert "commit" in result

    # Get the file
    content, sha = client.get_file("policies/test.json")
    assert content == '{"hello": "world"}'
    assert sha is not None

    # List files
    files = client.list_files("policies")
    assert len(files) == 1
    assert files[0]["name"] == "test.json"

    # Delete file
    deleted = client.delete_file("policies/test.json", "Delete test policy")
    assert deleted is True
    assert len(client.list_files("policies")) == 0


def test_github_policy_storage_crud(mock_github):
    transport, client = mock_github
    storage = GitHubPolicyStorage(client, policies_path="policies")

    # Initial empty list
    assert len(storage.list_policies()) == 0

    policy_data = {
        "policy": {
            "name": "api_security_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "description": "Production API Security WAF policy on GitHub",
        }
    }

    # Save policy (creates Git commit)
    meta = storage.save_policy("api_security_policy", policy_data)
    assert meta["name"] == "api_security_policy"
    assert meta["github_path"] == "policies/api_security_policy.json"
    assert "commit_sha" in meta

    # List policies
    policies = storage.list_policies()
    assert len(policies) == 1
    assert policies[0]["name"] == "api_security_policy"
    assert policies[0]["enforcementMode"] == "blocking"

    # Check policy_exists
    assert storage.policy_exists("api_security_policy") is True
    assert storage.policy_exists("non_existent") is False

    # Get policy
    retrieved = storage.get_policy("api_security_policy")
    assert retrieved is not None
    assert retrieved["policy"]["name"] == "api_security_policy"

    # Get raw policy
    raw = storage.get_raw_policy("api_security_policy")
    assert raw is not None
    assert "api_security_policy" in raw

    # Clone policy (creates new file commit)
    clone_meta = storage.clone_policy("api_security_policy", "api_security_policy_v2")
    assert clone_meta["name"] == "api_security_policy_v2"
    assert storage.policy_exists("api_security_policy_v2") is True
    assert len(storage.list_policies()) == 2

    # Rename policy
    renamed = storage.rename_policy("api_security_policy_v2", "api_security_policy_prod")
    assert renamed["name"] == "api_security_policy_prod"
    assert storage.policy_exists("api_security_policy_v2") is False
    assert storage.policy_exists("api_security_policy_prod") is True

    # Delete policy
    deleted = storage.delete_policy("api_security_policy")
    assert deleted is True
    assert storage.policy_exists("api_security_policy") is False
    assert len(storage.list_policies()) == 1

    # Health
    health = storage.get_health()
    assert health["connected"] is True
    assert health["backend"] == "github"


def test_github_logging_profile_storage_crud(mock_github):
    transport, client = mock_github
    storage = GitHubLoggingStorage(client, log_profiles_path="log-profiles")

    assert len(storage.list_profiles()) == 0

    log_profile_data = {
        "filter": {
            "request_type": "all",
            "name": "splunk_logging_profile",
        },
        "content": {
            "format": "splunk",
            "format_string": "%date% %time%",
            "max_message_size": "10k",
            "max_request_size": "2k",
        },
    }

    # Save
    meta = storage.save_profile("splunk_logging_profile", log_profile_data)
    assert meta["name"] == "splunk_logging_profile"
    assert meta["github_path"] == "log-profiles/splunk_logging_profile.json"

    # List
    profiles = storage.list_profiles()
    assert len(profiles) == 1
    assert profiles[0]["name"] == "splunk_logging_profile"

    # Get
    retrieved = storage.get_profile("splunk_logging_profile")
    assert retrieved is not None
    assert retrieved["filter"]["request_type"] == "all"

    # Clone
    clone_meta = storage.clone_profile("splunk_logging_profile", "splunk_logging_profile_backup")
    assert clone_meta["name"] == "splunk_logging_profile_backup"
    assert len(storage.list_profiles()) == 2

    # Delete
    deleted = storage.delete_profile("splunk_logging_profile")
    assert deleted is True
    assert storage.profile_exists("splunk_logging_profile") is False
    assert len(storage.list_profiles()) == 1


def test_github_api_endpoints_and_switching(mock_github):
    transport, client = mock_github
    test_client = TestClient(app)

    # Clean local memory storage
    init_storage(force_memory=True)

    # Pre-seed a file on remote GitHub repository
    remote_pol_content = json.dumps({
        "policy": {
            "name": "remote_waf_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
        }
    })
    transport.add_file("policies/remote_waf_policy.json", remote_pol_content)

    remote_log_content = json.dumps({
        "filter": {
            "name": "remote_log_profile",
            "request_type": "all",
        },
        "content": {
            "format": "default",
            "max_message_size": "5k",
        },
    })
    transport.add_file("log-profiles/remote_log_profile.json", remote_log_content)

    # 1. Connect GitHub endpoint via POST /api/github/connect
    res = test_client.post(
        "/api/github/connect",
        json={
            "owner": "f5-corp",
            "repo": "nginx-waf-gitops",
            "token": "ghp_test_token_1234",
            "branch": "main",
            "policies_path": "policies",
            "log_profiles_path": "log-profiles",
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert "Successfully connected to GitHub" in data["message"]
    assert data["health"]["github"]["connected"] is True
    assert data["health"]["github"]["owner"] == "f5-corp"

    # 2. Check storage status and github status endpoints
    status_res = test_client.get("/api/storage/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["connected"] is True
    assert status_data["github"]["connected"] is True
    assert status_data["github"]["owner"] == "f5-corp"

    gh_res = test_client.get("/api/github/status")
    assert gh_res.status_code == 200
    assert gh_res.json()["connected"] is True

    # 3. Pull from GitHub into Redis/Memory
    pull_res = test_client.post("/api/github/pull")
    assert pull_res.status_code == 200, pull_res.text
    pull_data = pull_res.json()
    assert "remote_waf_policy" in pull_data["policies_pulled"]
    assert "remote_log_profile" in pull_data["log_profiles_pulled"]

    # 4. Verify pulled policy is listed and accessible locally
    list_res = test_client.get("/api/policies")
    assert list_res.status_code == 200
    assert any(p["name"] == "remote_waf_policy" for p in list_res.json())

    # 5. Create new policy locally in Redis/Memory
    create_res = test_client.post(
        "/api/policies",
        json={
            "name": "local_waf_policy",
            "template_id": "api_security",
        },
    )
    assert create_res.status_code == 201, create_res.text

    # 6. Commit and Push policy from Redis to GitHub
    push_pol_res = test_client.post(
        "/api/policies/local_waf_policy/github-push",
        json={"message": "feat(waf): publish api security policy"},
    )
    assert push_pol_res.status_code == 200, push_pol_res.text
    push_data = push_pol_res.json()
    assert "successfully committed to GitHub" in push_data["message"]
    assert "policies/local_waf_policy.json" in transport.files

    # 7. Create new logging profile locally and commit to GitHub
    create_log_res = test_client.post(
        "/api/log-profiles",
        json={
            "name": "local_log_profile",
            "template_id": "log_default",
        },
    )
    assert create_log_res.status_code == 201, create_log_res.text

    push_log_res = test_client.post(
        "/api/log-profiles/local_log_profile/github-push",
        json={"message": "feat(logging): publish default logging profile"},
    )
    assert push_log_res.status_code == 200, push_log_res.text
    assert "log-profiles/local_log_profile.json" in transport.files

    # Reset back to clean in-memory storage
    init_storage(force_memory=True)


def test_github_startup_retrieval_into_redis(mock_github):
    transport, client = mock_github
    from f5_waf_editor.config import settings
    from f5_waf_editor.storage.github_service import pull_from_github, is_github_configured

    # Clean local memory storage
    init_storage(force_memory=True)

    # Configure settings for GitHub
    settings.github_owner = "f5-corp"
    settings.github_repo = "nginx-waf-gitops"
    settings.github_token = "ghp_startup_token"
    settings.github_branch = "main"

    assert is_github_configured() is True

    # Pre-seed GitHub repository with files
    transport.add_file(
        "policies/startup_waf_policy.json",
        json.dumps({
            "policy": {
                "name": "startup_waf_policy",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            }
        }),
    )
    transport.add_file(
        "log-profiles/startup_log_profile.json",
        json.dumps({
            "filter": {
                "name": "startup_log_profile",
                "request_type": "all",
            },
            "content": {
                "format": "default",
                "max_message_size": "5k",
            },
        }),
    )

    # Simulate startup pull
    pull_result = pull_from_github()
    assert pull_result["success"] is True
    assert "startup_waf_policy" in pull_result["policies_pulled"]
    assert "startup_log_profile" in pull_result["log_profiles_pulled"]

    # Verify policies and log profiles exist in local storage and can be queried via API
    test_client = TestClient(app)
    pol_res = test_client.get("/api/policies")
    assert pol_res.status_code == 200
    assert any(p["name"] == "startup_waf_policy" for p in pol_res.json())

    log_res = test_client.get("/api/log-profiles")
    assert log_res.status_code == 200
    assert any(p["name"] == "startup_log_profile" for p in log_res.json())

    # Clean up settings
    settings.github_owner = None
    settings.github_repo = None
    settings.github_token = None


def test_gitops_redis_staging_and_commit_workflow(mock_github):
    """
    Verifies the user requirements:
    1. WAF policies and logging profiles are displayed as they are on the GitHub repo.
    2. Editing a policy or logging profile writes intermediate saves to local Redis/Memory (marked dirty/uncommitted).
    3. Intermediate saves do NOT push directly to GitHub.
    4. Explicit 'Commit to GitHub' pushes changes to GitHub and clears uncommitted status.
    5. 'Revert' discards intermediate changes and restores the GitHub version.
    """
    transport, client = mock_github
    test_client = TestClient(app)

    # 1. Initialize local in-memory storage (simulating local Redis)
    init_storage(force_memory=True)
    local_store = get_storage()
    local_log_store = get_logging_storage()

    # Pre-seed a dummy local policy in Redis that DOES NOT exist on GitHub
    local_store.save_policy("stale_local_demo", {
        "policy": {"name": "stale_local_demo", "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"}}
    })

    # Pre-seed GitHub repository with official repo policy and log profile
    repo_policy_content = {
        "policy": {
            "name": "gitops_waf_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "description": "Clean version on GitHub repository",
        }
    }
    transport.add_file("policies/gitops_waf_policy.json", json.dumps(repo_policy_content))

    repo_log_content = {
        "filter": {"name": "gitops_log_profile", "request_type": "all"},
        "content": {"format": "default", "max_message_size": "5k"},
    }
    transport.add_file("log-profiles/gitops_log_profile.json", json.dumps(repo_log_content))

    # Initialize GitHub storage backend wrapping local storage
    init_github_storage(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test_token_1234",
        branch="main",
        transport=transport,
        auto_pull=True,
    )

    # 2. Check Display: Listing must display what is on GitHub repo
    pol_list_res = test_client.get("/api/policies")
    assert pol_list_res.status_code == 200
    pol_names = [p["name"] for p in pol_list_res.json()]
    assert "gitops_waf_policy" in pol_names
    # Stale local policy should NOT be shown in the GitHub catalog
    assert "stale_local_demo" not in pol_names

    p_item = next(p for p in pol_list_res.json() if p["name"] == "gitops_waf_policy")
    assert p_item["status"] == "synced"
    assert p_item.get("uncommitted_changes") is False

    # Check Logging Profile Display
    log_list_res = test_client.get("/api/log-profiles")
    assert log_list_res.status_code == 200
    log_names = [l["name"] for l in log_list_res.json()]
    assert "gitops_log_profile" in log_names

    # 3. Intermediate Save: Edit policy and save
    initial_commits = transport.commit_count

    modified_policy = json.loads(json.dumps(repo_policy_content))
    modified_policy["policy"]["description"] = "Draft changes in intermediate Redis storage"

    save_res = test_client.put(
        "/api/policies/gitops_waf_policy",
        json={"content": modified_policy},
    )
    assert save_res.status_code == 200, save_res.text
    save_data = save_res.json()
    assert save_data["metadata"]["saved_to"] == "redis"
    assert save_data["metadata"]["uncommitted_changes"] is True

    # Intermediate save must NOT create a GitHub commit
    assert transport.commit_count == initial_commits

    # Verify that listing now shows "modified" and uncommitted_changes=True
    pol_list_res2 = test_client.get("/api/policies")
    p_item2 = next(p for p in pol_list_res2.json() if p["name"] == "gitops_waf_policy")
    assert p_item2["status"] == "modified"
    assert p_item2["uncommitted_changes"] is True

    # Verify reading returns the intermediate Redis draft
    get_res = test_client.get("/api/policies/gitops_waf_policy")
    assert get_res.status_code == 200
    assert get_res.json()["policy"]["description"] == "Draft changes in intermediate Redis storage"

    # 4. Intermediate Save for Logging Profile
    modified_log = json.loads(json.dumps(repo_log_content))
    modified_log["content"]["max_message_size"] = "15k"

    save_log_res = test_client.put(
        "/api/log-profiles/gitops_log_profile",
        json={"content": modified_log},
    )
    assert save_log_res.status_code == 200, save_log_res.text
    save_log_data = save_log_res.json()
    assert save_log_data["metadata"]["saved_to"] == "redis"
    assert save_log_data["metadata"]["uncommitted_changes"] is True
    assert transport.commit_count == initial_commits

    log_list_res2 = test_client.get("/api/log-profiles")
    l_item2 = next(l for l in log_list_res2.json() if l["name"] == "gitops_log_profile")
    assert l_item2["status"] == "modified"
    assert l_item2["uncommitted_changes"] is True

    # 5. Revert Logging Profile: Discard Redis draft and restore GitHub version
    revert_log_res = test_client.post("/api/log-profiles/gitops_log_profile/github-revert")
    assert revert_log_res.status_code == 200
    assert revert_log_res.json()["status"] == "reverted"

    log_list_res3 = test_client.get("/api/log-profiles")
    l_item3 = next(l for l in log_list_res3.json() if l["name"] == "gitops_log_profile")
    assert l_item3["status"] == "synced"
    assert l_item3.get("uncommitted_changes") is False

    get_log_res = test_client.get("/api/log-profiles/gitops_log_profile")
    assert get_log_res.json()["content"]["max_message_size"] == "5k"

    # 6. Commit to GitHub: Push policy intermediate changes from Redis to GitHub
    push_res = test_client.post(
        "/api/policies/gitops_waf_policy/github-push",
        json={"message": "feat: update gitops policy description"},
    )
    assert push_res.status_code == 200, push_res.text
    push_data = push_res.json()
    assert "successfully committed to GitHub" in push_data["message"]
    assert transport.commit_count == initial_commits + 1

    # Verify listing is now clean/synced
    pol_list_res3 = test_client.get("/api/policies")
    p_item3 = next(p for p in pol_list_res3.json() if p["name"] == "gitops_waf_policy")
    assert p_item3["status"] == "synced"
    assert p_item3.get("uncommitted_changes") is False

    # Verify remote file on GitHub is updated
    content_raw, sha = client.get_file("policies/gitops_waf_policy.json")
    remote_data = json.loads(content_raw)
    assert remote_data["policy"]["description"] == "Draft changes in intermediate Redis storage"

    # Reset back to clean in-memory storage
    init_storage(force_memory=True)


def test_github_client_ssl_verification_options():
    """Verify GitHubClient initialization and _client() respecting verify_ssl."""
    transport = MockGitHubTransport(owner="f5-corp", repo="nginx-waf-gitops")

    # Default should be verify_ssl=True
    client_default = GitHubClient(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test123",
        transport=transport,
    )
    assert client_default.verify_ssl is True
    c1 = client_default._client()
    c1.close()
    ping_default = client_default.ping()
    assert ping_default["verify_ssl"] is True
    assert ping_default["disable_ssl_verify"] is False

    # Disabled verification: verify_ssl=False
    client_insecure = GitHubClient(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test123",
        verify_ssl=False,
        transport=transport,
    )
    assert client_insecure.verify_ssl is False
    c2 = client_insecure._client()
    c2.close()
    ping_insecure = client_insecure.ping()
    assert ping_insecure["verify_ssl"] is False
    assert ping_insecure["disable_ssl_verify"] is True


def test_github_connect_api_ssl_verification(mock_github):
    """Test /api/github/connect endpoint with disable_ssl_verify flag."""
    transport, _ = mock_github
    test_client = TestClient(app)

    # Connect with disable_ssl_verify=True
    res = test_client.post(
        "/api/github/connect",
        json={
            "owner": "f5-corp",
            "repo": "nginx-waf-gitops",
            "token": "ghp_test_mock_token_12345",
            "branch": "main",
            "disable_ssl_verify": True,
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert "Successfully connected" in data["message"]

    health = data.get("health", {})
    assert health.get("verify_ssl") is False
    assert health.get("disable_ssl_verify") is True

    # Check status endpoint
    status_res = test_client.get("/api/storage/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data.get("verify_ssl") is False
    assert status_data.get("disable_ssl_verify") is True
    assert status_data.get("github", {}).get("verify_ssl") is False
    assert status_data.get("github", {}).get("disable_ssl_verify") is True

    # Reconnect with verify_ssl=True (enabling certificate verification)
    res2 = test_client.post(
        "/api/github/connect",
        json={
            "owner": "f5-corp",
            "repo": "nginx-waf-gitops",
            "token": "ghp_test_mock_token_12345",
            "branch": "main",
            "verify_ssl": True,
        },
    )
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert data2.get("health", {}).get("verify_ssl") is True
    assert data2.get("health", {}).get("disable_ssl_verify") is False

    # Cleanup: restore in-memory storage
    init_storage(force_memory=True)


def test_github_client_api_url_normalization():
    """Verify that api_url correctly handles GitHub Enterprise URLs with and without /api/v3."""
    client_cloud = GitHubClient(
        owner="org",
        repo="repo",
        token="tok",
        api_url="https://api.github.com",
    )
    assert client_cloud.api_url == "https://api.github.com"

    client_ghes_domain = GitHubClient(
        owner="org",
        repo="repo",
        token="tok",
        api_url="https://ghes.company.local",
    )
    assert client_ghes_domain.api_url == "https://ghes.company.local/api/v3"

    client_ghes_with_api = GitHubClient(
        owner="org",
        repo="repo",
        token="tok",
        api_url="https://ghes.company.local/api",
    )
    assert client_ghes_with_api.api_url == "https://ghes.company.local/api/v3"

    client_ghes_with_v3 = GitHubClient(
        owner="org",
        repo="repo",
        token="tok",
        api_url="https://ghes.company.local/api/v3/",
    )
    assert client_ghes_with_v3.api_url == "https://ghes.company.local/api/v3"


def test_github_pull_overwrites_redis_and_preserves_local_drafts(mock_github):
    """
    Verifies that when clicking 'pull from github':
    1. If a policy or log profile already exists in Redis, the Redis copy is overwritten by GitHub.
    2. The pulled policy/profile is clean ('synced', uncommitted_changes=False).
    3. Policies/profiles in Redis that do not exist on GitHub remain in Redis as drafts ('new_uncommitted').
    """
    transport, client = mock_github
    test_client = TestClient(app)

    # 1. Initialize local storage (simulating local Redis)
    init_storage(force_memory=True)
    local_store = get_storage()
    local_log_store = get_logging_storage()

    # Pre-seed Redis with a policy that does NOT exist on GitHub
    local_store.save_policy("local_only_draft_policy", {
        "policy": {
            "name": "local_only_draft_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "description": "I only exist in local Redis as a draft",
        }
    })

    # Pre-seed GitHub repository with official files
    github_policy = {
        "policy": {
            "name": "shared_gitops_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "description": "Fresh content from GitHub",
        }
    }
    transport.add_file("policies/shared_gitops_policy.json", json.dumps(github_policy))

    github_log = {
        "filter": {"name": "shared_gitops_log", "request_type": "all"},
        "content": {"format": "default", "max_message_size": "5k"},
    }
    transport.add_file("log-profiles/shared_gitops_log.json", json.dumps(github_log))

    # Initialize GitHub storage backend
    init_github_storage(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test_token_pull_overwrite",
        branch="main",
        transport=transport,
        auto_pull=False,
    )
    gh_store = get_storage()
    # Explicitly mark local_only_draft_policy as dirty/draft in Redis
    gh_store._mark_dirty("local_only_draft_policy")

    # Seed an outdated/modified copy of shared_policy directly in local storage and mark dirty
    local_store.save_policy("shared_gitops_policy", {
        "policy": {
            "name": "shared_gitops_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "description": "Outdated local draft in Redis that should be overwritten",
        }
    })
    gh_store._mark_dirty("shared_gitops_policy")
    assert gh_store._is_dirty("shared_gitops_policy") is True

    # 2. Trigger pull from GitHub
    pull_res = test_client.post("/api/github/pull")
    assert pull_res.status_code == 200, pull_res.text
    pull_data = pull_res.json()
    assert "shared_gitops_policy" in pull_data["policies_pulled"]
    assert "shared_gitops_log" in pull_data["log_profiles_pulled"]

    # 3. Verify Redis copy of shared_gitops_policy was overwritten by GitHub
    raw_pulled = local_store.get_policy("shared_gitops_policy")
    assert raw_pulled["policy"]["description"] == "Fresh content from GitHub"
    assert gh_store._is_dirty("shared_gitops_policy") is False

    # 4. Verify policy listing:
    # - shared_gitops_policy is 'synced'
    # - local_only_draft_policy remains in Redis as 'new_uncommitted'
    pol_list_res = test_client.get("/api/policies")
    assert pol_list_res.status_code == 200
    pols = {p["name"]: p for p in pol_list_res.json()}

    assert "shared_gitops_policy" in pols
    assert pols["shared_gitops_policy"]["status"] == "synced"
    assert pols["shared_gitops_policy"]["uncommitted_changes"] is False

    assert "local_only_draft_policy" in pols
    assert pols["local_only_draft_policy"]["status"] == "new_uncommitted"
    assert pols["local_only_draft_policy"]["uncommitted_changes"] is True

    # Cleanup
    init_storage(force_memory=True)


def test_github_pull_conflicts_detection(mock_github):
    """
    Test that GET /api/github/pull/conflicts identifies policies and log profiles
    that exist on GitHub AND have uncommitted draft modifications in local Redis,
    while ignoring clean items and local-only items.
    """
    from f5_waf_editor.app import app
    from f5_waf_editor.storage import init_github_storage, init_storage, get_storage, get_logging_storage

    transport, client = mock_github
    test_client = TestClient(app)

    github_policy = {
        "policy": {
            "name": "conflict_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "description": "Remote GitHub policy copy",
        }
    }
    github_log = {
        "filter": {
            "name": "conflict_log",
            "description": "Remote GitHub logging profile",
        },
        "content": {
            "format": "default",
        },
    }

    transport.add_file("policies/conflict_policy.json", json.dumps(github_policy), sha="sha_conflict_pol_1")
    transport.add_file("log-profiles/conflict_log.json", json.dumps(github_log), sha="sha_conflict_log_1")

    init_storage(force_memory=True)
    init_github_storage(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test_conflicts",
        branch="main",
        transport=transport,
        auto_pull=False,
    )
    gh_store = get_storage()
    gh_log_store = get_logging_storage()

    # 1. Setup local Redis state:
    # - conflict_policy: draft in Redis, exists on GitHub -> CONFLICT
    gh_store.save_policy("conflict_policy", {
        "policy": {
            "name": "conflict_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "description": "Local draft policy in Redis",
        }
    })
    assert gh_store._is_dirty("conflict_policy") is True

    # - conflict_log: draft in Redis, exists on GitHub -> CONFLICT
    gh_log_store.save_profile("conflict_log", {
        "filter": {
            "name": "conflict_log",
            "description": "Local draft log profile in Redis",
        },
        "content": {
            "format": "default",
        },
    })
    assert gh_log_store._is_dirty("conflict_log") is True

    # - local_only_draft: draft in Redis, NOT on GitHub -> NOT a conflict
    gh_store.save_policy("local_only_draft", {
        "policy": {
            "name": "local_only_draft",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
        }
    })
    assert gh_store._is_dirty("local_only_draft") is True

    # 2. Check conflicts endpoint
    conf_res = test_client.get("/api/github/pull/conflicts")
    assert conf_res.status_code == 200, conf_res.text
    conf_data = conf_res.json()

    assert conf_data["has_conflicts"] is True
    conflict_names = {f"{c['type']}:{c['name']}" for c in conf_data["conflicts"]}
    assert "policy:conflict_policy" in conflict_names
    assert "logging:conflict_log" in conflict_names
    assert "policy:local_only_draft" not in conflict_names

    # 3. Test conflict resolution: KEEP LOCAL
    res_keep_local = test_client.post("/api/github/pull", json={
        "resolutions": {
            "policies": {"conflict_policy": "keep_local"},
            "log_profiles": {"conflict_log": "keep_local"},
        }
    })
    assert res_keep_local.status_code == 200, res_keep_local.text
    data_kl = res_keep_local.json()
    assert "conflict_policy" in data_kl["policies_preserved"]
    assert "conflict_log" in data_kl["log_profiles_preserved"]
    assert "conflict_policy" not in data_kl["policies_pulled"]
    assert "conflict_log" not in data_kl["log_profiles_pulled"]

    # Verify local draft was NOT overwritten and remains dirty
    pol_local = gh_store.get_policy("conflict_policy")
    assert pol_local["policy"]["description"] == "Local draft policy in Redis"
    assert gh_store._is_dirty("conflict_policy") is True

    # 4. Test conflict resolution: KEEP GITHUB
    res_keep_github = test_client.post("/api/github/pull", json={
        "resolutions": {
            "policies": {"conflict_policy": "keep_github"},
            "log_profiles": {"conflict_log": "keep_github"},
        }
    })
    assert res_keep_github.status_code == 200, res_keep_github.text
    data_kg = res_keep_github.json()
    assert "conflict_policy" in data_kg["policies_pulled"]
    assert "conflict_log" in data_kg["log_profiles_pulled"]

    # Verify Redis copy was overwritten by GitHub and is no longer dirty
    pol_from_gh = gh_store.get_policy("conflict_policy")
    assert pol_from_gh["policy"]["description"] == "Remote GitHub policy copy"
    assert gh_store._is_dirty("conflict_policy") is False

    log_from_gh = gh_log_store.get_profile("conflict_log")
    assert log_from_gh["filter"]["description"] == "Remote GitHub logging profile"
    assert gh_log_store._is_dirty("conflict_log") is False


def test_push_to_github_verbose_commit_description(mock_github):
    """Verify that committing a policy or log profile to GitHub auto-generates a verbose commit description."""
    from f5_waf_editor.app import app
    test_client = TestClient(app)

    transport, client = mock_github

    initial_policy = {
        "policy": {
            "name": "verbose_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "transparent",
            "server-technologies": [{"serverTechnologyName": "Apache"}],
        }
    }
    transport.add_file("policies/verbose_policy.json", json.dumps(initial_policy), sha="sha_verbose_pol_1")

    init_storage(force_memory=True)
    init_github_storage(
        owner="f5-corp",
        repo="nginx-waf-gitops",
        token="ghp_test_verbose",
        branch="main",
        transport=transport,
        auto_pull=False,
    )
    gh_store = get_storage()

    # Edit policy in Redis draft
    updated_policy = {
        "policy": {
            "name": "verbose_policy",
            "template": {"name": "POLICY_TEMPLATE_COMPREHENSIVE"},
            "enforcementMode": "blocking",
            "server-technologies": [
                {"serverTechnologyName": "Nginx"},
                {"serverTechnologyName": "PHP"},
            ],
            "urls": [{"name": "/api/v1/auth"}],
        }
    }
    gh_store.save_policy("verbose_policy", updated_policy, pre_validated=True)
    assert gh_store._is_dirty("verbose_policy") is True

    # Commit without custom message (or default)
    res = test_client.post("/api/policies/verbose_policy/github-push", json={})
    assert res.status_code == 200, res.text
    data = res.json()
    assert "commit" in data

    # Verify the commit message sent to GitHub client
    recorded_commits = transport.commits
    assert len(recorded_commits) > 0
    latest_commit = recorded_commits[-1]
    msg = latest_commit["message"]
    assert "feat(waf): update policy 'verbose_policy'" in msg
    assert "Changes:" in msg
    assert "- Enforcement mode: changed from 'transparent' to 'blocking'" in msg
    assert "- Base template: changed from 'POLICY_TEMPLATE_NGINX_BASE' to 'POLICY_TEMPLATE_COMPREHENSIVE'" in msg
    assert "Server technologies: added" in msg
    assert "URLs: added" in msg


    # Cleanup
    init_storage(force_memory=True)

