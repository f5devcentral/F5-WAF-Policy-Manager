"""
Integration tests for FastAPI REST API endpoints.
"""

import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest
from f5_waf_editor.app import app
from f5_waf_editor.storage import init_storage


@pytest.fixture(autouse=True)
def setup_storage():
    # Force fresh in-memory storage for test isolation
    init_storage(force_memory=True)


@pytest.fixture
def client():
    return TestClient(app)


def test_list_policies(client):
    res = client.get("/api/policies")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 4


def test_get_policy_details(client):
    res = client.get("/api/policies/app_protect_default_policy")
    assert res.status_code == 200
    data = res.json()
    assert data["policy"]["name"] == "app_protect_default_policy"
    assert data["policy"]["enforcementMode"] == "blocking"


def test_create_and_delete_policy(client):
    new_policy = {
        "name": "microservice_gateway",
        "template_id": "api_security",
    }
    # Create
    create_res = client.post("/api/policies", json=new_policy)
    assert create_res.status_code == 201
    assert create_res.json()["metadata"]["name"] == "microservice_gateway"

    # Verify exists
    get_res = client.get("/api/policies/microservice_gateway")
    assert get_res.status_code == 200
    assert get_res.json()["policy"]["name"] == "microservice_gateway"

    # Delete
    del_res = client.delete("/api/policies/microservice_gateway")
    assert del_res.status_code == 200

    # Verify gone
    get_res404 = client.get("/api/policies/microservice_gateway")
    assert get_res404.status_code == 404


def test_clone_policy(client):
    clone_req = {"new_name": "app_protect_default_v2"}
    res = client.post("/api/policies/app_protect_default_policy/clone", json=clone_req)
    assert res.status_code == 200
    assert res.json()["metadata"]["name"] == "app_protect_default_v2"

    # Check cloned content
    cloned = client.get("/api/policies/app_protect_default_v2").json()
    assert cloned["policy"]["name"] == "app_protect_default_v2"


def test_validate_endpoint(client):
    valid_payload = {
        "content": {
            "policy": {
                "name": "valid_test",
                "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            }
        }
    }
    res = client.post("/api/policies/validate", json=valid_payload)
    assert res.status_code == 200
    assert res.json()["valid"] is True

    invalid_payload = {
        "content": {
            "name": "missing_policy_wrapper"
        }
    }
    res_inv = client.post("/api/policies/validate", json=invalid_payload)
    assert res_inv.status_code == 200
    assert res_inv.json()["valid"] is False


def test_redis_health_endpoint(client):
    res = client.get("/api/redis/status")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "backend" in data


def test_html_ui_serves(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "F5 WAF & Logging Manager" in res.text


def test_policies_and_log_profiles_segregation(client):
    # 1. Create a logging profile
    log_res = client.post(
        "/api/log-profiles",
        json={"name": "test_profile_segregation", "template_id": "log_default"},
    )
    assert log_res.status_code == 201

    # 2. List policies: must NOT contain test_profile_segregation or any log: prefix
    pol_res = client.get("/api/policies")
    assert pol_res.status_code == 200
    policies = pol_res.json()
    for p in policies:
        assert not p["name"].startswith("log:")
        assert p["name"] != "test_profile_segregation"

    # 3. List log profiles: must contain test_profile_segregation
    logs_res = client.get("/api/log-profiles")
    assert logs_res.status_code == 200
    log_names = [lp["name"] for lp in logs_res.json()]
    assert "test_profile_segregation" in log_names

    # 4. Cannot create a WAF policy with log: prefix
    bad_pol_res = client.post(
        "/api/policies",
        json={"name": "log:bad_policy_prefix", "template_id": "default"},
    )
    assert bad_pol_res.status_code == 400

    # Cleanup
    client.delete("/api/log-profiles/test_profile_segregation")


def test_catalog_server_technologies(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "serverTechnologies" in data
    techs = data["serverTechnologies"]
    assert len(techs) >= 17
    tech_names = [t["name"] for t in techs]
    assert "Nginx" in tech_names
    assert "Apache/NCSA HTTP Server" in tech_names or any("Apache" in t for t in tech_names)
    assert "Python" in tech_names
    assert "Unix/Linux" in tech_names
    assert "MySQL" in tech_names


def test_policy_crud_with_server_technologies(client):
    # 1. Create a policy
    create_res = client.post(
        "/api/policies",
        json={"name": "test_server_tech_policy", "template_id": "default"},
    )
    assert create_res.status_code == 201

    # 2. Update with server-technologies
    policy_doc = {
        "policy": {
            "name": "test_server_tech_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "server-technologies": [
                {"serverTechnologyName": "Nginx"},
                {"serverTechnologyName": "Unix/Linux"},
                {"serverTechnologyName": "Python"},
            ],
        }
    }
    update_res = client.put("/api/policies/test_server_tech_policy", json={"content": policy_doc})
    assert update_res.status_code == 200
    meta = update_res.json()["metadata"]
    assert meta["serverTechCount"] == 3

    # 3. Retrieve policy details
    get_res = client.get("/api/policies/test_server_tech_policy")
    assert get_res.status_code == 200
    doc = get_res.json()
    assert len(doc["policy"]["server-technologies"]) == 3
    names = [t["serverTechnologyName"] for t in doc["policy"]["server-technologies"]]
    assert "Nginx" in names
    assert "Unix/Linux" in names

    # 4. Cleanup
    del_res = client.delete("/api/policies/test_server_tech_policy")
    assert del_res.status_code == 200


def test_catalog_signature_sets(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "signatureSets" in data
    assert len(data["signatureSets"]) >= 30
    names = [s["name"] for s in data["signatureSets"]]
    assert "High Accuracy Signatures" in names
    assert "SQL Injection Signatures" in names
    assert "Path Traversal Signatures" in names
    assert "Command Execution Signatures" in names
    assert "Threat Campaigns" not in names  # Threat Campaigns is a violation, not a signature set


def test_policy_crud_with_signature_sets_and_exceptions(client):
    policy_name = "test_sig_policy"

    # 1. Create a policy
    create_res = client.post(
        "/api/policies",
        json={"name": policy_name, "template_id": "default"},
    )
    assert create_res.status_code == 201

    # 2. Update with signature-sets and exceptions
    policy_doc = {
        "policy": {
            "name": policy_name,
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "signature-sets": [
                {
                    "name": "High Accuracy Signatures",
                    "alarm": True,
                    "block": True,
                },
                {
                    "name": "SQL Injection Signatures",
                    "alarm": True,
                    "block": True,
                },
            ],
            "signatures": [
                {
                    "signatureId": 200001475,
                    "enabled": False,
                    "tag": "False positive in legacy search endpoint",
                }
            ],
        }
    }
    update_res = client.put(f"/api/policies/{policy_name}", json={"content": policy_doc})
    assert update_res.status_code == 200
    meta = update_res.json()["metadata"]
    assert meta["signatureSetsCount"] == 2
    assert meta["signaturesCount"] == 1

    # 3. Retrieve policy details
    get_res = client.get(f"/api/policies/{policy_name}")
    assert get_res.status_code == 200
    doc = get_res.json()
    assert len(doc["policy"]["signature-sets"]) == 2
    assert doc["policy"]["signature-sets"][0]["name"] == "High Accuracy Signatures"
    assert doc["policy"]["signature-sets"][0]["alarm"] is True
    assert doc["policy"]["signature-sets"][0]["block"] is True
    assert len(doc["policy"]["signatures"]) == 1
    assert doc["policy"]["signatures"][0]["signatureId"] == 200001475
    assert doc["policy"]["signatures"][0]["enabled"] is False

    # 4. Cleanup
    del_res = client.delete(f"/api/policies/{policy_name}")
    assert del_res.status_code == 200


def test_catalog_includes_openapi_recommended_violations(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "openApiRecommendedViolations" in data
    assert len(data["openApiRecommendedViolations"]) >= 15
    assert any(v["name"] == "VIOL_JSON_SCHEMA" for v in data["openApiRecommendedViolations"])


def test_test_openapi_link_local_file(client, tmp_path):
    # Create a minimal valid OpenAPI YAML file
    spec_content = """openapi: 3.0.0
info:
  title: Pet Test Store
  version: 1.0.0
  description: Test OpenAPI specification for F5 WAF for NGINX
paths:
  /pets:
    get:
      summary: List all pets
    post:
      summary: Create a pet
  /pets/{petId}:
    get:
      summary: Info for a specific pet
components:
  schemas:
    Pet:
      type: object
      required:
        - id
        - name
      properties:
        id:
          type: integer
        name:
          type: string
"""
    spec_file = tmp_path / "test_spec.yaml"
    spec_file.write_text(spec_content, encoding="utf-8")

    # Local file test
    file_uri = f"file:///{spec_file.as_posix()}"
    res = client.post("/api/policies/test-openapi-link", json={"link": file_uri})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["validSpec"] is True
    assert data["title"] == "Pet Test Store"
    assert data["version"] == "1.0.0"
    assert data["pathsCount"] == 2
    assert data["schemasCount"] == 1
    assert "/pets" in data["samplePaths"]


def test_test_openapi_link_invalid_scheme(client):
    res = client.post("/api/policies/test-openapi-link", json={"link": "ftp://files.example.com/spec.yaml"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "Unsupported URI scheme" in data["error"]


def test_policy_crud_with_openapi_reference(client):
    policy_name = "openapi_protected_api"
    policy_doc = {
        "policy": {
            "name": policy_name,
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "open-api-files": [
                {
                    "link": "https://example.com/openapi.yaml"
                }
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_JSON_SCHEMA", "alarm": True, "block": True},
                    {"name": "VIOL_MANDATORY_REQUEST_BODY", "alarm": True, "block": True},
                ]
            },
        }
    }

    # 1. Create policy
    create_res = client.post("/api/policies", json={"name": policy_name, "content": policy_doc})
    assert create_res.status_code == 201
    meta = create_res.json()["metadata"]
    assert meta["hasOpenApi"] is True
    assert "openapi.yaml" in meta["openApiLink"]

    # 2. List policies and check metadata
    list_res = client.get("/api/policies")
    assert list_res.status_code == 200
    policies = list_res.json()
    found = next((p for p in policies if p["name"] == policy_name), None)
    assert found is not None
    assert found["hasOpenApi"] is True
    assert found["openApiType"] == "url"

    # 3. Retrieve policy details
    get_res = client.get(f"/api/policies/{policy_name}")
    assert get_res.status_code == 200
    details = get_res.json()
    assert "open-api-files" in details["policy"]
    assert details["policy"]["open-api-files"][0]["link"] == "https://example.com/openapi.yaml"

    # 4. Clean up
    del_res = client.delete(f"/api/policies/{policy_name}")
    assert del_res.status_code == 200


def test_catalog_grpc_items(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "grpcRecommendedViolations" in data
    assert len(data["grpcRecommendedViolations"]) >= 3
    rec_names = [v["name"] for v in data["grpcRecommendedViolations"]]
    assert "VIOL_GRPC_MALFORMED" in rec_names
    assert "VIOL_GRPC_FORMAT" in rec_names
    assert "VIOL_GRPC_METHOD" in rec_names
    assert "grpcSamples" in data
    assert len(data["grpcSamples"]) >= 2


def test_test_grpc_idl_single_proto(client):
    proto_path = Path(__file__).resolve().parent.parent / "examples" / "grpc" / "album.proto"
    file_uri = proto_path.as_uri()

    res = client.post("/api/policies/test-grpc-idl", json={"link": file_uri})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["isArchive"] is False
    assert data["syntax"] == "proto3"
    assert data["isProto3"] is True
    assert data["packageName"] == "album.v1"
    assert data["servicesCount"] == 1
    assert data["services"][0]["name"] == "AlbumService"
    assert "GetAlbum" in data["services"][0]["methods"]
    assert "ListAlbums" in data["services"][0]["methods"]
    assert "CreateAlbum" in data["services"][0]["methods"]
    assert "Album" in data["messages"]


def test_test_grpc_idl_archive_tgz(client):
    tgz_path = Path(__file__).resolve().parent.parent / "examples" / "grpc" / "album_service_files.tgz"
    file_uri = tgz_path.as_uri()

    res = client.post(
        "/api/policies/test-grpc-idl",
        json={"link": file_uri, "primaryIdlFileName": "album_service.proto"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["isArchive"] is True
    assert data["syntax"] == "proto3"
    assert data["isProto3"] is True
    assert data["primaryIdlFileName"] == "album_service.proto"
    assert data["servicesCount"] == 1
    assert data["services"][0]["name"] == "AlbumService"
    assert len(data["protoFiles"]) >= 2


def test_test_grpc_idl_invalid_file(client):
    res = client.post(
        "/api/policies/test-grpc-idl",
        json={"link": "file:///non/existent/path/service.proto"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "Local file not found" in data["error"]


def test_policy_crud_with_grpc_protection(client):
    policy_name = "grpc_protected_microservice"
    policy_doc = {
        "policy": {
            "name": policy_name,
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "grpc-profiles": [
                {
                    "name": "album_profile",
                    "description": "gRPC protection for album service",
                    "associateUrls": True,
                    "attackSignaturesCheck": True,
                    "metacharCheck": True,
                    "decodeStringValuesAsBase64": "disabled",
                    "defenseAttributes": {
                        "maximumDataLength": 100000,
                        "allowUnknownFields": False,
                    },
                    "idlFiles": [
                        {
                            "idlFile": {
                                "$ref": "file:///examples/grpc/album.proto"
                            },
                            "isPrimary": True,
                        }
                    ],
                }
            ],
            "blocking-settings": {
                "violations": [
                    {"name": "VIOL_GRPC_MALFORMED", "alarm": True, "block": True},
                    {"name": "VIOL_GRPC_FORMAT", "alarm": True, "block": True},
                    {"name": "VIOL_GRPC_METHOD", "alarm": True, "block": True},
                ]
            },
        }
    }

    # 1. Create policy
    create_res = client.post("/api/policies", json={"name": policy_name, "content": policy_doc})
    assert create_res.status_code == 201
    meta = create_res.json()["metadata"]
    assert meta["hasGrpc"] is True
    assert meta["grpcProfilesCount"] == 1
    assert "album.proto" in meta["grpcPrimaryIdl"]
    assert meta["grpcFileType"] == "proto"

    # 2. List policies and check metadata
    list_res = client.get("/api/policies")
    assert list_res.status_code == 200
    policies = list_res.json()
    found = next((p for p in policies if p["name"] == policy_name), None)
    assert found is not None
    assert found["hasGrpc"] is True
    assert found["grpcFileType"] == "proto"

    # 3. Retrieve policy details
    get_res = client.get(f"/api/policies/{policy_name}")
    assert get_res.status_code == 200
    details = get_res.json()
    assert "grpc-profiles" in details["policy"]
    assert details["policy"]["grpc-profiles"][0]["name"] == "album_profile"

    # 4. Clean up
    del_res = client.delete(f"/api/policies/{policy_name}")
    assert del_res.status_code == 200


def test_catalog_returns_categories(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "categories" in data
    assert isinstance(data["categories"], list)
    assert len(data["categories"]) == 12
    assert "All Categories" in data["categories"]
    assert "Threats & Signatures" in data["categories"]
    assert "gRPC & Protocol Buffers" in data["categories"]
    assert "API & Formats" in data["categories"]


def test_inspect_grpc_upload_single_proto(client):
    import io
    proto_code = b"""syntax = "proto3";
package payments;

service PaymentService {
    rpc ProcessPayment (PaymentRequest) returns (PaymentResponse);
    rpc Refund (RefundRequest) returns (RefundResponse);
}

message PaymentRequest {
    string order_id = 1;
    double amount = 2;
}

message PaymentResponse {
    bool success = 1;
    string transaction_id = 2;
}
"""
    file_bytes = io.BytesIO(proto_code)
    res = client.post(
        "/api/policies/inspect-grpc-upload",
        files={"file": ("payments.proto", file_bytes, "application/octet-stream")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["syntax"] == "proto3"
    assert data["isProto3"] is True
    assert data["isArchive"] is False
    assert data["servicesCount"] == 1
    assert data["services"][0]["name"] == "PaymentService"
    assert "ProcessPayment" in data["services"][0]["methods"]
    assert "Refund" in data["services"][0]["methods"]
    assert "PaymentRequest" in data["messages"]


def test_inspect_grpc_upload_tarball_archive(client):
    import io
    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        proto_content = b"""syntax = "proto3";
package users;

service UserService {
    rpc GetUser (UserRequest) returns (UserResponse);
}

message UserRequest {
    string user_id = 1;
}

message UserResponse {
    string name = 1;
    string email = 2;
}
"""
        tarinfo = tarfile.TarInfo(name="users.proto")
        tarinfo.size = len(proto_content)
        tar.addfile(tarinfo, io.BytesIO(proto_content))

    tar_buf.seek(0)
    res = client.post(
        "/api/policies/inspect-grpc-upload",
        files={"file": ("bundle.tar.gz", tar_buf, "application/gzip")},
        data={"primaryIdlFileName": "users.proto"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["isArchive"] is True
    assert data["primaryIdlFileName"] == "users.proto"
    assert "users.proto" in data["protoFiles"]
    assert data["servicesCount"] == 1
    assert data["services"][0]["name"] == "UserService"
    assert "GetUser" in data["services"][0]["methods"]


def test_inspect_grpc_upload_oversized(client):
    import io
    # 11MB file (exceeds 10MB limit)
    oversized = io.BytesIO(b"0" * (11 * 1024 * 1024))
    res = client.post(
        "/api/policies/inspect-grpc-upload",
        files={"file": ("huge.proto", oversized, "application/octet-stream")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "exceeds the 10MB buffer limit" in data["error"]


def test_test_openapi_link_options(client):
    # Test payload containing self-signed SSL bypass and authType
    res = client.post(
        "/api/policies/test-openapi-link",
        json={
            "link": "https://127.0.0.1:54321/spec.yaml",
            "allowSelfSigned": True,
            "authType": "bearer",
            "bearerToken": "secret_token_123",
        },
    )
    assert res.status_code == 200
    data = res.json()
    # Host is intentionally not running, verify handled gracefully
    assert data["success"] is False
    assert "error" in data


def test_test_openapi_link_basic_auth_success(client):
    import base64
    import http.server
    import json
    import threading

    class AuthServer(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            expected = "Basic " + base64.b64encode(b"admin:secr3t!").decode("ascii")
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="WafApi"')
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.1",
                "info": {"title": "Secure API", "version": "2.0.0"},
                "paths": {"/secure-data": {"get": {"summary": "Fetch data"}}},
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), AuthServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        url = f"http://127.0.0.1:{port}/spec.json"
        # 1. Clear password
        res = client.post(
            "/api/policies/test-openapi-link",
            json={
                "link": url,
                "authType": "basic",
                "basicAuth": {"user": "admin", "password": "secr3t!"},
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["validSpec"] is True
        assert data["title"] == "Secure API"
        assert data["pathsCount"] == 1

        # 2. Base64 password
        pwd_b64 = base64.b64encode(b"secr3t!").decode("ascii")
        res2 = client.post(
            "/api/policies/test-openapi-link",
            json={
                "link": url,
                "authType": "basic",
                "basicAuth": {"user": "admin", "passwordBase64": pwd_b64},
            },
        )
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["success"] is True
        assert data2["title"] == "Secure API"

        # 3. Wrong credentials
        res3 = client.post(
            "/api/policies/test-openapi-link",
            json={
                "link": url,
                "authType": "basic",
                "basicAuth": {"user": "admin", "password": "wrong_password"},
            },
        )
        assert res3.status_code == 200
        data3 = res3.json()
        assert data3["success"] is False
        assert "401" in data3["error"]
        assert "Server rejected credentials" in data3["error"]
    finally:
        server.shutdown()


def test_catalog_violations_and_categories(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    catalog = res.json()
    assert "categories" in catalog
    assert "violations" in catalog
    assert len(catalog["categories"]) == 12
    assert "All Categories" in catalog["categories"]
    assert "Threats & Signatures" in catalog["categories"]
    assert "HTTP Compliance" in catalog["categories"]
    assert "Buffer & Sizing" in catalog["categories"]
    assert "gRPC & Protocol Buffers" in catalog["categories"]

    assert len(catalog["violations"]) == 55
    # Every violation category must be one of the catalog categories
    for v in catalog["violations"]:
        assert v["category"] in catalog["categories"], f"Violation {v['name']} has invalid category {v['category']}"


def test_test_openapi_link_large_spec(client, tmp_path):
    # Generate a large OpenAPI spec (> 2.5 MB) with tens of thousands of lines
    large_spec_path = tmp_path / "large_spec.json"
    
    paths = {}
    for i in range(15000):
        paths[f"/resource_{i}"] = {
            "get": {
                "summary": f"Retrieve resource number {i}",
                "operationId": f"getResource{i}",
                "responses": {
                    "200": {
                        "description": f"Successful response for resource {i}"
                    }
                }
            }
        }
    
    import json
    large_spec_data = {
        "openapi": "3.0.3",
        "info": {
            "title": "Enterprise Microservices Large API",
            "version": "2.4.0",
            "description": "Enterprise scale API specification with over 15,000 routes."
        },
        "paths": paths
    }
    
    with open(large_spec_path, "w", encoding="utf-8") as f:
        json.dump(large_spec_data, f)
    
    file_size_mb = large_spec_path.stat().st_size / (1024 * 1024)
    assert file_size_mb > 2.0, f"Spec size {file_size_mb:.2f}MB was not > 2MB"

    # Test inspection via file URI
    res = client.post(
        "/api/policies/test-openapi-link",
        json={"link": large_spec_path.as_uri()}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True, f"Failed with: {data.get('error')}"
    assert data["openApiVersion"] == "3.0.3"
    assert data["version"] == "2.4.0"
    assert data["title"] == "Enterprise Microservices Large API"
    assert data["pathsCount"] == 15000


def test_bot_defense_enabled_in_policy_list(client):
    # Verify default policy has bot defense enabled
    res = client.get("/api/policies")
    assert res.status_code == 200
    policies = res.json()
    default_p = next((p for p in policies if p["name"] == "app_protect_default_policy"), None)
    assert default_p is not None
    assert default_p["botDefenseEnabled"] is True

    # Create a policy without bot defense
    new_policy = {
        "name": "api_no_bot_policy",
        "template_id": "api_security",
    }
    client.post("/api/policies", json=new_policy)

    # Check it shows disabled
    res2 = client.get("/api/policies")
    p_nobot = next((p for p in res2.json() if p["name"] == "api_no_bot_policy"), None)
    assert p_nobot is not None
    assert p_nobot["botDefenseEnabled"] is False

    # Now update it to enable bot defense
    policy_detail = client.get("/api/policies/api_no_bot_policy").json()
    policy_detail["policy"]["bot-defense"] = {
        "settings": {
            "isEnabled": True
        }
    }
    update_res = client.put("/api/policies/api_no_bot_policy", json={"content": policy_detail})
    assert update_res.status_code == 200

    # Verify it now shows botDefenseEnabled is True in policy list
    res3 = client.get("/api/policies")
    p_updated = next((p for p in res3.json() if p["name"] == "api_no_bot_policy"), None)
    assert p_updated is not None
    assert p_updated["botDefenseEnabled"] is True


def test_catalog_includes_attack_signatures(client):
    res = client.get("/api/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "attackSignatures" in data
    sigs = data["attackSignatures"]
    assert len(sigs) >= 50
    sample = sigs[0]
    assert "signatureId" in sample
    assert "name" in sample
    assert "attackType" in sample
    assert "accuracy" in sample
    assert "risk" in sample
    assert isinstance(sample["signatureId"], int)


def test_get_signatures_for_signature_set(client):
    # 1. High Accuracy standard set
    res = client.get("/api/signature-sets/High Accuracy Signatures/signatures")
    assert res.status_code == 200
    data = res.json()
    assert data["setName"] == "High Accuracy Signatures"
    assert data["total"] > 0
    assert all(s["accuracy"] == "High" for s in data["signatures"])

    # 2. Specific attack type set
    res_sql = client.get("/api/signature-sets/SQL Injection Signatures/signatures")
    assert res_sql.status_code == 200
    data_sql = res_sql.json()
    assert data_sql["total"] >= 5
    assert any(s["signatureId"] == 200001475 for s in data_sql["signatures"])

    # 3. Search filter
    res_search = client.get("/api/signature-sets/Threat Campaigns/signatures?search=CVE-2021-44228")
    assert res_search.status_code == 200
    data_search = res_search.json()
    assert data_search["total"] == 1
    assert data_search["signatures"][0]["signatureId"] == 300001001
    assert "Log4j" in data_search["signatures"][0]["name"]

    # 4. Accuracy and risk filtering
    res_filt = client.get("/api/signature-sets/High Accuracy Signatures/signatures?risk=Critical")
    assert res_filt.status_code == 200
    data_filt = res_filt.json()
    assert data_filt["total"] > 0
def test_policy_crud_with_urls_and_parameters(client):
    policy_payload = {
        "policy": {
            "name": "test_urls_params_policy",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "urls": [
                {"name": "/api/v1/auth/login", "type": "explicit"},
                {"name": "/static/*", "type": "wildcard"},
                {"name": "/media/*", "type": "wildcard"},
            ],
            "parameters": [
                {
                    "name": "session_token",
                    "type": "header",
                    "dataType": "string",
                    "sensitive": True,
                },
                {
                    "name": "page_id",
                    "type": "query",
                    "dataType": "integer",
                    "sensitive": False,
                },
                {
                    "name": "remember_me",
                    "type": "cookie",
                    "dataType": "boolean",
                    "sensitive": False,
                },
            ],
            "methods": [
                {"name": "GET"},
                {"name": "POST"},
                {"name": "OPTIONS"},
            ],
        }
    }

    # Create policy
    create_res = client.post("/api/policies", json={"name": "test_urls_params_policy", "content": policy_payload})
    assert create_res.status_code == 201
    create_data = create_res.json()["metadata"]
    assert create_data["name"] == "test_urls_params_policy"
    assert create_data["urlsCount"] == 3
    assert create_data["parametersCount"] == 3

    # Fetch policy details
    get_res = client.get("/api/policies/test_urls_params_policy")
    assert get_res.status_code == 200
    p = get_res.json()["policy"]
    assert len(p["urls"]) == 3
    assert p["urls"][0]["name"] == "/api/v1/auth/login"
    assert p["urls"][0]["type"] == "explicit"
    assert p["urls"][1]["type"] == "wildcard"

    assert len(p["parameters"]) == 3
    assert p["parameters"][0]["name"] == "session_token"
    assert p["parameters"][0]["sensitive"] is True
    assert p["parameters"][0]["type"] == "header"
    assert p["parameters"][1]["dataType"] == "integer"
    assert p["parameters"][2]["type"] == "cookie"

    assert len(p["methods"]) == 3
    assert {m["name"] for m in p["methods"]} == {"GET", "POST", "OPTIONS"}

    # Cleanup
    del_res = client.delete("/api/policies/test_urls_params_policy")
    assert del_res.status_code == 200


def test_policy_rename_and_description_update(client):
    # 1. Create a baseline policy
    init_payload = {
        "policy": {
            "name": "orig_api_policy",
            "description": "Initial policy description",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
        }
    }
    create_res = client.post("/api/policies", json={"name": "orig_api_policy", "content": init_payload})
    assert create_res.status_code == 201

    # Verify initial creation
    get_res = client.get("/api/policies/orig_api_policy")
    assert get_res.status_code == 200
    assert get_res.json()["policy"]["name"] == "orig_api_policy"
    assert get_res.json()["policy"]["description"] == "Initial policy description"

    # 2. Rename via PUT /api/policies/{old_name} with new name and description in content
    renamed_payload = {
        "policy": {
            "name": "renamed_api_policy",
            "description": "Updated policy description with more details",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "transparent",
        }
    }
    put_res = client.put("/api/policies/orig_api_policy", json={"content": renamed_payload})
    assert put_res.status_code == 200
    put_data = put_res.json()
    assert put_data["renamed"] is True
    assert put_data["old_name"] == "orig_api_policy"
    assert put_data["new_name"] == "renamed_api_policy"
    assert put_data["metadata"]["name"] == "renamed_api_policy"
    assert put_data["metadata"]["description"] == "Updated policy description with more details"

    # Old policy should no longer exist
    old_res = client.get("/api/policies/orig_api_policy")
    assert old_res.status_code == 404

    # New policy exists
    new_res = client.get("/api/policies/renamed_api_policy")
    assert new_res.status_code == 200
    assert new_res.json()["policy"]["name"] == "renamed_api_policy"
    assert new_res.json()["policy"]["description"] == "Updated policy description with more details"
    assert new_res.json()["policy"]["enforcementMode"] == "transparent"

    # 3. Rename via PUT /api/policies/{new_name} supplying original_name in body
    second_rename_payload = {
        "policy": {
            "name": "final_api_policy",
            "description": "Final description",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
        }
    }
    put_res2 = client.put(
        "/api/policies/final_api_policy",
        json={"content": second_rename_payload, "original_name": "renamed_api_policy"},
    )
    assert put_res2.status_code == 200
    assert put_res2.json()["renamed"] is True
    assert put_res2.json()["new_name"] == "final_api_policy"

    # 4. Attempt rename to conflict with another policy
    client.post(
        "/api/policies",
        json={
            "name": "collision_target_policy",
            "content": {
                "policy": {
                    "name": "collision_target_policy",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                }
            },
        },
    )
    conflict_res = client.put(
        "/api/policies/final_api_policy",
        json={
            "content": {
                "policy": {
                    "name": "collision_target_policy",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                }
            }
        },
    )
    assert conflict_res.status_code == 409

    # 5. Attempt rename with invalid name characters (e.g. spaces)
    invalid_res = client.put(
        "/api/policies/final_api_policy",
        json={
            "content": {
                "policy": {
                    "name": "invalid name with spaces",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                }
            }
        },
    )
    assert invalid_res.status_code == 422

    # 6. Attempt rename with reserved log: prefix
    log_res = client.put(
        "/api/policies/final_api_policy",
        json={
            "content": {
                "policy": {
                    "name": "log:my_log_profile",
                    "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
                }
            }
        },
    )
    assert log_res.status_code == 400

    # 7. Explicit rename endpoint POST /api/policies/{name}/rename
    post_rename_res = client.post(
        "/api/policies/final_api_policy/rename",
        json={"new_name": "post_renamed_policy"},
    )
    assert post_rename_res.status_code == 200
    assert post_rename_res.json()["renamed"] is True
    assert post_rename_res.json()["new_name"] == "post_renamed_policy"

    # Cleanup
    client.delete("/api/policies/post_renamed_policy")
    client.delete("/api/policies/collision_target_policy")


def test_bigip_policy_conversion_success_and_save(client):
    """Test converting BIG-IP JSON policy export and saving directly to storage."""
    sample_json = {
        "name": "bigip_prod_export",
        "description": "Production BIG-IP ASM security policy exported for migration",
        "enforcementMode": "blocking",
        "applicationLanguage": "utf-8",
        "blockingSettings": {
            "violations": [
                {"name": "VIOL_ATTACK_SIGNATURE", "alarm": True, "block": True},
                {"name": "VIOL_CSRF", "alarm": True, "block": False},
            ]
        },
        "urls": [
            {"name": "/api/v1/checkout", "type": "explicit", "method": "POST", "protocol": "https"},
            {"name": "/login", "type": "explicit", "method": "POST", "protocol": "all"},
        ],
        "parameters": [
            {"name": "session_token", "type": "explicit", "valueType": "alpha-numeric"},
        ],
        "signatureSets": [
            {"name": "Generic Detection Signatures", "alarm": True, "block": True},
        ],
        "signatures": [
            {"signatureId": 200001475, "enabled": False},
        ],
        "serverTechnologies": [
            {"serverTechnologyName": "Nginx"},
            {"serverTechnologyName": "Linux"},
        ],
    }
    raw_payload = json.dumps(sample_json).encode("utf-8")

    # 1. Convert without custom target name (uses JSON name "bigip_prod_export")
    res = client.post(
        "/api/policies/convert-bigip",
        files={"file": ("export.json", raw_payload, "application/json")},
        data={"save_to_storage": "true", "full_export": "true"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["policy_name"] == "bigip_prod_export"
    assert "warnings" in data
    # VIOL_CSRF is unsupported in F5 WAF for NGINX base catalog, so a warning should be registered
    assert any("VIOL_CSRF" in w for w in data["warnings"])
    assert data["saved"] is True

    # 2. Verify policy exists in storage and is valid F5 WAF for NGINX format
    get_res = client.get("/api/policies/bigip_prod_export")
    assert get_res.status_code == 200
    saved_doc = get_res.json()["policy"]
    assert saved_doc["name"] == "bigip_prod_export"
    assert saved_doc["enforcementMode"] == "blocking"
    assert len(saved_doc["urls"]) == 2
    assert len(saved_doc["parameters"]) == 1
    assert saved_doc["parameters"][0]["name"] == "session_token"
    assert len(saved_doc["server-technologies"]) == 2

    # Cleanup
    client.delete("/api/policies/bigip_prod_export")


def test_bigip_policy_conversion_invalid_json(client):
    """Test error handling when uploaded file is neither valid JSON nor XML."""
    bad_content = b"THIS IS NOT JSON OR XML CONTENT AT ALL { invalid: json"
    res = client.post(
        "/api/policies/convert-bigip",
        files={"file": ("corrupt.json", bad_content, "application/json")},
    )
    assert res.status_code == 422
    assert "JSON" in res.json()["detail"] or "syntax" in res.json()["detail"].lower()


def test_compiler_status(client):
    """Test getting status and availability of the F5 WAF compiler."""
    res = client.get("/api/compiler/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "version" in data
    assert "engine" in data
    assert "cli_available" in data


def test_compiler_policy_success_and_download_bundle(client):
    """Test compiling a valid policy, generating a .tgz bundle and downloading it."""
    policy_name = "test_compile_success_pol"

    # Create policy in storage
    create_res = client.post(
        "/api/policies",
        json={"name": policy_name, "template_id": "default"},
    )
    assert create_res.status_code == 201

    # Test compiler on stored policy
    test_res = client.post(
        "/api/compiler/test",
        json={"target_type": "policy", "target_name": policy_name, "include_source": True},
    )
    assert test_res.status_code == 200
    result = test_res.json()
    assert result["success"] is True
    assert result["target_name"] == policy_name
    assert result["bundle_name"] is not None
    assert result["bundle_id"] is not None
    assert result["bundle_size"] > 0
    assert result["bundle_sha256"] is not None
    assert len(result["errors"]) == 0

    # Test downloading the bundle archive
    bundle_id = result["bundle_id"]
    download_res = client.get(f"/api/compiler/download/{bundle_id}")
    assert download_res.status_code == 200
    assert len(download_res.content) == result["bundle_size"]
    assert "gzip" in download_res.headers.get("content-type", "") or "tar" in download_res.headers.get("content-type", "")

    # Cleanup
    client.delete(f"/api/policies/{policy_name}")


def test_compiler_policy_failure_diagnostics(client):
    """Test compiler catching errors (e.g. duplicate endpoints and forbidden basicAuth)."""
    # Policy with duplicate URL endpoints and forbidden basicAuth
    invalid_policy_content = {
        "policy": {
            "name": "invalid_test_pol",
            "template": {"name": "POLICY_TEMPLATE_NGINX_BASE"},
            "enforcementMode": "blocking",
            "open-api-files": [
                {
                    "link": "https://example.com/spec.yaml",
                    "basicAuth": True,  # FORBIDDEN: basicAuth is not allowed in F5 WAF for NGINX OpenAPI schemas
                }
            ],
            "urls": [
                {"name": "/api/users", "type": "explicit", "method": "GET"},
                {"name": "/api/users", "type": "explicit", "method": "GET"},  # DUPLICATE
            ],
        }
    }

    test_res = client.post(
        "/api/compiler/test",
        json={
            "target_type": "policy",
            "target_name": "invalid_test_pol",
            "content": invalid_policy_content,
        },
    )
    assert test_res.status_code == 200
    result = test_res.json()
    assert result["success"] is False
    assert len(result["errors"]) >= 2

    # Check for basicAuth error
    basic_auth_err = next((e for e in result["errors"] if e["code"] == "ERR_OPENAPI_BASICAUTH_FORBIDDEN"), None)
    assert basic_auth_err is not None
    assert "basicAuth" in basic_auth_err["message"]
    assert basic_auth_err["solution"] is not None

    # Check for duplicate URL error
    dup_url_err = next((e for e in result["errors"] if e["code"] == "ERR_DUPLICATE_URL"), None)
    assert dup_url_err is not None
    assert "/api/users" in dup_url_err["message"]
    assert dup_url_err["solution"] is not None


def test_compiler_log_profile_success_and_failure(client):
    """Test compiler validation on valid and invalid logging profiles."""
    profile_name = "test_compile_log_prof"

    # 1. Create a valid logging profile in storage
    create_res = client.post(
        "/api/log-profiles",
        json={"name": profile_name, "template_id": "log_default"},
    )
    assert create_res.status_code == 201

    # 2. Test compiler on valid logging profile
    test_res = client.post(
        "/api/compiler/test",
        json={"target_type": "log_profile", "target_name": profile_name},
    )
    assert test_res.status_code == 200
    result = test_res.json()
    assert result["success"] is True
    assert result["bundle_name"] == f"{profile_name}_compiled.tgz"
    assert result["bundle_id"] is not None

    # 3. Test compiler on invalid logging profile content (missing format and invalid request_type)
    invalid_lp = {
        "filter": {
            "request_type": "completely_invalid_type",
        },
        # Missing 'format' and missing 'filter.format'
    }
    test_fail_res = client.post(
        "/api/compiler/test",
        json={
            "target_type": "log_profile",
            "target_name": "invalid_lp",
            "content": invalid_lp,
        },
    )
    assert test_fail_res.status_code == 200
    fail_result = test_fail_res.json()
    assert fail_result["success"] is False
    assert len(fail_result["errors"]) >= 1

    # Cleanup
    client.delete(f"/api/log-profiles/{profile_name}")
