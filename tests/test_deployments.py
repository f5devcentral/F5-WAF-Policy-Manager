"""
Unit tests verifying Dockerfile, Docker Compose, and Helm Chart deployment files.
"""

from pathlib import Path
import re
import yaml


ROOT_DIR = Path(__file__).resolve().parent.parent
HELM_DIR = ROOT_DIR / "helm" / "f5-waf-policy-manager"
TEMPLATES_DIR = HELM_DIR / "templates"


def test_dockerfile_configuration():
    dockerfile = ROOT_DIR / "Dockerfile"
    assert dockerfile.exists(), "Dockerfile must exist"
    content = dockerfile.read_text(encoding="utf-8")
    assert "EXPOSE 8000" in content
    assert "HEALTHCHECK" in content
    assert "ENTRYPOINT" in content
    assert "main.py" in content


def test_dockerignore_configuration():
    dockerignore = ROOT_DIR / ".dockerignore"
    assert dockerignore.exists(), ".dockerignore must exist"
    content = dockerignore.read_text(encoding="utf-8")
    assert ".git" in content
    assert ".venv" in content
    assert "__pycache__" in content


def test_docker_compose_validity():
    compose_path = ROOT_DIR / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)
    
    assert "services" in compose_data
    services = compose_data["services"]
    assert "waf-editor" in services
    assert "apcompile" in services
    assert "redis" in services
    
    # waf-editor checks
    editor = services["waf-editor"]
    assert "depends_on" in editor
    assert "healthcheck" in editor
    assert "ports" in editor
    assert "networks" in editor
    
    # apcompile checks
    apcompile = services["apcompile"]
    assert "healthcheck" in apcompile
    assert "ports" in apcompile
    assert "networks" in apcompile
    
    # redis checks
    redis = services["redis"]
    assert "healthcheck" in redis
    assert "volumes" in redis
    assert "redis-data" in compose_data.get("volumes", {})
    assert "networks" in compose_data


def test_compiler_dockerfile_configuration():
    compiler_dockerfile = ROOT_DIR / "Dockerfile.compiler"
    assert compiler_dockerfile.exists(), "Dockerfile.compiler must exist"
    content = compiler_dockerfile.read_text(encoding="utf-8")
    assert "EXPOSE 9000" in content
    assert "HEALTHCHECK" in content
    assert "ENTRYPOINT" in content
    assert "f5_waf_editor.compiler.server" in content


def test_helm_chart_yaml_validity():
    chart_path = HELM_DIR / "Chart.yaml"
    assert chart_path.exists(), "Chart.yaml must exist"
    
    with open(chart_path, "r", encoding="utf-8") as f:
        chart_data = yaml.safe_load(f)
    
    assert chart_data["apiVersion"] == "v2"
    assert chart_data["name"] == "f5-waf-policy-manager"
    assert "version" in chart_data
    assert "appVersion" in chart_data
    assert chart_data["type"] == "application"


def test_helm_values_yaml_validity():
    values_path = HELM_DIR / "values.yaml"
    assert values_path.exists(), "values.yaml must exist"
    
    with open(values_path, "r", encoding="utf-8") as f:
        values_data = yaml.safe_load(f)
    
    assert "replicaCount" in values_data
    assert "image" in values_data
    assert "repository" in values_data["image"]
    assert "service" in values_data
    assert values_data["service"]["port"] == 80
    assert values_data["service"]["targetPort"] == 8000
    assert "ingress" in values_data
    assert "resources" in values_data
    assert "probes" in values_data
    assert "config" in values_data
    assert "redis" in values_data
    assert values_data["redis"]["enabled"] is True
    assert "persistence" in values_data["redis"]
    assert "external" in values_data["redis"]


def test_helm_templates_exist():
    expected_templates = [
        "_helpers.tpl",
        "serviceaccount.yaml",
        "configmap.yaml",
        "secret.yaml",
        "deployment.yaml",
        "service.yaml",
        "ingress.yaml",
        "hpa.yaml",
        "redis-pvc.yaml",
        "redis-deployment.yaml",
        "redis-service.yaml",
        "NOTES.txt",
    ]
    
    for filename in expected_templates:
        tmpl_file = TEMPLATES_DIR / filename
        assert tmpl_file.exists(), f"Helm template {filename} must exist"
        content = tmpl_file.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Template {filename} must not be empty"


def test_helm_template_brace_matching():
    """Ensure Go template action delimiters are properly matched in each template."""
    for tmpl_file in TEMPLATES_DIR.glob("*.*"):
        content = tmpl_file.read_text(encoding="utf-8")
        open_count = len(re.findall(r"\{\{", content))
        close_count = len(re.findall(r"\}\}", content))
        assert open_count == close_count, (
            f"Mismatched {{ and }} in {tmpl_file.name}: {open_count} open vs {close_count} close"
        )
