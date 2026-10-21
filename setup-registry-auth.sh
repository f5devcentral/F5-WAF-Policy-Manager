#!/bin/bash
# ==============================================================================
# Setup Docker Client Certificate Authentication for private-registry.nginx.com
# ==============================================================================
# Docker requires client certificates to authenticate against private-registry.nginx.com.
# BuildKit build secrets (--secret) only mount inside RUN steps; they cannot authenticate
# the base image pull (FROM private-registry.nginx.com/...).
#
# Docker's engine strictly requires:
#   - Directory: /etc/docker/certs.d/private-registry.nginx.com/
#   - Client certificate file MUST have .cert extension: client.cert (NOT .crt!)
#   - Client key file MUST have .key extension: client.key
# ==============================================================================

set -e

CERT_SRC="${1:-/etc/ssl/nginx/nginx-repo.crt}"
KEY_SRC="${2:-/etc/ssl/nginx/nginx-repo.key}"
REGISTRY="private-registry.nginx.com"
DOCKER_CERTS_DIR="/etc/docker/certs.d/${REGISTRY}"
BASE_IMAGE="${REGISTRY}/nap/waf-compiler:latest"

echo "=================================================================="
echo "Configuring Docker authentication for ${REGISTRY}"
echo "=================================================================="

# Check if certificate and key exist
if [ ! -f "${CERT_SRC}" ]; then
    echo "ERROR: Certificate file '${CERT_SRC}' not found!"
    echo "Usage: $0 [path/to/nginx-repo.crt] [path/to/nginx-repo.key]"
    exit 1
fi

if [ ! -f "${KEY_SRC}" ]; then
    echo "ERROR: Private key file '${KEY_SRC}' not found!"
    echo "Usage: $0 [path/to/nginx-repo.crt] [path/to/nginx-repo.key]"
    exit 1
fi

echo "-> Creating Docker registry certificates directory: ${DOCKER_CERTS_DIR}"
sudo mkdir -p "${DOCKER_CERTS_DIR}"

echo "-> Installing client.cert (note: extension MUST be .cert, not .crt)..."
sudo cp "${CERT_SRC}" "${DOCKER_CERTS_DIR}/client.cert"
sudo chmod 644 "${DOCKER_CERTS_DIR}/client.cert"

echo "-> Installing client.key..."
sudo cp "${KEY_SRC}" "${DOCKER_CERTS_DIR}/client.key"
sudo chmod 600 "${DOCKER_CERTS_DIR}/client.key"

JWT_SRC="${3:-/etc/ssl/nginx/nginx-repo.jwt}"
if [ -f "${JWT_SRC}" ]; then
    echo "-> Found JWT file ${JWT_SRC}, logging in to ${REGISTRY}..."
    docker login "${REGISTRY}" -u "$(tr -d '[:space:]' < "${JWT_SRC}")" -p none || true
fi

echo "-> Verifying Docker daemon can pull from ${REGISTRY}..."
docker pull "${BASE_IMAGE}"

echo "-> Tagging local image 'waf-compiler:local' (avoids Buildx remote metadata 401 in Compose v5)..."
docker tag "${BASE_IMAGE}" waf-compiler:local

echo "-> Copying certificates into project directory (satisfies Buildx Bake fs.read sandbox in Compose v5)..."
cp -f "${CERT_SRC}" ./nginx-repo.crt
cp -f "${KEY_SRC}" ./nginx-repo.key
chmod 600 ./nginx-repo.crt ./nginx-repo.key

echo "=================================================================="
echo "SUCCESS: Docker is now authenticated against ${REGISTRY}!"
echo "Base image '${BASE_IMAGE}' is cached locally (also tagged as 'waf-compiler:local')."
echo ""
echo "For Docker Compose v2 (e.g. 2.35.1):"
echo "  docker compose build"
echo ""
echo "For Docker Compose v5 (e.g. 5.6.0):"
echo "  NGINX_CERT=./nginx-repo.crt NGINX_KEY=./nginx-repo.key WAF_COMPILER_IMAGE=waf-compiler:local docker compose build"
echo "  # OR directly via buildx bake:"
echo "  WAF_COMPILER_IMAGE=waf-compiler:local docker buildx bake --allow=fs.read=${CERT_SRC} --allow=fs.read=${KEY_SRC}"
echo "=================================================================="
