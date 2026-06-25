#!/usr/bin/env bash
set -euo pipefail

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_TAG="audit-packs:smoke-test"
WORKSPACE_DIR=$(mktemp -d)

# Cleanup on exit
cleanup() {
    echo "=== Cleaning up ==="
    if [ -d "${WORKSPACE_DIR}" ]; then
        echo "Removing temporary workspace: ${WORKSPACE_DIR}"
        rm -rf "${WORKSPACE_DIR}"
    fi
    echo "Removing temporary Docker image: ${IMAGE_TAG}"
    docker rmi "${IMAGE_TAG}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== Building Docker Image ==="
docker build -t "${IMAGE_TAG}" "${REPO_DIR}"

echo "=== Setting up mock workspace ==="
mkdir -p "${WORKSPACE_DIR}"
# Create a basic insecure terraform file to trigger findings
cat << 'EOF' > "${WORKSPACE_DIR}/insecure.tf"
resource "aws_s3_bucket" "b" {
  bucket = "example"
}
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
EOF

echo "=== Running Docker Image Smoke Test ==="
# GITHUB_WORKSPACE inside the container should be /github/workspace
# We mount our temporary workspace directory to /github/workspace
docker run --rm \
  -e GITHUB_REPOSITORY="foo/bar" \
  -e GITHUB_TOKEN="mock-token" \
  -e GITHUB_SHA="mock-sha" \
  -e SCAN_MODE="full" \
  -e FRAMEWORKS="nist-800-53" \
  -e ADJUDICATION_MODE="off" \
  -e GITHUB_WORKSPACE="/github/workspace" \
  -v "${WORKSPACE_DIR}:/github/workspace" \
  "${IMAGE_TAG}"

echo "=== Verifying Output Files ==="
# Check that files were created
if [ ! -f "${WORKSPACE_DIR}/oscal.json" ]; then
    echo "FAIL: oscal.json not created"
    exit 1
fi
if [ ! -f "${WORKSPACE_DIR}/coverage.md" ]; then
    echo "FAIL: coverage.md not created"
    exit 1
fi
if [ ! -f "${WORKSPACE_DIR}/coverage.html" ]; then
    echo "FAIL: coverage.html not created"
    exit 1
fi
if [ ! -f "${WORKSPACE_DIR}/audit-packs.sarif" ]; then
    echo "FAIL: audit-packs.sarif not created"
    exit 1
fi

# Check that oscal.json is valid JSON
if ! python3 -m json.tool "${WORKSPACE_DIR}/oscal.json" >/dev/null; then
    echo "FAIL: oscal.json is not valid JSON"
    exit 1
fi

# Check that audit-packs.sarif is valid JSON
if ! python3 -m json.tool "${WORKSPACE_DIR}/audit-packs.sarif" >/dev/null; then
    echo "FAIL: audit-packs.sarif is not valid JSON"
    exit 1
fi

# Check that the files are non-empty
if [ ! -s "${WORKSPACE_DIR}/coverage.md" ]; then
    echo "FAIL: coverage.md is empty"
    exit 1
fi

echo "=== SMOKE TEST PASSED SUCCESSFULLY ==="
