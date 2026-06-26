import os
import pathlib
import shutil
import subprocess
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from audit_packs_action.cli import main

ROOT = pathlib.Path(__file__).parent.parent


def _run_git(cmd, cwd):
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Git command failed: {' '.join(cmd)}\nStderr: {res.stderr}")
    return res.stdout


@pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True).returncode != 0
    or shutil.which("checkov") is None
    or shutil.which("semgrep") is None,
    reason="git, checkov, or semgrep not on PATH — skipping e2e test",
)
def test_e2e_integration_forked_repo_scan_and_pr_review():
    """Perform a full E2E integration test simulating PR review and code scan on a forked repository."""
    with tempfile.TemporaryDirectory(dir=str(ROOT)) as tmpdir:
        # 1. Initialize a dummy git repository to represent the forked repo
        _run_git(["git", "init", "-b", "main"], cwd=tmpdir)
        _run_git(["git", "config", "user.email", "e2e-test@example.com"], cwd=tmpdir)
        _run_git(["git", "config", "user.name", "E2E Test User"], cwd=tmpdir)

        # Create base file and commit it
        readme_path = os.path.join(tmpdir, "README.md")
        with open(readme_path, "w") as f:
            f.write("# E2E Audit Packs Demo Repository\n")
        _run_git(["git", "add", "README.md"], cwd=tmpdir)
        _run_git(["git", "commit", "-m", "Initial baseline commit"], cwd=tmpdir)

        # 2. Create a PR/feature branch simulating the fork's branch with security vulnerabilities
        _run_git(["git", "checkout", "-b", "feature/insecure"], cwd=tmpdir)

        # Write vulnerable S3 terraform file
        s3_tf_dir = os.path.join(tmpdir, "terragoat")
        os.makedirs(s3_tf_dir, exist_ok=True)
        s3_tf_path = os.path.join(s3_tf_dir, "s3.tf")
        with open(s3_tf_path, "w") as f:
            f.write("""resource "aws_s3_bucket" "data" {
  bucket        = "vulnerable-bucket-e2e"
  force_destroy = true
}
resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
""")

        # Write vulnerable python file
        py_dir = os.path.join(tmpdir, "pygoat")
        os.makedirs(py_dir, exist_ok=True)
        py_path = os.path.join(py_dir, "vulnerable_app.py")
        with open(py_path, "w") as f:
            f.write("""import hashlib
import requests
import ssl

def check_credentials():
    admin_passwd = "secret-super-password"
    # Weak cipher
    h = hashlib.md5(admin_passwd.encode())
    # Disabled TLS verification
    response = requests.get("https://internal.insecure.api", verify=False)
    return response.status_code
""")

        # Commit changes to the PR branch
        _run_git(
            ["git", "add", "terragoat/s3.tf", "pygoat/vulnerable_app.py"], cwd=tmpdir
        )
        _run_git(
            [
                "git",
                "commit",
                "-m",
                "feat: Add insecure aws s3 resource and verify script",
            ],
            cwd=tmpdir,
        )

        # 3. Setup mock environments and monkeypatch GitHub actions environment variables
        env = {
            "GITHUB_REPOSITORY": "fork-owner/audit-packs",
            "GITHUB_TOKEN": "mock-token-xyz",
            "PR_NUMBER": "42",
            "BASE_REF": "main",
            "GITHUB_SHA": "HEAD",
            "GITHUB_WORKSPACE": tmpdir,
            "PACKS_DIR": str(ROOT / "packs"),
            "RULES_PATH": str(ROOT / "rules"),
            "SCAN_MODE": "both",
            "FAIL_ON": "high",
            "ADJUDICATION_MODE": "off",
            "EMIT_OSCAL": "true",
            "EMIT_COVERAGE": "true",
            "EMIT_SARIF": "true",
        }

        # Mock the requests GET and POST calls to GitHub API
        mock_get_pr = MagicMock()
        mock_get_pr.status_code = 200
        mock_get_pr.json.return_value = {
            "body": "PR review request for verifying cryptographic configurations and SC-13/IA-5 controls."
        }

        mock_get_commits = MagicMock()
        mock_get_commits.status_code = 200
        mock_get_commits.json.return_value = [
            {
                "commit": {
                    "message": "feat: Add insecure aws s3 resource and verify script"
                }
            }
        ]

        mock_post_review = MagicMock()
        mock_post_review.status_code = 200

        def mock_requests_get(url, *args, **kwargs):
            if "/pulls/42/commits" in url:
                return mock_get_commits
            elif "/pulls/42" in url:
                return mock_get_pr
            raise RuntimeError(f"Unexpected GET request to {url}")

        with (
            patch.dict(os.environ, env),
            patch(
                "audit_packs_evidence.evidence.requests.get",
                side_effect=mock_requests_get,
            ),
            patch(
                "audit_packs_action.report.requests.post", return_value=mock_post_review
            ) as mock_post,
        ):
            # 4. Execute the pipeline e2e
            exit_code = main()

            # The severity gate should fail (exiting with 1) because CKV_AWS_19 is a high-severity finding
            assert exit_code == 1, "E2E pipeline did not trip on the high severity gate"

            # Check that requests to post PR comments were made
            mock_post.assert_called_once()
            post_payload = mock_post.call_args[1]["json"]
            assert post_payload["event"] == "COMMENT"
            # Verify PR review comments payload contains inline comments
            comments = post_payload["comments"]
            assert len(comments) > 0, "No review comments generated for the PR review"

            # Check that the review comments are mapped to the vulnerable files in the diff
            comment_files = {c["path"] for c in comments}
            assert "terragoat/s3.tf" in comment_files
            assert "pygoat/vulnerable_app.py" in comment_files

            # 5. Verify the e2e outputs are created in the workspace root
            oscal_json = os.path.join(tmpdir, "oscal.json")
            coverage_md = os.path.join(tmpdir, "coverage.md")
            coverage_html = os.path.join(tmpdir, "coverage.html")
            audit_sarif = os.path.join(tmpdir, "audit-packs.sarif")

            assert os.path.isfile(oscal_json), "oscal.json was not created in workspace"
            assert os.path.isfile(
                coverage_md
            ), "coverage.md was not created in workspace"
            assert os.path.isfile(
                coverage_html
            ), "coverage.html was not created in workspace"
            assert os.path.isfile(
                audit_sarif
            ), "audit-packs.sarif was not created in workspace"

            # Check that oscal.json is non-empty
            assert os.path.getsize(oscal_json) > 0
            assert os.path.getsize(coverage_md) > 0
            assert os.path.getsize(audit_sarif) > 0
