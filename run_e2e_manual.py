import os
import pathlib
import shutil
import subprocess
import tempfile
import json
from unittest.mock import patch, MagicMock
from audit_packs.cli import main

ROOT = pathlib.Path(__file__).parent.absolute()
OUTPUT_DIR = os.path.join(ROOT, "e2e_manual_output")


def _run_git(cmd, cwd):
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Git command failed: {' '.join(cmd)}\nStderr: {res.stderr}")
    return res.stdout


def run_e2e_manual_verification():
    print("=== Setting up E2E manual verification workspace ===")
    if os.path.exists(OUTPUT_DIR):
        print(f"Cleaning existing output directory: {OUTPUT_DIR}")
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=str(ROOT)) as tmpdir:
        # 1. Init Git Repo
        _run_git(["git", "init", "-b", "main"], cwd=tmpdir)
        _run_git(
            ["git", "config", "user.email", "manual-verify@example.com"], cwd=tmpdir
        )
        _run_git(["git", "config", "user.name", "Manual Verify User"], cwd=tmpdir)

        # Baseline commit
        readme_path = os.path.join(tmpdir, "README.md")
        with open(readme_path, "w") as f:
            f.write("# E2E Manual Verification Demo\n")
        _run_git(["git", "add", "README.md"], cwd=tmpdir)
        _run_git(["git", "commit", "-m", "Initial baseline commit"], cwd=tmpdir)

        # PR/feature branch
        _run_git(["git", "checkout", "-b", "feature/insecure"], cwd=tmpdir)

        # Copy real_world_fixtures to mock fork PR branch
        shutil.copytree(
            os.path.join(ROOT, "real_world_fixtures/terragoat"),
            os.path.join(tmpdir, "terragoat"),
        )
        shutil.copytree(
            os.path.join(ROOT, "real_world_fixtures/pygoat"),
            os.path.join(tmpdir, "pygoat"),
        )

        # Commit files to trigger diff
        _run_git(["git", "add", "."], cwd=tmpdir)
        _run_git(
            ["git", "commit", "-m", "feat: Add vulnerable resources and scripts"],
            cwd=tmpdir,
        )

        # 2. Setup env variables
        env = {
            "GITHUB_REPOSITORY": "fork-owner/audit-packs-manual",
            "GITHUB_TOKEN": "manual-mock-token-123",
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

        # Mock APIs and capture POST payloads
        mock_get_pr = MagicMock()
        mock_get_pr.status_code = 200
        mock_get_pr.json.return_value = {
            "body": "PR review verifying cryptographic compliance and access controls."
        }

        mock_get_commits = MagicMock()
        mock_get_commits.status_code = 200
        mock_get_commits.json.return_value = [
            {"commit": {"message": "feat: Add vulnerable resources and scripts"}}
        ]

        captured_payload = {}

        def mock_requests_post(url, json=None, *args, **kwargs):
            nonlocal captured_payload
            captured_payload["url"] = url
            captured_payload["payload"] = json
            resp = MagicMock()
            resp.status_code = 200
            return resp

        def mock_requests_get(url, *args, **kwargs):
            if "/pulls/42/commits" in url:
                return mock_get_commits
            elif "/pulls/42" in url:
                return mock_get_pr
            raise RuntimeError(f"Unexpected GET request to {url}")

        print("=== Running Audit Packs Pipeline ===")
        with (
            patch.dict(os.environ, env),
            patch("audit_packs.evidence.requests.get", side_effect=mock_requests_get),
            patch("audit_packs.report.requests.post", side_effect=mock_requests_post),
        ):
            exit_code = main()
            print(
                f"Pipeline finished with Exit Code: {exit_code} (Expected 1 due to high-severity findings)"
            )

        # 3. Save mock review payload
        payload_file = os.path.join(OUTPUT_DIR, "review_payload.json")
        with open(payload_file, "w") as fh:
            json.dump(captured_payload, fh, indent=2)
        print(f"Saved review payload to: {payload_file}")

        # 4. Copy generated outputs to root output dir
        for file_name in (
            "oscal.json",
            "coverage.md",
            "coverage.html",
            "audit-packs.sarif",
        ):
            src = os.path.join(tmpdir, file_name)
            if os.path.isfile(src):
                dest = os.path.join(OUTPUT_DIR, file_name)
                shutil.copy2(src, dest)
                print(f"Copied generated output: {dest}")

    print("\n=== E2E manual verification complete ===")
    print(f"All outputs generated inside directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    run_e2e_manual_verification()
