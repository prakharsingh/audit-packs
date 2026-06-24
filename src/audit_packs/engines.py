import json
import os
import subprocess
import tempfile


def run_git_diff(workspace: str, base_ref: str) -> str:
    proc = subprocess.run(
        ["git", "diff", "--unified=0", f"{base_ref}...HEAD"],
        cwd=workspace, capture_output=True, text=True, check=True,
    )
    return proc.stdout


def run_checkov(target_dir: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        proc = subprocess.run(
            ["checkov", "-d", target_dir, "--output", "sarif", "--output-file-path", tmpdir],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode >= 2:
            raise RuntimeError(f"checkov exited with code {proc.returncode}: {proc.stderr.strip()}")
        sarif_file = os.path.join(tmpdir, "results_sarif.sarif")
        if os.path.exists(sarif_file):
            try:
                with open(sarif_file) as fh:
                    return json.load(fh)
            except json.JSONDecodeError:
                pass
        return {"runs": []}


def run_semgrep(target_dir: str, rules_path: str) -> dict:
    proc = subprocess.run(
        ["semgrep", "scan", "--config", rules_path, "--sarif", target_dir],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode >= 2:
        raise RuntimeError(f"semgrep exited with code {proc.returncode}: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"runs": []}
