import json
import os
import subprocess
import tempfile

def run_checkov(target_dir: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            ["checkov", "-d", target_dir, "--output", "sarif", "--output-file-path", tmpdir],
            capture_output=True, text=True, check=False,
        )
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
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"runs": []}
