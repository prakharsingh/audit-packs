import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import GitleaksEngine, run_gitleaks
from audit_packs_core.normalize import sarif_to_findings

_GITLEAKS_SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "gitleaks",
                    "rules": [
                        {
                            "id": "aws-access-token",
                            "shortDescription": {"text": "AWS Access Token detected"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "aws-access-token",
                    "level": "error",
                    "message": {"text": "AWS Access Key found"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "config.py"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


def _make_proc(returncode: int, stderr: bytes = b""):
    proc = MagicMock()
    proc.returncode = returncode

    async def _comm():
        return b"", stderr

    proc.communicate = _comm
    proc.kill = MagicMock()
    return proc


def _subprocess_writing(sarif: dict, returncode: int = 0):
    async def _side(*args, **kwargs):
        cmd = list(args)
        try:
            idx = cmd.index("--report-path")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)

    return _side


def test_gitleaks_returns_sarif():
    engine = GitleaksEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_GITLEAKS_SARIF),
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _GITLEAKS_SARIF


def test_gitleaks_findings_have_engine_gitleaks():
    engine = GitleaksEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_GITLEAKS_SARIF),
    ):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "gitleaks")
    assert len(findings) == 1
    assert findings[0].engine == "gitleaks"
    assert findings[0].check_id == "aws-access-token"


def test_gitleaks_exit_code_1_not_error():
    """Exit code 1 = leaks found; not an error."""
    engine = GitleaksEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_GITLEAKS_SARIF, returncode=1),
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _GITLEAKS_SARIF


def test_gitleaks_exit_code_126_raises():
    """Exit codes not in {0, 1} are errors."""

    async def _bad(*args, **kwargs):
        return _make_proc(126, stderr=b"exec format error")

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="gitleaks exited with code 126"):
            engine.run_scan("/tmp/target", {})


def test_gitleaks_uses_no_git_flag():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("/tmp/target", {})

    assert "--no-git" in captured


def test_gitleaks_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_gitleaks_convenience():
    with patch(
        "asyncio.create_subprocess_exec", side_effect=_subprocess_writing({"runs": []})
    ):
        result = run_gitleaks("/some/dir")
    assert result == {"runs": []}
