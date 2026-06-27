import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import TrivyEngine, run_trivy_fs, run_trivy_image
from audit_packs_core.normalize import sarif_to_findings

_MINIMAL_SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Trivy",
                    "rules": [
                        {
                            "id": "AVD-AWS-0132",
                            "shortDescription": {"text": "S3 not encrypted"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "AVD-AWS-0132",
                    "level": "error",
                    "message": {"text": "Bucket not encrypted"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.tf"},
                                "region": {"startLine": 10},
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
    """Returns a side_effect coroutine that writes sarif to the --output path."""

    async def _side(*args, **kwargs):
        cmd = list(args)
        try:
            idx = cmd.index("--output")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)

    return _side


def test_trivy_fs_returns_sarif():
    engine = TrivyEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_MINIMAL_SARIF),
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _MINIMAL_SARIF


def test_trivy_findings_have_engine_trivy():
    engine = TrivyEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_MINIMAL_SARIF),
    ):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "trivy")
    assert len(findings) == 1
    assert findings[0].engine == "trivy"
    assert findings[0].check_id == "AVD-AWS-0132"


def test_trivy_image_mode_uses_image_subcommand():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("", {"image": "myapp:latest"})

    assert "image" in captured
    assert "myapp:latest" in captured
    assert "fs" not in captured


def test_trivy_fs_mode_uses_fs_subcommand():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("/some/path", {})

    assert "fs" in captured
    assert "image" not in captured


def test_trivy_exit_code_1_not_error():
    engine = TrivyEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_MINIMAL_SARIF, returncode=1),
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _MINIMAL_SARIF


def test_trivy_exit_code_2_raises():
    async def _bad(*args, **kwargs):
        return _make_proc(2, stderr=b"fatal: db update required")

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="trivy exited with code 2"):
            engine.run_scan("/tmp/target", {})


def test_trivy_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_trivy_fs_convenience():
    with patch(
        "asyncio.create_subprocess_exec", side_effect=_subprocess_writing({"runs": []})
    ):
        result = run_trivy_fs("/some/dir")
    assert result == {"runs": []}


def test_run_trivy_image_convenience():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        run_trivy_image("myapp:latest")

    assert "image" in captured
    assert "myapp:latest" in captured
