import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import TfsecEngine, run_tfsec
from audit_packs_core.normalize import sarif_to_findings

_TFSEC_SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "tfsec",
                    "rules": [
                        {
                            "id": "aws-s3-enable-bucket-encryption",
                            "shortDescription": {"text": "S3 encryption disabled"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "aws-s3-enable-bucket-encryption",
                    "level": "error",
                    "message": {"text": "Bucket has no encryption"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.tf"},
                                "region": {"startLine": 3},
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
            idx = cmd.index("--out")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)

    return _side


def test_tfsec_returns_sarif():
    engine = TfsecEngine()
    with patch(
        "asyncio.create_subprocess_exec", side_effect=_subprocess_writing(_TFSEC_SARIF)
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _TFSEC_SARIF


def test_tfsec_findings_have_engine_tfsec():
    engine = TfsecEngine()
    with patch(
        "asyncio.create_subprocess_exec", side_effect=_subprocess_writing(_TFSEC_SARIF)
    ):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "tfsec")
    assert len(findings) == 1
    assert findings[0].engine == "tfsec"
    assert findings[0].check_id == "aws-s3-enable-bucket-encryption"


def test_tfsec_exit_code_1_not_error():
    engine = TfsecEngine()
    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=_subprocess_writing(_TFSEC_SARIF, returncode=1),
    ):
        result = engine.run_scan("/tmp/target", {})
    assert result == _TFSEC_SARIF


def test_tfsec_exit_code_2_raises():
    async def _bad(*args, **kwargs):
        return _make_proc(2, stderr=b"panic: nil pointer")

    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="tfsec exited with code 2"):
            engine.run_scan("/tmp/target", {})


def test_tfsec_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_tfsec_convenience():
    with patch(
        "asyncio.create_subprocess_exec", side_effect=_subprocess_writing({"runs": []})
    ):
        result = run_tfsec("/some/dir")
    assert result == {"runs": []}
