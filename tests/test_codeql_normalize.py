import json
import pathlib
import tempfile
import pytest
from audit_packs_action.engines import read_codeql_sarif
from audit_packs_core.normalize import sarif_to_findings, extract_rule_confidences
from audit_packs_core.models import PathNode

CODEQL_SARIF_WITH_FLOWS = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [
                        {"id": "python/CWE-312", "properties": {"confidence": "HIGH"}}
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python/CWE-312",
                    "level": "error",
                    "message": {"text": "Cleartext storage of sensitive information"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/models.py"},
                                "region": {
                                    "startLine": 42,
                                    "snippet": {"text": "password = plaintext"},
                                },
                            }
                        }
                    ],
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "app/views.py"
                                                    },
                                                    "region": {"startLine": 14},
                                                },
                                                "message": {
                                                    "text": "source: user-controlled input"
                                                },
                                            },
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "app/models.py"
                                                    },
                                                    "region": {"startLine": 42},
                                                },
                                                "message": {
                                                    "text": "reaches sink: cleartext storage"
                                                },
                                            },
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ],
        }
    ]
}


def test_sarif_with_codeflows_produces_evidence_path():
    findings = sarif_to_findings(CODEQL_SARIF_WITH_FLOWS, "codeql")
    assert len(findings) == 1
    f = findings[0]
    assert len(f.evidence_path) == 2
    assert isinstance(f.evidence_path[0], PathNode)
    assert f.evidence_path[0].line == 14
    assert "source" in f.evidence_path[0].description
    assert f.evidence_path[1].line == 42


def test_sarif_without_codeflows_has_empty_evidence_path():
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_AWS_19",
                        "level": "error",
                        "message": {"text": "Encryption disabled"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.tf"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    findings = sarif_to_findings(sarif, "checkov")
    assert findings[0].evidence_path == ()


def test_extract_rule_confidences_maps_high_to_09():
    confidences = extract_rule_confidences(CODEQL_SARIF_WITH_FLOWS)
    assert confidences.get("python/CWE-312") == pytest.approx(0.9)


def test_extract_rule_confidences_returns_empty_when_no_rules():
    confidences = extract_rule_confidences({"runs": []})
    assert confidences == {}


def test_read_codeql_sarif_merges_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        sarif1 = {"runs": [{"results": [{"ruleId": "A"}]}]}
        sarif2 = {"runs": [{"results": [{"ruleId": "B"}]}]}
        pathlib.Path(tmpdir, "a.sarif").write_text(json.dumps(sarif1))
        pathlib.Path(tmpdir, "b.sarif").write_text(json.dumps(sarif2))
        merged = read_codeql_sarif(tmpdir)
        assert len(merged["runs"]) == 2


def test_read_codeql_sarif_returns_empty_for_missing_dir():
    merged = read_codeql_sarif("/nonexistent/path")
    assert merged == {"runs": []}


def test_read_codeql_sarif_returns_empty_for_empty_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        merged = read_codeql_sarif(tmpdir)
        assert merged == {"runs": []}
