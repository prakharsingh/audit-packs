import json
import pathlib
from audit_packs_core.normalize import sarif_to_findings

FIXTURE = pathlib.Path(__file__).parent / "fixtures/sarif/checkov_sample.json"


def test_maps_sarif_result_to_finding():
    sarif = json.loads(FIXTURE.read_text())
    findings = sarif_to_findings(sarif, engine="checkov")
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "CKV_AWS_19"
    assert f.engine == "checkov"
    assert f.file == "main.tf"
    assert f.line == 11
    assert f.severity == "high"


def test_empty_sarif_yields_no_findings():
    assert sarif_to_findings({"runs": []}, engine="semgrep") == []


def test_properties_severity_overrides_level():
    """Checkov encodes richer severity in result.properties.severity; verify it wins over level."""
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_AWS_99",
                        "level": "warning",  # would resolve to "medium" via level
                        "properties": {
                            "severity": "CRITICAL"
                        },  # should win → "critical"
                        "message": {"text": "test finding"},
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
    findings = sarif_to_findings(sarif, engine="checkov")
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_level_severity_used_when_no_properties():
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_AWS_88",
                        "level": "note",
                        "message": {"text": "info finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "vpc.tf"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    findings = sarif_to_findings(sarif, engine="checkov")
    assert findings[0].severity == "low"


def test_snippet_used_as_evidence_over_message():
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_AWS_19",
                        "level": "error",
                        "message": {"text": "generic message"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "s3.tf"},
                                    "region": {
                                        "startLine": 7,
                                        "snippet": {"text": "encrypted = false"},
                                    },
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    findings = sarif_to_findings(sarif, engine="checkov")
    assert findings[0].evidence == "encrypted = false"
