import json
import pathlib
from audit_packs.normalize import sarif_to_findings

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
