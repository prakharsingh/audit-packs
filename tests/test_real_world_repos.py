import pathlib
import shutil
import pytest
from audit_packs.cli import analyze, assess
from audit_packs.models import AssessmentStatus

ROOT = pathlib.Path(__file__).parent.parent
PACKS = str(ROOT / "packs")
RULES = str(ROOT / "rules")
REAL_WORLD_DIR = str(ROOT / "real_world_fixtures")

# Require both checkov and semgrep to run these real-world integration tests
pytestmark = pytest.mark.skipif(
    shutil.which("checkov") is None or shutil.which("semgrep") is None,
    reason="checkov or semgrep not on PATH — skipping real-world integration tests",
)


def test_real_world_full_scan():
    """Test full scan (assess) on real world vulnerable repositories/files."""
    # Run assess over the entire real-world fixture directory
    control_statuses = assess(
        repo_dir=REAL_WORLD_DIR,
        packs_dir=PACKS,
        rules_path=RULES,
        frameworks=["nist-800-53"],
    )

    # We expect some controls to have failed because the fixtures contain vulnerabilities
    failed_controls = [
        cs for cs in control_statuses if cs.status == AssessmentStatus.FAIL
    ]
    assert (
        len(failed_controls) > 0
    ), "Expected at least one failed control in a full scan of vulnerable repositories"

    # Let's inspect some of the failed controls
    failed_ids = {cs.control_id for cs in failed_controls}

    # Verify that SC-13 (Cryptographic Protection) has failed status (due to weak-cipher or S3 encryption)
    assert (
        "SC-13" in failed_ids
    ), "Expected NIST control SC-13 to fail due to weak-cipher or S3 encryption violations"

    # Verify that IA-5 (Authenticator Management) has failed status (due to hardcoded-credential)
    assert (
        "IA-5" in failed_ids
    ), "Expected NIST control IA-5 to fail due to hardcoded-credential"

    # Verify that SC-8 (Transmission Confidentiality and Integrity) has failed status (due to no-tls-verify)
    assert (
        "SC-8" in failed_ids
    ), "Expected NIST control SC-8 to fail due to no-tls-verify"

    # Gather all findings
    all_findings = []
    for cs in control_statuses:
        all_findings.extend(cs.findings)

    # Check that checkov findings exist
    checkov_findings = [f for f in all_findings if f.finding.engine == "checkov"]
    assert (
        len(checkov_findings) > 0
    ), "Expected checkov findings from terragoat IaC files"

    # Check that semgrep findings exist
    semgrep_findings = [f for f in all_findings if f.finding.engine == "semgrep"]
    assert (
        len(semgrep_findings) > 0
    ), "Expected semgrep findings from vulnerable python app"

    # Verify we mapped findings to correct file locations
    for cf in all_findings:
        assert cf.finding.file in (
            "terragoat/s3.tf",
            "terragoat/rds.tf",
            "pygoat/vulnerable_app.py",
            "pygoat/views.py",
        )


def test_real_world_pr_diff_aws_s3_only():
    """Test PR-diff scan (analyze) when only an insecure S3 line is changed."""
    # Let's simulate a PR where lines of terragoat/s3.tf are changed
    changed = {"terragoat/s3.tf": set(range(1, 100))}

    scored_findings = analyze(
        repo_dir=REAL_WORLD_DIR,
        changed=changed,
        packs_dir=PACKS,
        rules_path=RULES,
        frameworks=["nist-800-53"],
    )

    # Only findings that target changed lines of terragoat/s3.tf should be surfaced
    assert len(scored_findings) > 0, "Expected findings on the changed lines of s3.tf"
    for sf in scored_findings:
        cf = sf.result.control_finding
        assert cf.finding.file == "terragoat/s3.tf"

    check_ids = {sf.result.control_finding.finding.check_id for sf in scored_findings}
    # CKV_AWS_19 (S3 encryption) or similar S3 bucket checks should be present
    assert any(cid.startswith("CKV_AWS") for cid in check_ids)


def test_real_world_pr_diff_python_only():
    """Test PR-diff scan (analyze) when only python files have changed."""
    # Simulate a PR where all lines of pygoat/vulnerable_app.py are changed
    changed = {"pygoat/vulnerable_app.py": set(range(1, 30))}

    scored_findings = analyze(
        repo_dir=REAL_WORLD_DIR,
        changed=changed,
        packs_dir=PACKS,
        rules_path=RULES,
        frameworks=["nist-800-53"],
    )

    assert (
        len(scored_findings) > 0
    ), "Expected findings on the changed lines of vulnerable_app.py"

    check_ids = {sf.result.control_finding.finding.check_id for sf in scored_findings}
    # Check that weak-cipher, hardcoded-credential, and no-tls-verify are found
    assert "weak-cipher" in check_ids
    assert "hardcoded-credential" in check_ids
    assert "no-tls-verify" in check_ids

    for sf in scored_findings:
        cf = sf.result.control_finding
        assert cf.finding.file == "pygoat/vulnerable_app.py"


def test_real_world_pr_diff_no_changes():
    """Test PR-diff scan (analyze) when no lines are changed in the PR."""
    changed = {}
    scored_findings = analyze(
        repo_dir=REAL_WORLD_DIR,
        changed=changed,
        packs_dir=PACKS,
        rules_path=RULES,
        frameworks=["nist-800-53"],
    )
    assert (
        len(scored_findings) == 0
    ), "No findings should be returned when no lines changed"
