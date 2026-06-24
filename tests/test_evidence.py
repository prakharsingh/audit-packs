import dataclasses
import pytest
from unittest.mock import patch, MagicMock
from audit_packs.models import Finding
from audit_packs.evidence import (
    PRContext, extract_doc_context, enrich, evidence_confidence
)

def _finding(**kwargs):
    defaults = dict(check_id="CKV_AWS_19", engine="checkov", file="main.tf",
                    line=5, severity="high", message="msg", evidence="snippet")
    defaults.update(kwargs)
    return Finding(**defaults)

FILE_WITH_DOCSTRING = '''\
# This module handles user data
def store_user(user_id):
    """Stores user PII to the database."""
    db.session.add(user_id)
'''

FILE_WITH_BLOCK_COMMENT = '''\
resource "aws_s3_bucket" "data" {
  # Bucket for sensitive customer records — encryption required by policy
  bucket = "my-bucket"
  encrypted = false
}
'''

def test_extract_doc_context_finds_python_docstring():
    ctx = extract_doc_context(FILE_WITH_DOCSTRING, line=4)
    assert "Stores user PII" in ctx

def test_extract_doc_context_finds_block_comment():
    ctx = extract_doc_context(FILE_WITH_BLOCK_COMMENT, line=4)
    assert "encryption required" in ctx

def test_extract_doc_context_returns_empty_when_none_nearby():
    text = "x = 1\ny = 2\nz = 3\n"
    ctx = extract_doc_context(text, line=2)
    assert ctx == ""

def test_enrich_attaches_doc_context():
    f = _finding(file="main.py", line=4)
    pr = PRContext(pr_body="Refactoring user storage", commit_messages=("fix: update handler",))
    enriched = enrich(f, FILE_WITH_DOCSTRING, pr)
    assert "Stores user PII" in enriched.doc_context

def test_enrich_returns_new_finding_instance():
    f = _finding()
    pr = PRContext(pr_body="", commit_messages=())
    enriched = enrich(f, "no docstring here\n", pr)
    assert enriched is not f

def test_enrich_does_not_mutate_original():
    f = _finding()
    pr = PRContext(pr_body="", commit_messages=())
    enrich(f, "code\n", pr)
    assert f.doc_context == ""

def test_evidence_confidence_base_score_from_sarif():
    f = _finding()
    score = evidence_confidence(f, None)
    assert score == pytest.approx(0.4)

def test_evidence_confidence_adds_doc_context_bonus():
    f = _finding(doc_context="important comment")
    score = evidence_confidence(f, None)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_adds_pr_body_reference():
    f = _finding(file="main.tf", doc_context="")
    pr = PRContext(pr_body="changes in main.tf to fix encryption", commit_messages=())
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_adds_commit_message_reference():
    f = _finding(file="main.tf", doc_context="")
    pr = PRContext(pr_body="", commit_messages=("fix: update main.tf encryption",))
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_caps_at_1_0():
    f = _finding(file="main.tf", doc_context="important doc")
    pr = PRContext(pr_body="changes in main.tf", commit_messages=("update main.tf",))
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(1.0)

def test_extract_doc_context_finds_double_slash_comment():
    file_with_double_slash_comment = '''\\
resource "aws_s3_bucket" "data" {
  // Bucket for sensitive customer records — encryption required by policy
  bucket = "my-bucket"
  encrypted = false
}
'''
    ctx = extract_doc_context(file_with_double_slash_comment, line=4)
    assert "encryption required" in ctx

