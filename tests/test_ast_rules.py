import ast
import tempfile
import os
import pathlib
import importlib.util
from audit_packs.engines import run_ast_rules

ROOT = pathlib.Path(__file__).parent.parent


def _load_rule(name):
    path = str(ROOT / "ast-rules" / f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load AST rule: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


unmasked_pii_sink = _load_rule("unmasked-pii-sink")
db_user_input = _load_rule("db-user-input")
logging_pii = _load_rule("logging-pii")
public_endpoint_pii = _load_rule("public-endpoint-pii")


# Test AST-001: PII reaches sink without masking
def test_ast_001_detects_unmasked_pii_var():
    code = """
def handler(request):
    ssn = request.form.get("ssn")
    db.session.add(ssn)
"""
    tree = ast.parse(code)
    findings = unmasked_pii_sink.detect(tree, code, "test.py")
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "AST-001"
    assert "without masking" in findings[0]["message"]["text"]


def test_ast_001_ignores_masked_pii_var():
    code = """
def handler(request):
    ssn = request.form.get("ssn")
    masked = encrypt(ssn)
    db.session.add(masked)
"""
    tree = ast.parse(code)
    findings = unmasked_pii_sink.detect(tree, code, "test.py")
    assert len(findings) == 0


# Test AST-002: Dynamic DB Query
def test_ast_002_detects_dynamic_sql():
    code = """
def query_user(request):
    user_id = request.args.get("id")
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    tree = ast.parse(code)
    findings = db_user_input.detect(tree, code, "test.py")
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "AST-002"
    assert "Use parameterized queries" in findings[0]["message"]["text"]


def test_ast_002_ignores_parameterized_sql():
    code = """
def query_user(request):
    user_id = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    tree = ast.parse(code)
    findings = db_user_input.detect(tree, code, "test.py")
    assert len(findings) == 0


# Test AST-003: Logging raw PII objects
def test_ast_003_detects_logging_pii_object():
    code = """
class Patient(db.Model):
    ssn = db.Column(db.String)

def log_patient(request):
    patient = Patient(ssn=request.form["ssn"])
    logging.info(patient)
"""
    tree = ast.parse(code)
    findings = logging_pii.detect(tree, code, "test.py")
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "AST-003"
    assert "logged directly" in findings[0]["message"]["text"]


# Test AST-004: route returning PII without auth
def test_ast_004_detects_decoratorless_public_pii_route():
    code = """
@app.route("/profile")
def get_profile():
    return {"ssn": "123-45-678"}
"""
    tree = ast.parse(code)
    findings = public_endpoint_pii.detect(tree, code, "test.py")
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "AST-004"
    assert "lacks authentication decorators" in findings[0]["message"]["text"]


def test_ast_004_ignores_auth_pii_route():
    code = """
@app.route("/profile")
@login_required
def get_profile():
    return {"ssn": "123-45-678"}
"""
    tree = ast.parse(code)
    findings = public_endpoint_pii.detect(tree, code, "test.py")
    assert len(findings) == 0


# Test run_ast_rules Integration
def test_run_ast_rules_integration():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = """
def handler(request):
    ssn = request.form["ssn"]
    print(ssn)  # AST-001 trigger
"""
        py_file = os.path.join(tmpdir, "vuln.py")
        with open(py_file, "w") as fh:
            fh.write(code)

        rules_dir = str(ROOT / "ast-rules")
        sarif = run_ast_rules(tmpdir, rules_dir)

        assert "runs" in sarif
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "AST-001"
        assert (
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == py_file
        )
