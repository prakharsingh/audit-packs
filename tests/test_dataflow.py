from audit_packs.dataflow import DataFlow, extract_data_flows, flow_confidence

PYTHON_WITH_UNPROTECTED_FLOW = """\\
def handle_request(request):
    user_data = request.form.get("ssn")
    db.session.add(user_data)
"""

PYTHON_WITH_PROTECTED_FLOW = """\\
def handle_request(request):
    user_data = request.form.get("ssn")
    encrypted = encrypt(user_data)
    db.session.add(encrypted)
"""


def test_extract_unprotected_python_flow():
    flows = extract_data_flows(PYTHON_WITH_UNPROTECTED_FLOW, "python")
    assert len(flows) >= 1
    assert any(not f.has_transform for f in flows)


def test_extract_protected_python_flow():
    flows = extract_data_flows(PYTHON_WITH_PROTECTED_FLOW, "python")
    assert any(f.has_transform for f in flows)


def test_extract_unsupported_language_returns_empty():
    flows = extract_data_flows("some code", "ruby")
    assert flows == []


def test_flow_confidence_neutral_when_no_flows():
    assert flow_confidence([], 10) == 0.5


def test_flow_confidence_high_for_unprotected_both_ends_in_range():
    flow = DataFlow(
        source_line=5,
        source_type="user_input",
        transforms=(),
        sink_line=8,
        sink_type="db_write",
        has_transform=False,
    )
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.9


def test_flow_confidence_low_for_protected_both_ends_in_range():
    flow = DataFlow(
        source_line=5,
        source_type="user_input",
        transforms=("encrypt",),
        sink_line=8,
        sink_type="db_write",
        has_transform=True,
    )
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.2


def test_flow_confidence_moderate_for_unprotected_one_end_in_range():
    flow = DataFlow(
        source_line=5,
        source_type="user_input",
        transforms=(),
        sink_line=200,
        sink_type="db_write",
        has_transform=False,
    )
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.7


def test_flow_confidence_neutral_for_protected_one_end_in_range():
    flow = DataFlow(
        source_line=5,
        source_type="user_input",
        transforms=("mask",),
        sink_line=200,
        sink_type="db_write",
        has_transform=True,
    )
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.5


def test_flow_confidence_out_of_range_returns_neutral():
    flow = DataFlow(
        source_line=500,
        source_type="user_input",
        transforms=(),
        sink_line=600,
        sink_type="db_write",
        has_transform=False,
    )
    score = flow_confidence([flow], finding_line=10)
    assert score == 0.5


def test_dataflow_fields():
    flow = DataFlow(
        source_line=1,
        source_type="env_var",
        transforms=("hash",),
        sink_line=10,
        sink_type="log",
        has_transform=True,
    )
    assert flow.has_transform is True
    assert "hash" in flow.transforms
