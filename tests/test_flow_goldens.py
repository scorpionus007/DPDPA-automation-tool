"""Golden-style tests for flow rule regressions.

Tests cover:
- Analytics/marketing/logging flow detection with multi-signal confidence
- Symbol-level tracking (field->arg continuity)
- Taint propagation verification
- Consent-near-sink proximity
- FK-graph-aware deletion coverage
- Purpose mismatch detection
- Score-impact gating (scorable behavior)
- ML classifier evidence integration
"""

import pytest

from dpdp_scanner.rule_engine import compute_compliance_score
from dpdp_scanner.rules import data_flow
from dpdp_scanner.flow.symbol_tracker import (
    extract_pii_symbols,
    symbol_continuity_score,
    compute_symbol_evidence,
)
from dpdp_scanner.flow.taint_tracker import (
    propagate_taint_in_file,
    trace_taint_across_path,
)
from dpdp_scanner.flow.consent_proximity import (
    has_consent_near_sink,
    consent_proximity_score,
)
from dpdp_scanner.flow.fk_graph import (
    build_fk_graph,
    transitive_dependencies,
    deletion_must_cover,
)
from dpdp_scanner.flow.ml_classifier import (
    build_feature_vector,
    RuleBasedFlowClassifier,
    classify_flow,
)

pytestmark = pytest.mark.flow_goldens


def _base_extracted():
    return {
        "pii_flow_graph": {"flow_paths": []},
        "consent_signals": [],
        "pii_fields": [],
        "third_party_imports": [],
        "route_files": [],
        "model_files": [],
        "deletion_signals": [],
        "deletion_endpoints": [],
        "_file_contents": {},
    }


# ═══════════════════════════════════════════════════════════════════
# 1. Analytics flow detection
# ═══════════════════════════════════════════════════════════════════

def test_flow_to_analytics_without_consent_is_emitted_and_scorable():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": (
            "def login(email, password):\n"
            "    user = db.find_user(email)\n"
            "    token = create_token(user)\n"
            "    return token\n"
        ),
        "src/service/user.py": (
            "from auth.login import login\n"
            "def get_user(email):\n"
            "    user_data = {'email': email}\n"
            "    return user_data\n"
        ),
        "src/analytics/client.py": (
            "import analytics\n"
            "def track_login(email):\n"
            "    analytics.track('login', {'email': email})\n"
        ),
    }
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/analytics/client.py",
                "path": ["src/auth/login.py", "src/service/user.py", "src/analytics/client.py"],
                "hop_count": 2,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    flow_findings = [f for f in findings if f.get("rule") == "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT"]
    assert len(flow_findings) == 1
    f = flow_findings[0]
    assert f["confidence"] >= 0.60
    assert f.get("scorable") == _expected_scorable(f["confidence"])
    ev = f.get("evidence", {})
    assert "flow_evidence" in ev


def test_analytics_flow_not_emitted_when_consent_near_sink():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": "def login(email, password): return token",
        "src/analytics/client.py": (
            "def track_login(email):\n"
            "    if check_consent(user, 'analytics'):\n"
            "        analytics.track('login', {'email': email})\n"
        ),
    }
    extracted["consent_signals"] = [
        {"file": "src/analytics/client.py", "line_content": "check_consent(user, 'analytics')"}
    ]
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/analytics/client.py",
                "path": ["src/auth/login.py", "src/analytics/client.py"],
                "hop_count": 1,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    analytics_findings = [f for f in findings if f.get("rule") == "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT"]
    assert len(analytics_findings) == 0


def test_analytics_flow_with_weak_consent_still_emits():
    """Consent on path but not near sink and not purpose-specific."""
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": "def login(email, password): return token",
        "src/middleware/auth.py": "def require_auth(): pass",
        "src/analytics/client.py": "analytics.track('login', {'email': email})",
    }
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/analytics/client.py",
                "path": ["src/auth/login.py", "src/middleware/auth.py", "src/analytics/client.py"],
                "hop_count": 2,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    analytics_findings = [f for f in findings if f.get("rule") == "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT"]
    assert len(analytics_findings) >= 1


# ═══════════════════════════════════════════════════════════════════
# 2. Marketing flow detection
# ═══════════════════════════════════════════════════════════════════

def test_marketing_flow_emitted_without_consent():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/register.py": (
            "def register(email, name):\n"
            "    user = create_user(email=email, name=name)\n"
            "    return user\n"
        ),
        "src/marketing/mailer.py": (
            "import sendgrid\n"
            "def add_to_campaign(email):\n"
            "    sendgrid.send({'to': email, 'campaign': 'welcome'})\n"
        ),
    }
    extracted["pii_fields"] = [{"file": "src/auth/register.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/register.py",
                "sink": "src/marketing/mailer.py",
                "path": ["src/auth/register.py", "src/marketing/mailer.py"],
                "hop_count": 1,
                "sink_type": "marketing_email",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    mkt = [f for f in findings if f.get("rule") == "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT"]
    assert len(mkt) == 1


def test_marketing_flow_suppressed_with_consent_near_sink():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/register.py": "def register(email): pass",
        "src/marketing/mailer.py": (
            "def add_to_campaign(email):\n"
            "    if marketing_consent(email):\n"
            "        sendgrid.send({'to': email})\n"
        ),
    }
    extracted["consent_signals"] = [
        {"file": "src/marketing/mailer.py", "line_content": "marketing_consent"}
    ]
    extracted["pii_fields"] = [{"file": "src/auth/register.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/register.py",
                "sink": "src/marketing/mailer.py",
                "path": ["src/auth/register.py", "src/marketing/mailer.py"],
                "hop_count": 1,
                "sink_type": "marketing_email",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    mkt = [f for f in findings if f.get("rule") == "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT"]
    assert len(mkt) == 0


# ═══════════════════════════════════════════════════════════════════
# 3. Logging flow detection
# ═══════════════════════════════════════════════════════════════════

def test_logging_flow_requires_sensitive_pii():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": "def login(email, password): return token",
        "src/monitoring/logger.py": "logger.error('Login failed', {'email': email})",
    }
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/monitoring/logger.py",
                "path": ["src/auth/login.py", "src/monitoring/logger.py"],
                "hop_count": 1,
                "sink_type": "error_logging",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    log_findings = [f for f in findings if f.get("rule") == "PII_FLOW_TO_LOGGING"]
    assert len(log_findings) == 1


def test_logging_flow_not_emitted_for_non_sensitive_pii():
    """Non-sensitive PII (e.g. 'username' not in sensitive set) with non-sensitive sink."""
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/app.py": "def handler(request_id): pass",
        "src/logger.py": "logger.info(request_id)",
    }
    extracted["pii_fields"] = [{"file": "src/app.py", "field": "request_id"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/app.py",
                "sink": "src/logger.py",
                "path": ["src/app.py", "src/logger.py"],
                "hop_count": 1,
                "sink_type": "error_logging",
                "pii_fields": ["request_id"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    log_findings = [f for f in findings if f.get("rule") == "PII_FLOW_TO_LOGGING"]
    assert len(log_findings) == 0


# ═══════════════════════════════════════════════════════════════════
# 4. Symbol-level tracking
# ═══════════════════════════════════════════════════════════════════

def test_symbol_tracker_finds_pii_in_source():
    syms = extract_pii_symbols("user_email = request.form['email']")
    assert "email" in syms


def test_symbol_continuity_high_when_pii_in_call_args():
    source = "def login(email, password): return email"
    sink = "analytics.track('login', {'email': email})"
    score = symbol_continuity_score(source, sink, [])
    assert score >= 0.5


def test_symbol_continuity_low_when_no_pii():
    source = "def handler(request_id): return request_id"
    sink = "logger.info(message)"
    score = symbol_continuity_score(source, sink, [])
    assert score <= 0.2


def test_symbol_evidence_returns_required_keys():
    flow_path = {
        "source": "src/login.py",
        "sink": "src/track.py",
        "path": ["src/login.py", "src/track.py"],
    }
    contents = {
        "src/login.py": "email = request.form['email']",
        "src/track.py": "analytics.track(email=email)",
    }
    ev = compute_symbol_evidence(flow_path, contents)
    assert "symbol_continuity_score" in ev
    assert "source_pii_symbols" in ev
    assert "sink_pii_symbols" in ev


# ═══════════════════════════════════════════════════════════════════
# 5. Taint propagation
# ═══════════════════════════════════════════════════════════════════

def test_taint_propagates_through_assignment():
    content = "user_email = email\ndata = {'email': user_email}"
    outgoing, all_t, events = propagate_taint_in_file(content, {"email"})
    assert "user_email" in all_t
    assert len(events) >= 1


def test_taint_reaches_sink_across_path():
    files = {
        "a.py": "user_email = get_email()\nreturn user_email",
        "b.py": "data = user_email\nsend(data)",
    }
    result = trace_taint_across_path(["a.py", "b.py"], files, {"email"})
    assert result["reached_sink"] is True
    assert result["confidence"] > 0


def test_taint_does_not_reach_sink_without_pii():
    files = {
        "a.py": "request_id = generate_id()",
        "b.py": "process(request_id)",
    }
    result = trace_taint_across_path(["a.py", "b.py"], files, set())
    assert result["reached_sink"] is False
    assert result["confidence"] == 0.0


# ═══════════════════════════════════════════════════════════════════
# 6. Consent proximity
# ═══════════════════════════════════════════════════════════════════

def test_consent_detected_in_same_function():
    code = (
        "def track_user(email):\n"
        "    if check_consent(email, 'analytics'):\n"
        "        analytics.track(email)\n"
    )
    result = has_consent_near_sink(code, "analytics")
    assert result["found"] is True
    assert result["proximity"] == "same_function"


def test_consent_not_found_when_absent():
    code = "def track_user(email):\n    analytics.track(email)\n"
    result = has_consent_near_sink(code, "analytics")
    assert result["found"] is False


def test_consent_proximity_score_zero_without_consent():
    code = "analytics.track(email)"
    score = consent_proximity_score(code, "analytics")
    assert score == 0.0


def test_consent_proximity_score_high_with_purpose_specific():
    code = (
        "def send_email(email):\n"
        "    if marketing_consent(email):\n"
        "        sendgrid.send(email)\n"
    )
    score = consent_proximity_score(code, "marketing")
    assert score >= 0.7


# ═══════════════════════════════════════════════════════════════════
# 7. FK graph and deletion coverage
# ═══════════════════════════════════════════════════════════════════

def test_fk_graph_detects_foreign_key():
    contents = {
        "models/user.py": "class User(Base):\n    id = Column(Integer)\n",
        "models/order.py": "class Order(Base):\n    user_id = ForeignKey('User')\n",
    }
    graph = build_fk_graph(contents, ["models/user.py", "models/order.py"])
    assert "user" in graph.get("order", set()) or "order" in graph


def test_fk_graph_transitive_dependencies():
    graph = {"user": {"order"}, "order": {"order_item"}, "order_item": set()}
    deps = transitive_dependencies(graph, "user")
    assert "order" in deps
    assert "order_item" in deps


def test_deletion_must_cover_includes_fk_dependents():
    graph = {"user": {"session", "order"}, "session": set(), "order": {"order_item"}, "order_item": set()}
    must = deletion_must_cover(graph, {"user"})
    assert "session" in must
    assert "order" in must
    assert "order_item" in must


def test_deletion_coverage_reports_entities_and_fk():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["model_files"] = ["backend/models/user.py", "backend/models/session.py", "backend/models/order.py"]
    extracted["pii_fields"] = [
        {"file": "backend/models/user.py", "field": "email"},
        {"file": "backend/models/session.py", "field": "session_token"},
    ]
    extracted["_file_contents"] = {
        "backend/models/user.py": "class User(Base):\n    email = Column(String)\n",
        "backend/models/session.py": "class Session(Base):\n    user_id = ForeignKey('User')\n",
        "backend/models/order.py": "class Order(Base):\n    user_id = ForeignKey('User')\n",
        "backend/api/routes/user_delete.py": "def delete_user(user_id): db.delete(user)",
    }
    extracted["deletion_signals"] = [{"file": "backend/api/routes/user_delete.py"}]
    extracted["deletion_endpoints"] = [{"file": "backend/api/routes/user_delete.py", "method": "DELETE"}]
    extracted["pii_flow_graph"] = {"flow_paths": []}

    findings = data_flow.run(extracted)
    d = [f for f in findings if f.get("rule") == "INCOMPLETE_DELETION_COVERAGE"]
    assert len(d) == 1
    ev = d[0].get("evidence", {})
    assert "covered_entities" in ev
    assert "uncovered_entities" in ev
    assert "coverage_pct" in ev
    assert isinstance(ev.get("entity_to_files"), dict)
    assert "fk_graph_edges" in ev


# ═══════════════════════════════════════════════════════════════════
# 8. Purpose mismatch
# ═══════════════════════════════════════════════════════════════════

def test_purpose_mismatch_emits_for_auth_to_marketing():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": (
            "def login(email, password):\n"
            "    user = authenticate(email, password)\n"
            "    return user\n"
        ),
        "src/marketing/campaign_client.py": (
            "import mailchimp\n"
            "def send_campaign(email):\n"
            "    mailchimp.send({'email': email})\n"
        ),
    }
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/marketing/campaign_client.py",
                "path": ["src/auth/login.py", "src/marketing/campaign_client.py"],
                "hop_count": 1,
                "sink_type": "marketing_email",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    mismatch = [f for f in findings if f.get("rule") == "PII_FLOW_PURPOSE_MISMATCH"]
    assert len(mismatch) == 1
    assert mismatch[0].get("dpdp_section") == "Section 5 — Purpose Limitation"


def test_purpose_mismatch_not_emitted_for_same_purpose():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/analytics/collector.py": "def collect(event): segment.track(event)",
        "src/analytics/processor.py": "def process(event): analytics.aggregate(event)",
    }
    extracted["pii_fields"] = [{"file": "src/analytics/collector.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/analytics/collector.py",
                "sink": "src/analytics/processor.py",
                "path": ["src/analytics/collector.py", "src/analytics/processor.py"],
                "hop_count": 1,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    mismatch = [f for f in findings if f.get("rule") == "PII_FLOW_PURPOSE_MISMATCH"]
    assert len(mismatch) == 0


# ═══════════════════════════════════════════════════════════════════
# 9. Score-impact gating
# ═══════════════════════════════════════════════════════════════════

def test_low_scorable_findings_do_not_change_score():
    base_findings = [
        {
            "rule": "AUDIT_TRAIL_MISSING",
            "severity": "HIGH",
            "dpdp_section": "Section 8(4) — Audit Trail",
            "file": "N/A",
        }
    ]
    with_low_scorable = base_findings + [
        {
            "rule": "PII_FLOW_PURPOSE_MISMATCH",
            "severity": "HIGH",
            "dpdp_section": "Section 5 — Purpose Limitation",
            "file": "src/analytics/client.py",
            "scorable": False,
        }
    ]
    a = compute_compliance_score(base_findings, indexed_file_count=10)["score"]
    b = compute_compliance_score(with_low_scorable, indexed_file_count=10)["score"]
    assert a == b


def test_high_confidence_scorable_findings_lower_score():
    base = compute_compliance_score([], indexed_file_count=10)["score"]
    with_finding = compute_compliance_score(
        [
            {
                "rule": "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT",
                "severity": "HIGH",
                "dpdp_section": "Section 6 — Consent",
                "file": "src/analytics.py",
                "scorable": True,
            }
        ],
        indexed_file_count=10,
    )["score"]
    assert with_finding < base


# ═══════════════════════════════════════════════════════════════════
# 10. ML classifier
# ═══════════════════════════════════════════════════════════════════

def test_ml_feature_vector_length():
    evidence = {"sink_type": "analytics", "hop_count": 2}
    features = build_feature_vector(evidence)
    assert len(features) == 14


def test_rule_based_classifier_returns_probability():
    clf = RuleBasedFlowClassifier()
    features = [0.8, 1.0, 0.7, 0.3, 0.0, 0.0, 0.0, 0.25, 1.0, 0.0, 0.0, 0.3, 0.25, 0.4]
    is_viol, prob = clf.classify(features)
    assert 0.0 <= prob <= 1.0


def test_classify_flow_end_to_end():
    evidence = {
        "symbol_continuity_score": 0.6,
        "taint_reached_sink": True,
        "taint_confidence": 0.5,
        "taint_total_events": 3,
        "consent_found_at_sink": False,
        "consent_purpose_specific": False,
        "consent_proximity_score": 0.0,
        "hop_count": 2,
        "sink_type": "analytics",
        "pii_field_count": 2,
        "path_length": 3,
        "sink_call_arg_pii_count": 1,
    }
    result = classify_flow(evidence)
    assert "is_violation" in result
    assert "ml_confidence" in result
    assert result["classifier_type"] == "RuleBasedFlowClassifier"


def test_ml_consent_present_reduces_violation_probability():
    base = {
        "symbol_continuity_score": 0.5,
        "taint_reached_sink": True,
        "taint_confidence": 0.5,
        "taint_total_events": 2,
        "hop_count": 2,
        "sink_type": "analytics",
        "pii_field_count": 1,
        "path_length": 3,
        "sink_call_arg_pii_count": 1,
    }
    no_consent = {**base, "consent_found_at_sink": False, "consent_purpose_specific": False, "consent_proximity_score": 0.0}
    with_consent = {**base, "consent_found_at_sink": True, "consent_purpose_specific": True, "consent_proximity_score": 0.9}
    r1 = classify_flow(no_consent)
    r2 = classify_flow(with_consent)
    assert r2["ml_confidence"] < r1["ml_confidence"]


# ═══════════════════════════════════════════════════════════════════
# 11. Edge cases
# ═══════════════════════════════════════════════════════════════════

def test_empty_flow_graph_produces_no_findings():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    findings = data_flow.run(extracted)
    assert findings == []


def test_same_dir_flow_suppressed():
    """Flows within the same directory are not emitted."""
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {
        "src/auth/login.py": "email = request.email",
        "src/auth/utils.py": "analytics.track(email)",
    }
    extracted["pii_fields"] = [{"file": "src/auth/login.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/auth/login.py",
                "sink": "src/auth/utils.py",
                "path": ["src/auth/login.py", "src/auth/utils.py"],
                "hop_count": 1,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    assert len([f for f in findings if f.get("rule") == "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT"]) == 0


def test_self_loop_flow_suppressed():
    data_flow.FLOW_VERIFY_MAX = 0
    extracted = _base_extracted()
    extracted["_file_contents"] = {"src/app.py": "email = input(); analytics.track(email)"}
    extracted["pii_fields"] = [{"file": "src/app.py", "field": "email"}]
    extracted["pii_flow_graph"] = {
        "flow_paths": [
            {
                "source": "src/app.py",
                "sink": "src/app.py",
                "path": ["src/app.py"],
                "hop_count": 0,
                "sink_type": "analytics",
                "pii_fields": ["email"],
            }
        ]
    }
    findings = data_flow.run(extracted)
    assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _expected_scorable(confidence: float) -> bool:
    return confidence >= 0.75
