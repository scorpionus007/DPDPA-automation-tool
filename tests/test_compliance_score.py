"""Tests for compliance scoring edge cases."""
import pytest

from dpdp_scanner.rule_engine import compute_compliance_score


def test_score_none_when_zero_indexed_files():
    out = compute_compliance_score([], indexed_file_count=0)
    assert out["score"] is None
    assert out.get("score_unreliable") is True
    assert out.get("score_unreliable_reason") == "no_indexed_source_files"
    assert out["grade"] == "N/A"


def test_score_numeric_when_files_indexed():
    out = compute_compliance_score([], indexed_file_count=1)
    assert isinstance(out["score"], int)
    assert out["score"] == 100
    assert out.get("score_unreliable") is None


def test_default_indexed_none_behaves_like_normal():
    out = compute_compliance_score([])
    assert isinstance(out["score"], int)
