from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict


FP_LOG_PATH = Path(".dpdp-history") / "fp_log.jsonl"


def record_false_positive(rule: str, file_path: str, repo_hint: str = "") -> Path:
    FP_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "rule": (rule or "").strip(),
        "file": (file_path or "").strip(),
        "repo_hint": (repo_hint or os.getcwd()).strip(),
    }
    with FP_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    return FP_LOG_PATH


def load_false_positive_penalties() -> Dict[str, float]:
    """
    Reduce confidence by 0.05 after 3 distinct repo reports, capped at 0.20.
    """
    if not FP_LOG_PATH.is_file():
        return {}
    per_rule_repos: Dict[str, set[str]] = {}
    try:
        for line in FP_LOG_PATH.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            rule = str(item.get("rule") or "").strip()
            repo_hint = str(item.get("repo_hint") or "").strip()
            if not rule or not repo_hint:
                continue
            per_rule_repos.setdefault(rule, set()).add(repo_hint)
    except Exception:
        return {}
    penalties: Dict[str, float] = {}
    for rule, repos in per_rule_repos.items():
        if len(repos) < 3:
            continue
        steps = min(4, len(repos) // 3)
        penalties[rule] = round(0.05 * steps, 2)
    return penalties
