"""Enqueue scan jobs via RQ or inline thread fallback."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

_executor: Optional[ThreadPoolExecutor] = None


def get_redis_url() -> str:
    return os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")


def get_queue_name() -> str:
    return os.environ.get("DPDP_RQ_QUEUE", "dpdp-scans")


def is_rq_available() -> bool:
    try:
        from redis import Redis

        conn = Redis.from_url(get_redis_url(), socket_connect_timeout=1)
        conn.ping()
        return True
    except Exception:
        return False


def enqueue_scan_job(scan_job_id: int) -> Optional[str]:
    """Enqueue run_scan_job. Returns rq job id or 'inline'."""
    from backend.workers.scan_runner import run_scan_job

    if is_rq_available():
        from redis import Redis
        from rq import Queue

        conn = Redis.from_url(get_redis_url())
        q = Queue(get_queue_name(), connection=conn)
        job = q.enqueue(run_scan_job, scan_job_id, job_timeout="2h")
        return job.id
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=int(os.environ.get("DPDP_INLINE_WORKERS", "4")))
    _executor.submit(run_scan_job, scan_job_id)
    return "inline"


def enqueue_org_report(org_report_id: int) -> Optional[str]:
    from backend.workers.scan_runner import generate_org_report_job

    if is_rq_available():
        from redis import Redis
        from rq import Queue

        conn = Redis.from_url(get_redis_url())
        q = Queue(get_queue_name(), connection=conn)
        job = q.enqueue(generate_org_report_job, org_report_id, job_timeout="1h")
        return job.id
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=2)
    _executor.submit(generate_org_report_job, org_report_id)
    return "inline"
