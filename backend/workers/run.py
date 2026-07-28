"""
Start RQ worker for org bulk scans.

Usage:
  set USE_SQLITE=1
  set REDIS_URL=redis://127.0.0.1:6379/0
  py -3 -m backend.workers.run
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from redis import Redis
from rq import Worker, Queue

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
QUEUE_NAME = os.environ.get("DPDP_RQ_QUEUE", "dpdp-scans")


def main() -> None:
    conn = Redis.from_url(REDIS_URL)
    queues = [Queue(QUEUE_NAME, connection=conn)]
    worker = Worker(queues, connection=conn)
    print(f"RQ worker listening on queue '{QUEUE_NAME}' ({REDIS_URL})")
    worker.work()


if __name__ == "__main__":
    main()
