from backend.database import SessionLocal
from backend.models import Scan

db = SessionLocal()
scans = db.query(Scan).all()
for s in scans:
    print(f"ID: {s.id}, Repo: {s.repo_name}, Path: {s.report_path}")
db.close()
