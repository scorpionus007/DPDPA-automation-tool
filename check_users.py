from backend.database import SessionLocal
from backend.models import User

db = SessionLocal()
users = db.query(User).all()
print("ID | Username | Email | Github ID")
print("-" * 40)
for u in users:
    print(f"{u.id} | {u.username} | {u.email} | {u.github_id!r}")
db.close()
