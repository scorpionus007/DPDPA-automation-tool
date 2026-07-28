import os  # noqa: F401
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base  # noqa: F401
from backend.models import User, Scan
from datetime import datetime, timedelta

def load_dotenv():
    return None # placeholder

engine = create_engine("postgresql://postgres:rohang1003@localhost:5432/dpdp_scanner_db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# Get first user
user = db.query(User).first()
if user:
    # Create some mock scans for this user
    scans = [
        Scan(
            repo_name="node-express-api",
            repo_url="https://github.com/rohang/node-express-api",
            score=78,
            findings_count=8,
            findings_high=2,
            findings_medium=4,
            findings_low=2,
            status="review",
            owner_id=user.id,
            created_at=datetime.utcnow() - timedelta(days=1)
        ),
        Scan(
            repo_name="react-dashboard",
            repo_url="https://github.com/rohang/react-dashboard",
            score=92,
            findings_count=3,
            findings_high=0,
            findings_medium=1,
            findings_low=2,
            status="completed",
            owner_id=user.id,
            created_at=datetime.utcnow() - timedelta(days=2)
        ),
        Scan(
            repo_name="fastapi-backend",
            repo_url="https://github.com/rohang/fastapi-backend",
            score=45,
            findings_count=15,
            findings_high=5,
            findings_medium=7,
            findings_low=3,
            status="critical",
            owner_id=user.id,
            created_at=datetime.utcnow() - timedelta(days=4)
        )
    ]
    db.add_all(scans)
    db.commit()
    print(f"Seed data added for user: {user.email}")
else:
    print("No user found to seed data for.")
db.close()
