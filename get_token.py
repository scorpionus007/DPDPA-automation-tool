from backend.auth import create_access_token
from backend.database import SessionLocal
from backend.models import User
from datetime import timedelta

db = SessionLocal()
user = db.query(User).first()
if user:
    token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=30))
    print(f"TOKEN: {token}")
else:
    print("No user found")
db.close()
