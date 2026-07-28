import os
from urllib.parse import quote_plus

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

_load_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_load_env)

# Optional: set DATABASE_URL in .env to override everything, e.g.
# postgresql://postgres:secret@127.0.0.1:5432/mydb
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Optional: USE_SQLITE=1 for local dev without PostgreSQL (file: backend/compliance_local.db)
USE_SQLITE = os.environ.get("USE_SQLITE", "").strip().lower() in ("1", "true", "yes")

DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "postgres")
# Use 127.0.0.1 by default — on Windows, "localhost" often resolves to ::1 first and can fail
# with "password authentication failed" even when the password is correct for 127.0.0.1.
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "dpdp_scanner_db")

if DATABASE_URL:
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    _engine_kwargs = {}
elif USE_SQLITE:
    _db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance_local.db")
    SQLALCHEMY_DATABASE_URL = f"sqlite:///{_db_path.replace(chr(92), '/')}"
    _engine_kwargs = {"connect_args": {"check_same_thread": False}}
else:
    # URL-encode user/password (handles @, :, spaces, etc.)
    user_enc = quote_plus(DB_USER)
    pass_enc = quote_plus(DB_PASSWORD)
    SQLALCHEMY_DATABASE_URL = (
        f"postgresql://{user_enc}:{pass_enc}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    _engine_kwargs = {}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency for FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
