import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "rohang1003")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "dpdp_scanner_db")

url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(url)

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN github_access_token VARCHAR;"))
        conn.commit()
        print("Migration successful: Added github_access_token column.")
    except Exception as e:
        print(f"Migration error: {e}")
