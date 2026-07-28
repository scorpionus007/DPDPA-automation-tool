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
        # Create scans table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                repo_name VARCHAR NOT NULL,
                repo_url VARCHAR NOT NULL,
                branch VARCHAR DEFAULT 'main',
                score INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                findings_high INTEGER DEFAULT 0,
                findings_medium INTEGER DEFAULT 0,
                findings_low INTEGER DEFAULT 0,
                status VARCHAR DEFAULT 'completed',
                compliance_data JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                owner_id INTEGER REFERENCES users(id)
            );
        """))
        conn.commit()
        print("Migration successful: Created scans table.")
    except Exception as e:
        print(f"Migration error: {e}")
