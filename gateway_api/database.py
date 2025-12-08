# gateway_api/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

# Create database engine
engine = create_engine('sqlite:///./wireguard.db')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """
    Initialize database with schema.
    This will create new tables if they don't exist
    and update existing ones to match the new schema.
    """
    # Create all tables
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

