from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

# Database URLs
USERS_DATABASE_URL = "sqlite:///./users.db"
INCIDENTS_DATABASE_URL = "sqlite:///./incidents.db"

# Create engines
users_engine = create_engine(
    USERS_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

incidents_engine = create_engine(
    INCIDENTS_DATABASE_URL,
    pool_size=20,
    max_overflow=20,
    pool_timeout=60,
    pool_pre_ping=True
)

# Create sessions
UsersSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=users_engine)
IncidentsSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=incidents_engine)

# Shared declarative base
Base = declarative_base()

# Database dependency injectors
def get_users_db():
    db = UsersSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_incidents_db():
    db = IncidentsSessionLocal()
    try:
        yield db
    finally:
        db.close()