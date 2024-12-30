from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import StaticPool

# Database URLs
USERS_DATABASE_URL = "sqlite:///./users.db"
INCIDENTS_DATABASE_URL = "sqlite:///./incidents.db"

# Create engines with SQLite-compatible settings
users_engine = create_engine(
    USERS_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

incidents_engine = create_engine(
    INCIDENTS_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,  # Use static pool for SQLite
)

# Enable foreign key support for SQLite
@event.listens_for(incidents_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

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