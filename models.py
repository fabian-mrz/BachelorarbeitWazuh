from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey
from datetime import datetime
from database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True)
    name = Column(String(100))
    email = Column(String(100), unique=True)
    phone = Column(String(20))
    department = Column(String(50))
    role = Column(String(20))
    password_hash = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=True)
    description = Column(JSON)
    severity = Column(Integer, nullable=True)
    source = Column(String, nullable=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String, nullable=True)
    escalated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    archived = Column(Boolean, default=False)
    archived_at = Column(DateTime, nullable=True)
    archived_by = Column(String, nullable=True)
    update_count = Column(Integer, default=0)
    archived_version = relationship("ArchivedIncidentModel", back_populates="original_incident", uselist=False)

        
    

class ArchivedIncidentModel(Base):
    __tablename__ = "archived_incidents"

    id = Column(String, primary_key=True)
    original_id = Column(String, ForeignKey('incidents.id'))
    title = Column(String, nullable=True)
    description = Column(JSON)
    severity = Column(Integer, nullable=True)
    source = Column(String, nullable=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String, nullable=True)
    escalated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    archived_at = Column(DateTime, default=datetime.now)
    archived_by = Column(String, nullable=True)
    update_count = Column(Integer, default=0)
    archive_reason = Column(String, nullable=True)
    archive_notes = Column(String, nullable=True)

    # Relationship to original incident
    original_incident = relationship("IncidentModel", back_populates="archived_version")


