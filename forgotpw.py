#!/usr/bin/env python3
from database import get_users_db
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import bcrypt
import json
import os

SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
get_users_db = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True)  # Will use email as username
    name = Column(String(100))
    email = Column(String(100), unique=True)
    phone = Column(String(20))
    department = Column(String(50))
    role = Column(String(20))
    password_hash = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def create_initial_users():
    try:
        # Drop and recreate tables
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        
        db = get_users_db()

        # Initial users with email as username
        users = [
            User(
                username="fabianannomerz@gmail.com",  # Email as username
                name="Fabian Merz",
                email="fabianannomerz@gmail.com",
                phone="**621",
                department="Security",
                role="admin",
                password_hash=hash_password("admin")
            )
        ]

        for user in users:
            db.add(user)
            print(f"Creating user: {user.name} (username: {user.username})")

        db.commit()
        print(f"\nSuccessfully created {len(users)} users")

    except Exception as e:
        print(f"Error: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    create_initial_users()