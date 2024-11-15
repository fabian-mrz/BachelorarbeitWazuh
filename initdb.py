#!/usr/bin/env python3
from auth import register_user, SessionLocal, Base, engine
from fastapi import HTTPException
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    try:
        # Create admin user
        admin_user = register_user("admin", "admin")
        logger.info("Admin user created successfully")
        return True
    except HTTPException as e:
        if e.detail == "Username already registered":
            logger.info("Admin user already exists")
        else:
            logger.error(f"Error creating admin user: {e.detail}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return False

if __name__ == "__main__":
    init_db()