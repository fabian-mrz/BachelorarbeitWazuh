#!/usr/bin/env python3
from auth import register_user, SessionLocal, Base, engine
from fastapi import HTTPException
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    success = True
    try:
        # Create admin user
        admin_user = register_user("admin", "admin", role="admin")
        logger.info("Admin user created successfully")
        
        # Create analyst user
        analyst_user = register_user("analyst", "analyst", role="analyst")
        logger.info("Analyst user created successfully")
        
    except HTTPException as e:
        if e.detail == "Username already registered":
            logger.info("User already exists")
        else:
            logger.error(f"Error creating user: {e.detail}")
        success = False
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        success = False
    
    return success

if __name__ == "__main__":
    init_db()