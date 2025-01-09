from datetime import datetime, timezone, timedelta
import jwt
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError  #
from passlib.context import CryptContext
import logging
from jwt import ExpiredSignatureError, InvalidTokenError
from functools import wraps
import time
from database import get_users_db
from models import User
from logger import logger
from configparser import ConfigParser



# Optional: Add file handler to also log to a file
file_handler = logging.FileHandler('auth.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# Single CryptContext instance
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

class PasswordManager:
    @staticmethod
    def hash(password: str) -> str:
        """Single source for password hashing"""
        try:
            # Ensure string input
            if isinstance(password, bytes):
                password = password.decode()
            return pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Hashing error: {str(e)}")
            raise

    @staticmethod
    def verify(plain_password: str, hashed_password: str) -> bool:
        """Single source for password verification"""
        try:
            # Ensure string inputs
            if isinstance(plain_password, bytes):
                plain_password = plain_password.decode()
            if isinstance(hashed_password, bytes):
                hashed_password = hashed_password.decode()
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Verification error: {str(e)}")
            return False

# JWT Configuration
def get_secret_key():
    config = ConfigParser()
    try:
        config.read('config.ini')
        return config['AUTH']['secret_key']
    except:
        return "asdasdfljnasdkfaljkdflkasfawe8"  # fallback

SECRET_KEY = get_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


security = HTTPBearer()



def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Created token: {token}")
    return token

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        token = credentials.credentials
        start_time = time.time()
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        decode_time = time.time() - start_time
        return payload
    except ExpiredSignatureError as e:
        logger.error(f"Token expired: {str(e)}")
        logger.error(f"Token expiry details: {e.__dict__}")
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError as e:
        logger.error(f"Invalid token error: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error details: {e.__dict__}")
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def is_admin(token = Depends(verify_token)):
    logger.info("Starting admin check...")
    
    try:
        if not token or 'sub' not in token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )

        db = next(get_users_db())
        user = db.query(User).filter(User.username == token["sub"]).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
            
        if user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Admin access required. Current role: {user.role}"
            )
            
        logger.info(f"Admin check successful: {user.username}")
        return user
        
    except HTTPException as he:
        # Let HTTP exceptions propagate as-is
        raise he
    except Exception as e:
        logger.error(f"Admin check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authorization"
        )
    finally:
        if 'db' in locals():
            db.close()

def verify_auth(username: str, password: str):
    try:
        db = next(get_users_db())
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return False
        return PasswordManager.verify(password, user.password_hash)
    except Exception as e:
        logger.error(f"Error verifying authentication: {str(e)}")
        return False

def register_user(username: str, password: str, role: str = None):
    try:
        db = next(get_users_db())
        
        valid_roles = ["admin", "analyst"]
        if role not in valid_roles:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'analyst'")
        
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        
        user = User(
            username=username,
            password_hash=PasswordManager.hash(password),
            role=role
        )
        db.add(user)
        db.commit()
        return user
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )