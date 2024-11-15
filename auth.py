from datetime import datetime, timezone, timedelta
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
import logging
from sqlalchemy.orm import Session
from jwt import ExpiredSignatureError, InvalidTokenError  # Updated imports
import jwt
from functools import wraps
from fastapi import Depends

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String)  # Changed from Enum to String

Base.metadata.create_all(bind=engine)

# JWT Configuration
SECRET_KEY = "test"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


security = HTTPBearer()
logger = logging.getLogger(__name__)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

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
        logger.debug(f"Verifying token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.debug(f"Token payload: {payload}")
        return payload
    except ExpiredSignatureError:
        logger.error("Token has expired")
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
def is_admin(token = Depends(verify_token)):
    db = next(get_db())
    user = db.query(User).filter(User.username == token.get("sub")).first()
    if not user or user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required"
        )
    return user


def verify_auth(username: str, password: str):
    db = next(get_db())
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    return verify_password(password, user.password_hash)

def register_user(username: str, password: str, role: str = None):
    db = next(get_db())
    
    # Validate role as string
    valid_roles = ["admin", "analyst"]
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'analyst'")
    
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Create user with string role
    user = User(
        username=username,
        password_hash=get_password_hash(password),
        role=role  # Will store as plain string
    )
    db.add(user)
    db.commit()
    return user