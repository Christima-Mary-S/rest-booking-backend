"""
Centralized JWT Authentication Module for Restaurant Booking API.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

# JWT configuration
SECRET_KEY = "mock-secret-key-for-testing-only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security scheme for swagger UI
security = HTTPBearer()

# Mock users database (same as in auth router)
MOCK_USERS = {
    "test@restaurant.com": {
        "password": "password123",
        "name": "Test User",
        "role": "user"
    },
    "admin@restaurant.com": {
        "password": "admin123", 
        "name": "Admin User",
        "role": "admin"
    }
}

# For backward compatibility with the hardcoded token
LEGACY_MOCK_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImFwcGVsbGErYXBpQHJlc2"
    "RpYXJ5LmNvbSIsIm5iZiI6MTc1NDQzMDgwNSwiZXhwIjoxNzU0NTE3MjA1LCJpYXQiOjE3NTQ0MzA4"
    "MDUsImlzcyI6IlNlbGYiLCJhdWQiOiJodHRwczovL2FwaS5yZXNkaWFyeS5jb20ifQ.g3yLsufdk8Fn"
    "2094SB3J3XW-KdBc0DY9a2Jiu_56ud8"
)

class TokenData(BaseModel):
    """Token payload data model."""
    email: Optional[str] = None
    role: Optional[str] = None

class CurrentUser(BaseModel):
    """Current authenticated user model."""
    email: str
    name: str
    role: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode in the token
        expires_delta: Token expiration time delta
        
    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> TokenData:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        TokenData: Decoded token data
        
    Raises:
        HTTPException: If token is invalid, expired, or malformed
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check for legacy hardcoded token for backward compatibility
    if token == LEGACY_MOCK_TOKEN:
        return TokenData(email="legacy@restaurant.com", role="user")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")
        
        if email is None:
            raise credentials_exception
            
        token_data = TokenData(email=email, role=role)
        return token_data
        
    except jwt.PyJWTError:
        raise credentials_exception

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> CurrentUser:
    """
    Dependency to get the current authenticated user.
    
    Args:
        credentials: HTTP Bearer credentials from Authorization header
        
    Returns:
        CurrentUser: Current authenticated user information
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    token = credentials.credentials
    token_data = verify_token(token)
    
    # Handle legacy token
    if token_data.email == "legacy@restaurant.com":
        return CurrentUser(
            email="legacy@restaurant.com",
            name="Legacy User",
            role="user"
        )
    
    # First check mock users
    user = MOCK_USERS.get(token_data.email)
    if user:
        return CurrentUser(
            email=token_data.email,
            name=user["name"],
            role=user["role"]
        )
    
    # Then check database for registered users
    try:
        # Import locally to avoid circular imports
        from app.database import SessionLocal
        from app.models import Customer
        
        db = SessionLocal()
        customer = db.query(Customer).filter(Customer.email == token_data.email).first()
        db.close()
        
        if customer:
            return CurrentUser(
                email=token_data.email,
                name=f"{customer.first_name} {customer.surname}",
                role="user"
            )
    except Exception as e:
        # If database query fails, fall through to "User not found"
        pass
    
    # User not found in either place
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="User not found",
        headers={"WWW-Authenticate": "Bearer"},
    )

def get_current_active_user(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """
    Dependency to get current active user (for future extensibility).
    
    Args:
        current_user: Current user from get_current_user dependency
        
    Returns:
        CurrentUser: Current active user
    """
    return current_user

# Convenience function for backward compatibility with existing verify_token functions
def verify_bearer_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Backward compatibility function that mimics the old verify_token behavior.
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        str: The token string (for compatibility)
        
    Raises:
        HTTPException: If authentication fails
    """
    # This will validate the token and raise exceptions if invalid
    get_current_user(credentials)
    # Return the token for backward compatibility
    return credentials.credentials