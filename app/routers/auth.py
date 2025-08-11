"""
Authentication endpoints for the Restaurant Booking Mock API.

This module provides mock authentication endpoints that simulate a real authentication system.
It includes login, token refresh, and logout endpoints for frontend integration testing.
"""

from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Form, Depends, status
from pydantic import BaseModel
from typing import Optional
import jwt
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Import from centralized auth module
from app.auth import (
    MOCK_USERS, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, 
    get_current_user, CurrentUser, LEGACY_MOCK_TOKEN
)
from app.database import get_db
from app.models import Customer

# Router configuration
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)

# Token expiration constants
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Response models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int

class TokenRefresh(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class UserInfo(BaseModel):
    email: str
    name: str
    role: str

class LoginResponse(BaseModel):
    user: UserInfo
    token: Token

class RegisterRequest(BaseModel):
    firstName: str
    lastName: str
    email: str
    phone: str
    password: str
    confirmPassword: str

class RegisterResponse(BaseModel):
    message: str
    user: UserInfo

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/login", response_model=LoginResponse, summary="User Login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
) -> LoginResponse:
    """
    Authenticate user and return access and refresh tokens.
    
    **Mock Credentials:**
    - Email: `test@restaurant.com`, Password: `password123`
    - Email: `admin@restaurant.com`, Password: `admin123`
    
    Args:
        email: User email address
        password: User password
        
    Returns:
        LoginResponse: User information and authentication tokens
        
    Raises:
        HTTPException: 401 if credentials are invalid
    """
    user_name = None
    user_role = "user"
    
    # First check hardcoded mock users
    if email in MOCK_USERS:
        user = MOCK_USERS[email]
        if user["password"] == password:
            user_name = user["name"]
            user_role = user["role"]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        # Check database for registered users
        customer = db.query(Customer).filter(Customer.email == email).first()
        if not customer or not customer.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verify password hash
        if not verify_password(password, customer.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_name = f"{customer.first_name} {customer.surname}"
        user_role = "user"
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": email, "role": user_role}, 
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": email}, 
        expires_delta=refresh_token_expires
    )
    
    return LoginResponse(
        user=UserInfo(email=email, name=user_name, role=user_role),
        token=Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    )

@router.post("/register", response_model=RegisterResponse, summary="User Registration")
async def register(
    firstName: str = Form(...),
    lastName: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    confirmPassword: str = Form(...),
    db: Session = Depends(get_db)
) -> RegisterResponse:
    """
    Register a new user account.
    
    Args:
        firstName: User's first name
        lastName: User's last name  
        email: User's email address
        phone: User's phone number
        password: User's password
        confirmPassword: Password confirmation
        db: Database session
        
    Returns:
        RegisterResponse: Registration confirmation and user info
        
    Raises:
        HTTPException: 400 if validation fails or user already exists
    """
    # Validate passwords match
    if password != confirmPassword:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )
    
    # Validate password length
    if len(password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters long"
        )
    
    # Check if user already exists
    existing_customer = db.query(Customer).filter(Customer.email == email).first()
    if existing_customer:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered"
        )
    
    # Check if email exists in mock users (for authentication)
    if email in MOCK_USERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered"
        )
    
    try:
        # Create new customer record with hashed password
        hashed_password = get_password_hash(password)
        new_customer = Customer(
            first_name=firstName,
            surname=lastName,
            email=email,
            mobile=phone,
            phone=phone,
            password_hash=hashed_password,
            receive_email_marketing=False,
            receive_sms_marketing=False,
            receive_restaurant_email_marketing=False,
            receive_restaurant_sms_marketing=False
        )
        
        db.add(new_customer)
        db.commit()
        db.refresh(new_customer)
        
        return RegisterResponse(
            message="Account created successfully",
            user=UserInfo(
                email=email,
                name=f"{firstName} {lastName}",
                role="user"
            )
        )
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create account"
        )

@router.post("/refresh", response_model=TokenRefresh, summary="Refresh Token")
async def refresh_token(refresh_token: str = Form(...)) -> TokenRefresh:
    """
    Refresh an access token using a valid refresh token.
    
    Args:
        refresh_token: Valid refresh token
        
    Returns:
        TokenRefresh: New access token
        
    Raises:
        HTTPException: 401 if refresh token is invalid or expired
    """
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if email is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        user = MOCK_USERS.get(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email, "role": user["role"]}, 
        expires_delta=access_token_expires
    )
    
    return TokenRefresh(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@router.get("/me", response_model=UserInfo, summary="Get Current User")
async def get_current_user_info(current_user: CurrentUser = Depends(get_current_user)) -> UserInfo:
    """
    Get current user information from access token.
    
    Args:
        current_user: Current user from JWT token
        
    Returns:
        UserInfo: Current user information
    """
    return UserInfo(
        email=current_user.email,
        name=current_user.name,
        role=current_user.role
    )

@router.post("/logout", summary="User Logout")
async def logout():
    """
    Logout user (for mock API, this just returns success).
    
    In a real implementation, this would invalidate the token.
    
    Returns:
        dict: Success message
    """
    return {"message": "Successfully logged out"}

@router.get("/test-token", summary="Get Test Token")
async def get_test_token():
    """
    Get the original hardcoded token for backward compatibility.
    
    This endpoint provides the same token that was hardcoded in the system
    for easy testing and backward compatibility.
    
    Returns:
        dict: The hardcoded Bearer token
    """
    return {
        "token": LEGACY_MOCK_TOKEN,
        "token_type": "bearer",
        "note": "This is the hardcoded token for backward compatibility. Use /login for dynamic tokens."
    }