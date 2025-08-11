"""
Restaurant Booking Mock API Server.

A complete FastAPI-based mock server that simulates a restaurant booking system.
This server provides realistic endpoints for availability checking, booking creation,
booking management, and cancellation operations.

Author: AI Assistant
Version: 1.0.0
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import availability, booking, auth, restaurants
from app.database import engine
from app.models import Base
import app.init_db as init_db

# Create database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Restaurant Booking Mock API",
    description=(
        "A complete mock restaurant booking management system built with FastAPI "
        "and SQLite. Provides realistic endpoints for testing applications."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174", 
        "http://localhost:3000", 
        "http://localhost:8080",  
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth.router)
app.include_router(restaurants.router)
app.include_router(availability.router)
app.include_router(booking.router)


@app.on_event("startup")
async def startup_event() -> None:
    """
    Initialize database with sample data on application startup.

    This function is called once when the FastAPI application starts.
    It ensures the database contains sample restaurant data and availability slots.
    """
    init_db.init_sample_data()


@app.get("/", summary="API Information", tags=["Root"])
async def root() -> dict:
    """
    Get API information and available endpoints.

    Returns:
        dict: API metadata including version and available endpoint URLs.
    """
    return {
        "message": "Restaurant Booking Mock API",
        "version": "1.0.0",
        "description": "Mock restaurant booking system for testing applications",
        "endpoints": {
            "login": "/api/auth/login",
            "refresh_token": "/api/auth/refresh",
            "get_user": "/api/auth/me",
            "logout": "/api/auth/logout",
            "test_token": "/api/auth/test-token",
            "list_restaurants": "/api/restaurants",
            "get_restaurant": "/api/restaurants/{restaurant_name}",
            "availability_search": (
                "/api/ConsumerApi/v1/Restaurant/{restaurant_name}/"
                "AvailabilitySearch"
            ),
            "create_booking": (
                "/api/ConsumerApi/v1/Restaurant/{restaurant_name}/"
                "BookingWithStripeToken"
            ),
            "cancel_booking": (
                "/api/ConsumerApi/v1/Restaurant/{restaurant_name}/Booking/"
                "{booking_reference}/Cancel"
            ),
            "get_booking": (
                "/api/ConsumerApi/v1/Restaurant/{restaurant_name}/Booking/"
                "{booking_reference}"
            ),
            "update_booking": (
                "/api/ConsumerApi/v1/Restaurant/{restaurant_name}/Booking/"
                "{booking_reference}"
            ),
            "docs": "/docs",
            "redoc": "/redoc"
        }
    }
