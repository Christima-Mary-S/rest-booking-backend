"""
Restaurant endpoints for listing and managing restaurants.

This module provides endpoints to get restaurant information and details.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime

from app.database import get_db
from app.models import Restaurant
from app.auth import verify_bearer_token

# Router configuration
router = APIRouter(prefix="/api/restaurants", tags=["Restaurants"])

# Response models
class RestaurantResponse(BaseModel):
    id: int
    name: str
    microsite_name: str
    created_at: datetime

    class Config:
        from_attributes = True

class RestaurantsListResponse(BaseModel):
    restaurants: List[RestaurantResponse]
    total_count: int

@router.get("/", response_model=RestaurantsListResponse, summary="List All Restaurants")
async def get_restaurants(
    db: Session = Depends(get_db),
    token: str = Depends(verify_bearer_token)
) -> RestaurantsListResponse:
    """
    Get a list of all restaurants in the system.

    This endpoint returns all restaurants available for booking.
    Each restaurant includes basic information like name and microsite identifier.

    Args:
        db: Database session dependency
        token: Authentication token dependency

    Returns:
        RestaurantsListResponse: List of restaurants with count

    Raises:
        HTTPException: 401 if authentication fails
    """
    restaurants = db.query(Restaurant).all()
    
    return RestaurantsListResponse(
        restaurants=[RestaurantResponse.from_orm(restaurant) for restaurant in restaurants],
        total_count=len(restaurants)
    )

@router.get("/{restaurant_name}", response_model=RestaurantResponse, summary="Get Restaurant Details")
async def get_restaurant_by_name(
    restaurant_name: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_bearer_token)
) -> RestaurantResponse:
    """
    Get details of a specific restaurant by name.

    Args:
        restaurant_name: Name of the restaurant to retrieve
        db: Database session dependency
        token: Authentication token dependency

    Returns:
        RestaurantResponse: Restaurant details

    Raises:
        HTTPException: 401 if authentication fails, 404 if restaurant not found
    """
    restaurant = db.query(Restaurant).filter(Restaurant.name == restaurant_name).first()
    
    if not restaurant:
        raise HTTPException(
            status_code=404,
            detail=f"Restaurant '{restaurant_name}' not found"
        )
    
    return RestaurantResponse.from_orm(restaurant)