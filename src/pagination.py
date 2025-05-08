from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field
from fastapi import Query
from sqlalchemy.orm import Query as SQLAlchemyQuery

T = TypeVar("T")


class PaginationParams:
    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number"),
        limit: int = Query(50, ge=1, le=100, description="Items per page"),
    ):
        self.page = page
        self.limit = limit
        self.offset = (page - 1) * limit


class Page(BaseModel, Generic[T]):
    """Pagination response model"""

    items: List[T]
    total: int
    page: int
    limit: int
    pages: int = Field(..., description="Total number of pages")

    @classmethod
    def create(cls, items: List[T], total: int, params: PaginationParams):
        """Create a paginated response"""
        pages = (total + params.limit - 1) // params.limit if total > 0 else 0
        return cls(
            items=items, total=total, page=params.page, limit=params.limit, pages=pages
        )


def paginate(query: SQLAlchemyQuery, params: PaginationParams) -> tuple:
    """Apply pagination to a SQLAlchemy query"""
    total = query.count()
    items = query.offset(params.offset).limit(params.limit).all()
    return items, total
