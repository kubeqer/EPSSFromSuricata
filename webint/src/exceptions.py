from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR


class BaseAppException(Exception):
    """Base exception for application errors"""

    status_code: int = HTTP_500_INTERNAL_SERVER_ERROR
    detail: str = "An unexpected error occurred"

    def __init__(self, detail: str = None):
        if detail:
            self.detail = detail
        super().__init__(self.detail)


class NotFoundException(BaseAppException):
    """Exception for resource not found errors"""

    status_code: int = HTTP_404_NOT_FOUND
    detail: str = "Resource not found"


async def exception_handler(request: Request, exc: BaseAppException):
    """Global exception handler for application exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


def register_exception_handlers(app):
    """Register exception handlers with the FastAPI app"""
    app.add_exception_handler(BaseAppException, exception_handler)
