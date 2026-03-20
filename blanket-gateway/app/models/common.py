from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PaginationMeta(BaseModel):
    page: int
    page_size: int
    total: int


class ApiResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    meta: PaginationMeta | None = None


class ErrorDetail(BaseModel):
    status: str = "error"
    detail: str
