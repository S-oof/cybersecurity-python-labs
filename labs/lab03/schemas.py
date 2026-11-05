"""Pydantic-моделі валідації вхідних та вихідних даних API (Варіант 8)."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class CategoryBase(BaseModel): #перевіряє чи джсон не суперечить вимогам перед записом у базу даних
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )
    # Межі 2-40 точно відповідають CHECK-обмеженню у schema.sql
    name: str = Field(min_length=2, max_length=40)


class CategoryCreate(CategoryBase):
    """Схема створення категорії через POST /categories (без id)."""
    pass


class CategoryRead(CategoryBase): # перевіряє чи айді більше 0
    """Схема читання категорії з id."""
    id: int = Field(gt=0)


class RecordBase(BaseModel): 
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid", 
    )
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=0.0, allow_inf_nan=False) 
    status: Literal["new", "in_progress", "done"]


class RecordCreate(RecordBase):
    """Схема створення запису через POST /records."""
    code: str = Field(min_length=3, max_length=40)


class RecordReplace(RecordCreate):
    """Схема повної заміни запису через PUT /records/{record_id}."""
    pass

class RecordRead(RecordCreate):
    """Схема читання запису з id та category_name (після JOIN)."""
    id: int = Field(gt=0)
    category_name: str = Field(min_length=2, max_length=40)