"""Маршрути Web API для управління категоріями (Варіант 8)."""

import sqlite3
from fastapi import APIRouter, HTTPException, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead], status_code=status.HTTP_200_OK)
def list_categories():
    """Отримати список усіх категорій у порядку зростання ID."""
    return repository.get_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: CategoryCreate):
    """Створити нову категорію (ID генерується базою)."""
    try:
        return repository.create_category(category)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія з такою назвою вже існує.",
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    """Видалити порожню категорію за ID."""
    if category_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID категорії повинен бути додатним цілим числом.",
        )

    result = repository.delete_category(category_id)
    if result == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Категорію не знайдено.",
        )
    if result == "conflict":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Неможливо видалити категорію, яка містить записи.",
        )
    
    # Для HTTP 204 тіло відповіді залишається порожнім
    return None