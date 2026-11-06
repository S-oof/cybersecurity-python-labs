"""Маршрути для категорій."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])

CategoryId = Annotated[int, Path(gt=0, description="ID категорії (додатне ціле)")]


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Усі категорії за зростанням id."""
    return repository.get_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate) -> dict:
    """Створити категорію; id генерує база."""
    try:
        return repository.create_category(category)
    except repository.ConflictError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> None:
    """Видалити категорію, у якій немає записів."""
    try:
        repository.delete_category(category_id)
    except repository.NotFoundError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    except repository.ConflictError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
