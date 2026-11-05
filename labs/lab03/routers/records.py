"""Маршрути Web API для управління записами вимірювань (Варіант 8)."""

import sqlite3
from typing import Literal
from fastapi import APIRouter, HTTPException, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead], status_code=status.HTTP_200_OK)
def get_records(
    category_id: int | None = Query(None, gt=0),
    status_filter: Literal["new", "in_progress", "done"] | None = Query(None, alias="status"),
    min_value: float | None = Query(None, ge=0.0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Отримати список записів із можливістю фільтрації, пошуку та пагінації."""
    return repository.get_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post("/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED)
def create_records_bulk(records: list[RecordCreate]):
    """Пакетне створення записів в одній атомарній транзакції (від 1 до 100 записів)."""
    if len(records) < 1 or len(records) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Кількість елементів пакета повинна бути від 1 до 100.",
        )
    try:
        return repository.create_records_bulk(records)
    except ValueError as err:
        if str(err) == "category_not_found":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Вкажіть існуючу категорію для всіх записів пакета.",
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Конфлікт унікальності code в базі або всередині пакета.",
        )


@router.get("/{record_id}", response_model=RecordRead, status_code=status.HTTP_200_OK)
def get_record(record_id: int):
    """Отримати один запис за його ID."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним цілим числом.",
        )
    rec = repository.get_record_by_id(record_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено."
        )
    return rec


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: RecordCreate):
    """Створити новий запис."""
    try:
        return repository.create_record(record)
    except ValueError as err:
        if str(err) == "category_not_found":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Категорію з таким ID не знайдено.",
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким унікальним code вже існує.",
        )


@router.put("/{record_id}", response_model=RecordRead, status_code=status.HTTP_200_OK)
def replace_record(record_id: int, record: RecordReplace):
    """Повна заміна змінюваних полів наявного запису."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним цілим числом.",
        )
    try:
        updated = repository.replace_record(record_id, record)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено."
            )
        return updated
    except ValueError as err:
        if str(err) == "category_not_found":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Вказану категорію не знайдено.",
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким code вже існує.",
        )


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    """Видалити запис за ID."""
    if record_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ID має бути додатним цілим числом.",
        )
    if not repository.delete_record(record_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено."
        )
    return None