"""Маршрути для записів вимірювань часу відновлення."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["Records"])

RecordId = Annotated[int, Path(gt=0, description="ID запису (додатне ціле)")]

NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Запис із таким code вже існує"}}


def _to_http(error: Exception) -> HTTPException:
    """Перетворити помилку шару даних на HTTP-помилку."""
    if isinstance(error, repository.NotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(error))
    return HTTPException(status.HTTP_409_CONFLICT, str(error))


@router.get("", response_model=list[RecordRead], summary="Список записів")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status_filter: Annotated[
        Status | None, Query(alias="status", description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(ge=0, allow_inf_nan=False, description="value >= min_value, хвилини"),
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Підрядок у title"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Скільки записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки пропустити")] = 0,
) -> list[dict]:
    """Записи з фільтрами (через AND), відсортовані за id."""
    return repository.get_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Створити від 1 до 100 записів атомарно: або всі, або жоден."""
    try:
        return repository.create_records_bulk(records)
    except (repository.NotFoundError, repository.ConflictError) as error:
        raise _to_http(error) from error


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Один запис за id."""
    record = repository.get_record_by_id(record_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Запис не знайдено")
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(record: RecordCreate) -> dict:
    """Створити запис; id генерує база."""
    try:
        return repository.create_record(record)
    except (repository.NotFoundError, repository.ConflictError) as error:
        raise _to_http(error) from error


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Замінити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Повністю замінити всі змінювані поля запису."""
    try:
        return repository.replace_record(record_id, record)
    except (repository.NotFoundError, repository.ConflictError) as error:
        raise _to_http(error) from error


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> None:
    """Видалити запис за id."""
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as error:
        raise _to_http(error) from error
