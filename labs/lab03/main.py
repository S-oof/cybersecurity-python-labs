"""FastAPI-застосунок лабораторної роботи №3 (варіант 8)."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03.config import DOMAIN_NAME, THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Під час запуску створити відсутні таблиці (дані не змінюються)."""
    initialize_database()
    logger.info("Базу даних перевірено.")
    yield


app = FastAPI(
    title=f"{DOMAIN_NAME}",
    description=(
        "Сервіс обліку навчальних вимірювань часу відновлення сервісів. "
        "Категорія — сервіс, `value` — час відновлення, "
        "`status` — стан перевірки вимірювання.\n\n"
        f"**Одиниця вимірювання:** {UNIT} (хвилини).\n\n"
        f"**Поріг:** {THRESHOLD} хв."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Відповідь 422 без поля input.

    Стандартний обробник повертає введене значення, а значення на кшталт
    1e309 (нескінченність) не можна записати в JSON — замість 422 був би 500.
    """
    errors = [
        {key: value for key, value in error.items() if key != "input"}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


@app.get("/ping", tags=["System"], summary="Перевірка доступності")
def ping() -> dict[str, str]:
    """Повертає {"status": "ok"}."""
    return {"status": "ok"}


@app.get("/student", tags=["System"], summary="Дані студента")
def student_info() -> dict[str, str | int]:
    """ПІБ, група та варіант із shared/student.py."""
    return {
        "student_name": STUDENT_NAME.strip(),
        "group_name": GROUP_NAME.strip(),
        "variant_number": VARIANT_NUMBER,
    }
