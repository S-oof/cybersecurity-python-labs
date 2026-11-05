"""Головний модуль FastAPI-застосунку (main.py) для Варіанта 8."""

from contextlib import asynccontextmanager
import logging
import sqlite3
from fastapi import FastAPI, status

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
from labs.lab03.config import DOMAIN_NAME, THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Контекст життєвого циклу застосунку для ініціалізації бази даних."""
    try:
        logger.info("Автоматична перевірка та створення таблиць SQLite...")
        initialize_database()
    except sqlite3.Error as e:
        logger.critical(f"Помилка ініціалізації таблиць SQLite: {e}")
        raise
    yield


app = FastAPI(
    title=f"API: {DOMAIN_NAME} (Варіант {VARIANT_NUMBER})",
    description=(
        f"Сервіс обліку вимірювань часу відновлення сервісів.\n"
        f"**Одиниця вимірювання (unit):** {UNIT} (хвилини).\n"
        f"**Прикладний поріг реагування (threshold):** {THRESHOLD} хв."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Підключення модульних роутерів категорій та записів
app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", status_code=status.HTTP_200_OK, tags=["System"])
def ping():
    """Перевірка доступності Web API."""
    return {"status": "ok"}


@app.get("/student", status_code=status.HTTP_200_OK, tags=["System"])
def student_info():
    """Повертає інформацію про автора роботи з shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }