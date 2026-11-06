"""Початкове заповнення бази з data/seed.json.

Запуск із кореня репозиторію: python -m labs.lab03.seed
"""
# початкова ініціалізація

import json
import logging
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import CategoryRead, RecordCreate

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s") 
logger = logging.getLogger(__name__) 

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def load_seed(path: Path) -> tuple[list[CategoryRead], list[RecordCreate]]: 
    """Прочитати JSON і перевірити його тими самими моделями, що й API."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"Файл не знайдено: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Помилка синтаксису JSON: {error}") from error

    if not isinstance(data, dict) or set(data) != {"categories", "records"}:
        raise ValueError("JSON має бути об'єктом з ключами 'categories' і 'records'")

    try: #перевіряє чи дані коректні
        categories = [CategoryRead.model_validate(item) for item in data["categories"]]
        records = [RecordCreate.model_validate(item) for item in data["records"]]
    except (TypeError, ValidationError) as error:
        raise ValueError(f"Некоректні дані: {error}") from error

    category_ids = [category.id for category in categories]
    if len(category_ids) != len(set(category_ids)):
        raise ValueError("Повторний id категорії")
    if len({c.name for c in categories}) != len(categories):
        raise ValueError("Повторна назва категорії")
    if len({r.code for r in records}) != len(records):
        raise ValueError("Повторний code запису")
    for record in records:
        if record.category_id not in category_ids:
            raise ValueError(
                f"Запис {record.code}: категорії {record.category_id} немає"
            )
    return categories, records


def is_database_empty(connection: sqlite3.Connection) -> bool:
    """Перевірити, що в обох таблицях немає рядків."""
    for table in ("categories", "records"):
        if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
            return False
    return True


def seed_database(categories: list[CategoryRead], records: list[RecordCreate]) -> None:
    """Додати категорії та записи в одній транзакції."""
    initialize_database()
    with closing(get_connection()) as connection:
        if not is_database_empty(connection):
            logger.info("База вже містить дані — заповнення пропущено.")
            return
        with connection:
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(c.id, c.name) for c in categories],
            )
            connection.executemany(
                "INSERT INTO records (code, title, category_id, value, status)"
                " VALUES (?, ?, ?, ?, ?)",
                [(r.code, r.title, r.category_id, r.value, r.status) for r in records],
            )
    logger.info("Додано %d категорій і %d записів.", len(categories), len(records))


def main() -> int:
    """Точка входу; повертає код завершення процесу."""
    try:
        categories, records = load_seed(SEED_PATH)
        seed_database(categories, records)
    except ValueError as error:
        logger.error("Заповнення скасовано: %s", error)
        return 1
    except sqlite3.Error as error:
        logger.error("Помилка SQLite, зміни скасовано: %s", error)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
