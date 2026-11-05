"""Початкове заповнення бази даних із файлу data/seed.json (Варіант 8)."""

from contextlib import closing
import json
import logging
import math
from pathlib import Path
import sqlite3

# Пакетний імпорт згідно з регламентом запуску python -m labs.lab03.seed
from labs.lab03.database import get_connection, initialize_database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
JSON_DATA_PATH = BASE_DIR / "data" / "seed.json"
VALID_STATUSES = {"new", "in_progress", "done"}


def load_and_validate_json(file_path: Path) -> dict:
    """Зчитування та сувора валідація початкових даних Варіанта 8."""
    if not file_path.exists():
        raise FileNotFoundError(
            f"Файл із початковими даними не знайдено за шляхом: {file_path}"
        )

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Помилка синтаксису JSON у файлі {file_path.name}: {e}")

    if "categories" not in data or "records" not in data:
        raise ValueError(
            "Некоректна структура JSON: відсутні ключі 'categories' або 'records'."
        )

    category_ids = set()
    for cat in data["categories"]:
        if not all(k in cat for k in ("id", "name")):
            raise ValueError(f"Категорія має містити 'id' та 'name': {cat}")
        if (
            type(cat["id"]) is not int
            or cat["id"] <= 0
            or not isinstance(cat["name"], str)
        ):
            raise ValueError(f"Некоректний тип або значення категорії: {cat}")
        category_ids.add(cat["id"])

    for rec in data["records"]:
        required_fields = {"code", "title", "category_id", "value", "status"}
        if not required_fields.issubset(rec.keys()):
            raise ValueError(f"У записі відсутні обов'язкові поля: {rec}")

        if rec["category_id"] not in category_ids:
            raise ValueError(
                f"Порушення цілісності: category_id={rec['category_id']} у записі '{rec['code']}' не існує."
            )

        if rec["status"] not in VALID_STATUSES:
            raise ValueError(
                f"Недопустимий статус '{rec['status']}' у записі '{rec['code']}'."
            )

        val = rec["value"]
        # Перевіряємо, що value — дійсне скінченне невід'ємне число (не bool)
        if (
            type(val) is bool
            or not isinstance(val, (int, float))
            or not math.isfinite(val)
            or val < 0
        ):
            raise ValueError(
                f"Поле 'value' має бути невід'ємним числом (хвилини) у записі '{rec['code']}'."
            )

    return data


def is_database_populated(connection: sqlite3.Connection) -> bool:
    """Перевірка наявності існуючих категорій чи записів."""
    cursor = connection.execute("SELECT COUNT(*) FROM categories;")
    cat_count = cursor.fetchone()[0]  # Використовуємо [0] замість ["count"]

    cursor = connection.execute("SELECT COUNT(*) FROM records;")
    rec_count = cursor.fetchone()[0]  # Використовуємо [0] замість ["count"]

    return cat_count > 0 or rec_count > 0


def seed_database(data: dict) -> None:
    """Ініціалізація та заповнення бази даних у межах єдиної транзакції."""
    # 1. Створюємо таблиці, якщо вони ще не існують
    initialize_database()

    with closing(get_connection()) as connection:
        # 2. Перевіряємо чи база вже заповнена
        if is_database_populated(connection):
            logger.info(
                "База даних вже містить дані. Заповнення скасовано, зміни не вносилися."
            )
            return

        try:
            # 3. Атомарне додавання всіх категорій і записів у контексті транзакції (with connection)
            with connection:
                categories_tuples = [
                    (cat["id"], cat["name"]) for cat in data["categories"]
                ]
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?);",
                    categories_tuples,
                )

                records_tuples = [
                    (
                        rec["code"],
                        rec["title"],
                        rec["category_id"],
                        rec["value"],
                        rec["status"],
                    )
                    for rec in data["records"]
                ]
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    records_tuples,
                )

            logger.info(
                f"Успішно заповнено базу: додано {len(categories_tuples)} категорій та {len(records_tuples)} записів."
            )

        except sqlite3.Error as e:
            # Контекстний менеджер with connection автоматично виконає rollback()
            logger.error(f"Помилка обмежень SQLite під час виконання пакета: {e}")
            raise


if __name__ == "__main__":
    try:
        seed_data = load_and_validate_json(JSON_DATA_PATH)
        seed_database(seed_data)
    except Exception as ex:
        logger.error(f"Ініціалізацію скасовано через помилку: {ex}")