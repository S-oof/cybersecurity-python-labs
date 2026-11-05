#напряму взаємодіє з бд

from contextlib import closing
import sqlite3
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import CategoryCreate, RecordCreate, RecordReplace


def get_categories() -> list[dict[str, Any]]:
    """Отримання списку всіх категорій у порядку зростання ID."""
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row  # Гарантує створення словника {id: ..., name: ...}
        cursor = conn.execute("SELECT id, name FROM categories ORDER BY id ASC;")
        return [dict(row) for row in cursor.fetchall()]


def create_category(category: CategoryCreate) -> dict[str, Any]:
    """Створення категорії та повернення створеного об'єкта з ID."""
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                "INSERT INTO categories (name) VALUES (?);",
                (category.name,),
            )
            # Отримуємо автоматично згенерований ID від SQLite
            new_id = cursor.lastrowid

        # Повертаємо словник з правильним id (не None)
        return {"id": new_id, "name": category.name}


def delete_category(category_id: int) -> str:
    """
    Видалення порожньої категорії.
    Повертає: 'success', 'not_found' або 'conflict'.
    """
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT id FROM categories WHERE id = ?;", (category_id,)
        )
        if not cursor.fetchone():
            return "not_found"

        cursor = conn.execute(
            "SELECT 1 FROM records WHERE category_id = ? LIMIT 1;", (category_id,)
        )
        if cursor.fetchone():
            return "conflict"

        with conn:
            conn.execute("DELETE FROM categories WHERE id = ?;", (category_id,))
        return "success"


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    """Отримання одного запису за ID разом із category_name через JOIN."""
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
               r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?;
    """
    with closing(get_connection()) as conn:
        cursor = conn.execute(query, (record_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_records( #перевіряє посилання після ?
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримання списку записів з фільтрами, буквеним пошуком та пагінацією."""
    conditions = []
    params: list[Any] = []

    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)

    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)

    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)

    if q is not None and len(q) > 0:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    query = f"""
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
               r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        {where_clause}
        ORDER BY r.id ASC
        LIMIT ? OFFSET ?;
    """
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row  # <-- ДОДАТИ ЦЕЙ РЯДОК
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def create_record(record: RecordCreate) -> dict[str, Any]:
    """Створення нового запису."""
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT 1 FROM categories WHERE id = ?;", (record.category_id,)
        )
        if not cursor.fetchone():
            raise ValueError("category_not_found")

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?) RETURNING id;
                """,
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                ),
            )
            new_id = cursor.fetchone()["id"]

    return get_record_by_id(new_id)  # type: ignore


def replace_record(
    record_id: int, record: RecordReplace
) -> dict[str, Any] | None:
    """Повна заміна змінюваних полів запису за його id."""
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT 1 FROM records WHERE id = ?;", (record_id,)
        )
        if not cursor.fetchone():
            return None

        cursor = conn.execute(
            "SELECT 1 FROM categories WHERE id = ?;", (record.category_id,)
        )
        if not cursor.fetchone():
            raise ValueError("category_not_found")

        with conn:
            conn.execute(
                """
                UPDATE records
                SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                WHERE id = ?;
                """,
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                    record_id,
                ),
            )

    return get_record_by_id(record_id)


def delete_record(record_id: int) -> bool:
    """Видалення запису за id."""
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT 1 FROM records WHERE id = ?;", (record_id,)
        )
        if not cursor.fetchone():
            return False

        with conn:
            conn.execute("DELETE FROM records WHERE id = ?;", (record_id,))
        return True


def create_records_bulk( #даю велики джсон і створює по ньому декілька записів
    records: list[RecordCreate],
) -> list[dict[str, Any]]:
    """Пакетне створення записів в одній атомарній транзакції."""
    cat_ids = {r.category_id for r in records}
    codes = [r.code for r in records]

    # 1. Перевірка дублікатів коду всередині пакета
    if len(codes) != len(set(codes)):
        raise sqlite3.IntegrityError("Duplicate code in bulk request payload")

    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        
        # 2. Перевірка існування всіх вказаних категорій
        placeholders = ",".join(["?"] * len(cat_ids))
        cursor.execute(
            f"SELECT id FROM categories WHERE id IN ({placeholders});",
            list(cat_ids),
        )
        existing_cats = {row["id"] for row in cursor.fetchall()}
        if len(existing_cats) != len(cat_ids):
            raise ValueError("category_not_found")

        created_ids = []
        # 3. Додавання в єдиній транзакції
        try:
            with conn:
                for r in records:
                    cursor.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?) RETURNING id;
                        """,
                        (r.code, r.title, r.category_id, r.value, r.status),
                    )
                    created_ids.append(cursor.fetchone()["id"])
        except sqlite3.Error:
            raise

    # 4. Повертаємо створені об'єкти з category_name
    return [get_record_by_id(rid) for rid in created_ids if get_record_by_id(rid)]  # type: ignore