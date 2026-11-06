# """Шар доступу до даних: параметризовані SQL-запити до SQLite. напряму взаємодіє з бд
import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import CategoryCreate, RecordCreate, RecordReplace

RECORD_SELECT = """
    SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
           r.value, r.status
    FROM records AS r
    JOIN categories AS c ON c.id = r.category_id
"""


class NotFoundError(Exception):
    """Потрібний запис або категорія не існує."""


class ConflictError(Exception):
    """Дублікат унікального значення або категорія містить записи."""


def _connect() -> sqlite3.Connection:
    """Відкрити з'єднання, у якому рядки читаються як словники."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _record_exists(connection: sqlite3.Connection, record_id: int) -> bool:
    row = connection.execute(
        "SELECT 1 FROM records WHERE id = ?", (record_id,)
    ).fetchone()
    return row is not None


def _fetch_record(
    connection: sqlite3.Connection, record_id: int
) -> dict[str, Any] | None:
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


def _record_params(record: RecordCreate) -> tuple[Any, ...]:
    return (
        record.code,
        record.title,
        record.category_id,
        record.value,
        record.status,
    )


def get_categories() -> list[dict[str, Any]]:
    """Повернути всі категорії за зростанням id."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def create_category(category: CategoryCreate) -> dict[str, Any]:
    """Створити категорію; id генерує база."""
    with closing(_connect()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)",
                    (category.name,),
                )
        except sqlite3.IntegrityError as error:
            raise ConflictError("Категорія з такою назвою вже існує") from error
    return {"id": cursor.lastrowid, "name": category.name}


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(_connect()) as connection:
        if not _category_exists(connection, category_id):
            raise NotFoundError("Категорію не знайдено")
        try:
            with connection:
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as error:
            # ON DELETE RESTRICT: у категорії є записи.
            raise ConflictError("Категорія містить записи") from error


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    """Повернути один запис разом із category_name або None."""
    with closing(_connect()) as connection:
        return _fetch_record(connection, record_id)


def get_records(  #перевіряє посилання після ?
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повернути записи з фільтрами (через AND) та поділом на сторінки."""
    # SQL-фрагменти лише з коду, значення лише через параметри "?".
    conditions: list[str] = []
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
    if q:
        # instr — буквальний пошук з урахуванням регістру (% і _ не шаблони).
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    query = RECORD_SELECT
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_connect()) as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def create_record(record: RecordCreate) -> dict[str, Any]:
    """Створити запис і повернути його з category_name."""
    with closing(_connect()) as connection:
        if not _category_exists(connection, record.category_id):
            raise NotFoundError("Категорію не знайдено")
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status)"
                    " VALUES (?, ?, ?, ?, ?)",
                    _record_params(record),
                )
        except sqlite3.IntegrityError as error:
            raise ConflictError("Запис із таким code вже існує") from error
        return _fetch_record(connection, cursor.lastrowid)  # type: ignore[return-value]


def replace_record(record_id: int, record: RecordReplace) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with closing(_connect()) as connection:
        if not _record_exists(connection, record_id):
            raise NotFoundError("Запис не знайдено")
        if not _category_exists(connection, record.category_id):
            raise NotFoundError("Категорію не знайдено")
        try:
            with connection:
                connection.execute(
                    "UPDATE records"
                    " SET code = ?, title = ?, category_id = ?, value = ?, status = ?"
                    " WHERE id = ?",
                    (*_record_params(record), record_id),
                )
        except sqlite3.IntegrityError as error:
            raise ConflictError("Запис із таким code вже існує") from error
        return _fetch_record(connection, record_id)  # type: ignore[return-value]


def delete_record(record_id: int) -> None:
    """Видалити запис за id."""
    with closing(_connect()) as connection:
        if not _record_exists(connection, record_id):
            raise NotFoundError("Запис не знайдено")
        with connection:
            connection.execute("DELETE FROM records WHERE id = ?", (record_id,))


def create_records_bulk(records: list[RecordCreate]) -> list[dict[str, Any]]: #даю велики джсон і створює по ньому декілька записів
    """Додати пакет записів в одній транзакції: або всі, або жоден."""
    codes = [record.code for record in records]
    if len(codes) != len(set(codes)):
        raise ConflictError("Пакет містить повторний code")

    category_ids = sorted({record.category_id for record in records})
    placeholders = ", ".join("?" for _ in category_ids)

    with closing(_connect()) as connection:
        found = connection.execute(
            f"SELECT COUNT(*) FROM categories WHERE id IN ({placeholders})",
            category_ids,
        ).fetchone()[0]
        if found != len(category_ids):
            raise NotFoundError("Категорію не знайдено")

        created_ids: list[int] = []
        try:
            # Один with — одна транзакція; за помилки буде rollback усього пакета.
            with connection:
                for record in records:
                    cursor = connection.execute(
                        "INSERT INTO records"
                        " (code, title, category_id, value, status)"
                        " VALUES (?, ?, ?, ?, ?)",
                        _record_params(record),
                    )
                    created_ids.append(cursor.lastrowid)  # type: ignore[arg-type]
        except sqlite3.IntegrityError as error:
            raise ConflictError("Запис із таким code вже існує") from error

        return [_fetch_record(connection, rid) for rid in created_ids]  # type: ignore[misc]
