# Лабораторна робота №3 — варіант 8

**Облік часу відновлення сервісів.** Web API на FastAPI + SQLite для навчальних
вимірювань відновлення сервісів.

- `categories` — сервіси: `database`, `web_service`, `file_storage`;
- `records.value` — час відновлення, **хвилини** (`minutes`), число ≥ 0;
- `records.status` — стан перевірки вимірювання: `new`, `in_progress`, `done`;
- поріг реагування — **60.0 хв**.

## Структура

```
labs/lab03/
├── main.py            # FastAPI-застосунок, lifespan, /ping, /student
├── database.py        # з'єднання та виконання schema.sql
├── schema.sql         # готова схема (варіанти 7–9)
├── repository.py      # параметризовані SQL-запити
├── schemas.py         # Pydantic-моделі
├── config.py          # предметна область, одиниця, поріг
├── seed.py            # початкове заповнення з data/seed.json
├── routers/           # categories.py, records.py
└── data/seed.json     # 3 категорії, 8 записів
```

## Встановлення

З кореня репозиторію:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск

```bash
python -m labs.lab03.seed        # створює базу і заповнює її (повторний запуск нічого не змінює)
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Документація: <http://127.0.0.1:8000/docs>, схема: <http://127.0.0.1:8000/openapi.json>.

Файл бази `labs/lab03/data/lab3.sqlite3` створюється автоматично й не додається до Git.

## Маршрути

| Метод і шлях | Призначення | Успіх |
|---|---|---|
| `GET /ping` | перевірка доступності | 200 |
| `GET /student` | ПІБ, група, варіант | 200 |
| `GET /categories` | список категорій | 200 |
| `POST /categories` | створити категорію | 201 |
| `DELETE /categories/{id}` | видалити порожню категорію | 204 |
| `GET /records` | список із фільтрами | 200 |
| `GET /records/{id}` | один запис | 200 |
| `POST /records` | створити запис | 201 |
| `PUT /records/{id}` | повна заміна полів | 200 |
| `DELETE /records/{id}` | видалити запис | 204 |
| `POST /records/bulk` | пакет 1–100 записів, атомарно | 201 |

Помилки: `404` — немає запису/категорії, `409` — дублікат `code` чи назви категорії
або категорія містить записи, `422` — некоректні дані.

Параметри `GET /records`: `category_id`, `status`, `min_value`, `q` (підрядок у `title`,
з урахуванням регістру), `limit` (1–100, типово 20), `offset` (типово 0).

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i "http://127.0.0.1:8000/records?min_value=60"

curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V08-TEST","title":"Тестове вимірювання","category_id":1,"value":45.5,"status":"new"}'

curl -i -X PUT "http://127.0.0.1:8000/records/9" \
  -H "Content-Type: application/json" \
  -d '{"code":"V08-TEST","title":"Тестове вимірювання","category_id":2,"value":50,"status":"done"}'

curl -i -X DELETE "http://127.0.0.1:8000/records/9"

# Скасування пакета: V08-01 уже є в базі → 409, V08-ROLLBACK теж не збережено
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V08-ROLLBACK","title":"Перший елемент","category_id":1,"value":10,"status":"new"},
       {"code":"V08-01","title":"Дублікат коду","category_id":2,"value":20,"status":"new"}]'
```

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
```
