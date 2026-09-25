# 8 sha256 min_length = 11

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER, salt


class ValidationError(Exception):
    pass


min_length = 11

# Динамічне формування шляхів до папки data і файлів users.csv,log.json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_FILE_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_FILE_PATH = os.path.join(DATA_DIR, "log.json")


def generate_hash(password: str, salt: str = "00000") -> str:

    if password is None or salt is None or password == "" or salt == "":
        raise ValueError()

    if len(password) < min_length:
        raise ValidationError()

    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


users_to_register = (
    ("user_valid1", "secure_pass123"),
    ("user_empty_str", ""),
    ("user_too_short1", "short"),
    ("user_none_val", None),
    ("user_valid2", "another_good_1"),
    ("user_too_short2", "12345"),
    ("user_valid3", "password_99"),
    ("user_empty_str2", ""),
    ("user_valid4", "valid_p@ss"),
    ("user_too_short3", "abc12"),
)


def create_user(username: str, password: str) -> tuple[str, str]:
    return (username, generate_hash(password, salt))


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)
    valid_users = []

    # Перехоплення некоректних паролів під час створення
    for username, password in users_list:
        try:
            user_tuple = create_user(username, password)
            valid_users.append(user_tuple)
            print(f"Зареєстровано: '{username}'")
        except (ValueError, ValidationError) as e:
            print(f"[Помилка реєстрації] Користувач '{username}': {e}")

    # Запис успішно зареєстрованих користувачів у CSV
    try:
        with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "hash_value"])
            writer.writerows(valid_users)
        print(f"\nБазу даних збережено у {CSV_FILE_PATH}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка запису CSV] {e}")


def read_users_db() -> list[tuple[str, str]]:
    users_db = []
    if not os.path.exists(CSV_FILE_PATH):
        return users_db
    try:
        with open(CSV_FILE_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)  # Пропускає заголовок
            if header:
                for row in reader:
                    if row:
                        users_db.append((row[0], row[1]))
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка читання CSV] {e}")
        return []

    return users_db


def display_users_db(users_db: list[tuple[str, str]]):
    print("\nВміст users.csv")
    print(f"{'Логін':<20} | {'Хеш пароля SHA-256'}")
    print("-" * 65)
    for uname, hval in users_db:
        print(f"{uname:<20} | {hval[:25]}...")
    print("-" * 65 + "\n")


def log_event(func):
    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure"
        try:
            res = func(username, password, *args, **kwargs)
            result_status = "success" if res else "failure"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(LOG_FILE_PATH):
                try:
                    with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    logs = []

            logs.append(log_entry)

            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (PermissionError, OSError) as e:
                print(f"[Помилка запису логу] {e}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = read_users_db()
    users_dict = dict(users_db)

    if username not in users_dict:
        return False

    try:
        input_hash = generate_hash(password, salt)
    except (ValueError, ValidationError):
        return False

    return input_hash == users_dict[username]


def run_task3():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    print("Реєстрація користувачів ")
    create_users(users_to_register)

    # Відображення бази даних у консолі
    users_db = read_users_db()
    display_users_db(users_db)

    print("Тестування автентифікації")
    test_cases = [
        ("user_valid1", "secure_pass123"),
        ("user_valid1", "WrongPass123!"),
        ("unknown_user", "SomePass123!"),
        ("user_valid2", "short"),
    ]

    for uname, pwd in test_cases:
        try:
            success = login(uname, pwd)
            status_str = "Успіх" if success else "Відмова"
            print(f"Спроба входу user='{uname}': {status_str}")
        except (
            ValueError,
            ValidationError,
            FileNotFoundError,
            PermissionError,
            OSError,
        ) as e:
            print(f"Спроба входу user='{uname}': ПОМИЛКА ({e})")

    print(f"\nЛог подій збережено у {LOG_FILE_PATH}")


# run_task3()

if __name__ == "__main__":
    run_task3()
