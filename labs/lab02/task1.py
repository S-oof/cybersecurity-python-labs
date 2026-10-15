import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

# ==========================================
# КОНСТАНТИ БЕЗПЕКИ ТА НАЛАШТУВАНЬ СЕСІЇ
# ==========================================
SALT_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900  # 15 хвилин

# Регулярний вираз для валідації пошти
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
)


# ==========================================
# 1. КЛАС КОРЕНЕВОГО КОРИСТУВАЧА (User)
# ==========================================
class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        password: str | None = None,
        active: bool = True,
    ) -> None:
        if not username or not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім.")

        self.username: str = username.strip()
        self.email: str = email
        self.role: str = role
        self.active: bool = active
        self._password_salt: bytes = b""  # Інкапсульоване поле солі
        self._password_hash: bytes = b""  # Інкапсульоване поле хешу

        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str | None) -> None:
        """Встановлює безпечний криптографічний хеш пароля та сіль."""
        if not password:
            self._password_salt = b""
            self._password_hash = b""
            return
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має бути рядком довжиною щонайменше 4 символи.")

        self._password_salt = os.urandom(SALT_SIZE_BYTES)
        self._password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self._password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою стійкого до атак порівняння hmac.compare_digest."""
        if not self._password_hash or not self._password_salt:
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self._password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self._password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status={status})"
        )


# ==========================================
# 2. КЛАС АДМІНІСТРАТОРА (Admin)
# ==========================================
class Admin(User):
    """Клас адміністратора, що наслідує User та додає управління правами доступу."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(
            username=username,
            email=email,
            role="admin",
            password=password,
            active=active,
        )
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає додаткове право доступу адміністратору."""
        if not permission or not permission.strip():
            raise ValueError("Назва дозволу не може бути порожньою.")
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        """Відкликає чинне право доступу адміністратора."""
        if not permission or not permission.strip():
            raise ValueError("Назва дозволу не може бути порожньою.")
        self.permissions.discard(permission.strip())

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність вказаного дозволу."""
        return permission.strip() in self.permissions

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"status={status}, permissions=[{perms}])"
        )


# ==========================================
# 3. КЛАС КОРИСТУВАЦЬКОЇ СЕСІЇ (Session)
# ==========================================
class Session:
    """Клас користувацької сесії з контролем часу таймауту."""

    def __init__(self, ip: str) -> None:
        if not ip or not ip.strip():
            raise ValueError("IP-адреса сесії не може бути порожньою.")
        now = datetime.now(timezone.utc)
        self.ip: str = ip.strip()
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:
        """Оновлює час останньої активності сесії поточним часом."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув заданий час з моменту останньої дії."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії має бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        return (
            f"Session(ip='{self.ip}', login_time='{self.login_time.isoformat()}', "
            f"last_activity='{self.last_activity.isoformat()}')"
        )


# ==========================================
# 4. ЖУРНАЛ АУДІТУ ПОДІЙ БЕЗПЕКИ (AuditLog)
# ==========================================
@dataclass(frozen=True)
class AuditEntry:
    """Конкретний запис у журналі аудиту (незмінний датаклас)."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал для безпечного накопичення та відображення подій системи."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []  # Інкапсульований список логів

    @property
    def entries(self) -> list[AuditEntry]:
        """Повертає безпечну копію списку записів логів."""
        return list(self._entries)

    def add_log(self, username: str, action: str) -> None:
        """Створює запис з поточним UTC часом (паролі сюди не потрапляють)."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> None:
        """Виводить увесь вміст журналу аудиту на екран."""
        print("\n-- ЗАПИСИ ЖУРНАЛУ АУДІТУ (AUDIT LOG) --")
        if not self._entries:
            print("(Журнал порожній)")
            return
        for entry in self._entries:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")
        print("---------------------------------------")


# ==========================================
# 5. КОМПОЗИЦІЯ СУТНОСТЕЙ: КЛАС USERACCOUNT
# ==========================================
class UserAccount:
    """Обліковий запис, який об'єднує сутності User, Session та AuditLog за допомогою композиції."""

    _ALLOWED_KEYS: ClassVar[dict[str, type | tuple[type, ...]]] = {
        "user": User,
        "session": (Session, type(None)),
        "audit_log": AuditLog,
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError(
                "Поле 'user' має бути екземпляром класу User або його нащадків."
            )
        if session is not None and not isinstance(session, Session):
            raise TypeError("Поле 'session' має бути екземпляром Session або None.")
        if audit_log is not None and not isinstance(audit_log, AuditLog):
            raise TypeError("Поле 'audit_log' має бути екземпляром AuditLog.")

        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Здійснює автентифікацію. У разі успіху створює нову сесію та оновлює лог."""
        if not username or not username.strip():
            raise ValueError("Ім'я користувача на вході не може бути порожнім.")

        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(self.user.username, "login_success")
        return True

    def is_authenticated(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевіряє життєздатність сесії. Невдала перевірка анулює її та не робить touch."""
        if self.session is None or not self.user.active:
            return False
        return self.session.is_active(timeout_sec)

    def logout(self) -> None:
        """Коректно завершує діючу сесію та фіксує це в аудиті."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        """Забезпечує поліморфний інтерфейс читання дозволених об'єктів (наприклад account["user"])."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Оновлює об'єкти з повною валідацією типів на відповідність (наприклад account["session"] = ...)."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        expected_type = self._ALLOWED_KEYS[key]
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Неправильний тип для ключа '{key}': отримано {type(value).__name__}."
            )
        setattr(self, key, value)
