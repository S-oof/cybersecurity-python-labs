import time

from labs.lab02.task1 import Admin, Session, User, UserAccount


def run_demo() -> None:
    print("Завдання 1\n")

    # 1. Створення користувача та адміністратора
    print("Створення користувача та адміністратора!")
    user = User("umbr_ella", "umbr_ella@example.com", password="Umbrellas#6")
    admin = Admin(
        "admin_user",
        "admin@example.com",
        password="AdminPassword!123",
        permissions=["ban_ip", "read_logs"],
    )

    print(f"Створено користувача: {user}")
    print(f"Створено адміністратора: {admin}")

    # 2. Зміна email з валідацією
    print("Зміна email з валідацією")
    user.email = "new_email@example.com"
    print(f"Новий валідний email {user.email}")

    for invalid_email in ["wrong_email_format", "o.i@lpnu.ua", "123abc@lpnu.ua"]:
        try:
            user.email = invalid_email
        except ValueError as e:
            print(f"Помилка валідації: {e}")
    print()

    # 3. Перевірка прав адміністратора
    print("Перевірка прав адміністратора")
    admin.grant_permission("manage_firewall")
    print(f"Після надання права 'manage_firewall': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}")
    admin.revoke_permission("ban_ip")
    print(f"Після відкликання 'ban_ip': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}\n")

    # 4. Робота з UserAccount, сесією та таймаутом
    print("Робота з UserAccount, сесією та таймаутом")
    account = UserAccount(user=user)

    # Невдалий вхід
    result_fail = account.login("umbr_ella", "wrong_password", ip="127.0.0.1")
    print(
        f"Невдалий вхід: result={result_fail}, is_authenticated={account.is_authenticated()}"
    )

    # Успішний вхід
    result_ok = account.login("umbr_ella", "Umbrellas#6", ip="127.0.0.1")
    print(
        f"Успішний вхід: result={result_ok}, is_authenticated={account.is_authenticated()}"
    )
    print(f"Доступ через спецметод account['user']: {account['user']}")

    # Перевірка таймауту (таймаут 1 сек)
    time.sleep(1.1)
    print(
        f"Після закінчення таймауту: is_authenticated={account.is_authenticated(timeout_sec=1)}"
    )

    # Повторна авторизація та logout
    account.login("umbr_ella", "Umbrellas#6", ip="127.0.0.1")
    account.logout()
    print(f"Після виходу (logout): is_authenticated={account.is_authenticated()}\n")

    # 5. Захист __getitem__ / __setitem__
    print("Захист __getitem__ / __setitem__")
    try:
        _ = account["password_hash"]
    except KeyError as e:
        print(f"KeyError (заборонений ключ): {e}")

    try:
        account["session"] = "wrong_type_string"
    except TypeError as e:
        print(f"TypeError (хибний тип): {e}")

    new_session = Session(ip="127.0.0.1")
    account["session"] = new_session
    print(f"Коректне присвоєння account['session']: {account['session']}\n")

    # 6. Журнал аудиту першого акаунту
    account.audit_log.show_all()

    # 7. Перевірка користувача без пароля
    print("\nКористувач без пароля")
    no_pass_user = User(username="noname", email="noname@lpnu.ua")
    no_pass_admin = Admin(
        username="noname_admin",
        email="admin_noname@lpnu.ua",
        permissions=["read_logs"],
    )
    print(f"Створено: {no_pass_user}")
    print(f"Створено: {no_pass_admin}")

    no_pass_account = UserAccount(user=no_pass_user)
    login_nopass_result = no_pass_account.login(
        "noname", "any_password", ip="127.0.0.1"
    )
    print(f"Спроба входу без встановленого пароля: {login_nopass_result}")

    no_pass_account.audit_log.show_all()


if __name__ == "__main__":
    run_demo()
