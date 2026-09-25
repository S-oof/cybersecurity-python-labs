# Варіант 8
# Завдання 1:

import os
import random
import sys
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "ThreatH@nt3r",
    "weak123",
    "P3n3trat10n@Test",
    "visitor",
    "Cyber@Defense2023",
    "normal",
    "Incident@R3sp0nse",
    "standard",
    "Risk@Analys1s",
    "typical",
]
criteria = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"weak123", "visitor", "normal", "standard", "typical", "admin"}


random_indices = random.sample(range(len(passwords)), 3)
duplicated_passwords = [passwords[i] for i in random_indices]
passwords.extend(duplicated_passwords)

# Підрахунок кількості повторів для перевірки унікальності
counts = Counter(passwords)


# 4. Алгоритм оцінки надійності пароля
def evaluate_password(pwd: str, criteria: dict, forbidden: set, counts: Counter) -> str:
    min_len = criteria.get("min_length", 10)

    # Критерій 1: Заборонений (входить до заборонених або коротший за min_length)
    if pwd in forbidden or len(pwd) < min_len:
        return "Заборонений"

    # Перевірка 4 груп символів (малі, великі, цифри, спецсимволи)
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    criteria_met = sum([has_lower, has_upper, has_digit, has_special])
    is_unique = counts[pwd] == 1

    # Критерій 5: Дуже сильний (всі групи символів, довжина >= min_length + 4, унікальний)
    if criteria_met == 4 and len(pwd) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    # Критерій 4: Сильний (всі групи символів, але довжина < min_length + 4 або пароль не унікальний)
    if criteria_met == 4:
        return "Сильний"

    # Критерій 3: Середній (деякі, але не всі групи символів)
    if criteria_met in (2, 3):
        return "Середній"

    # Критерій 2: Слабкий (лише 1 група символів)
    return "Слабкий"


# 5. Виведення результату аналізу в табличному форматі
print(f"Студент: {STUDENT_NAME}")
print(f"Група: {GROUP_NAME}")
print(f"Варіант: {VARIANT_NUMBER}\n")

header = f"| {'№':<2} | {'Пароль':<20} | {'Довжина':<8} | {'Категорія':<14} |"
divider = "-" * len(header)

print(divider)
print(header)
print(divider)


def run_task1():

    for idx, pwd in enumerate(passwords, 1):
        category = evaluate_password(pwd, criteria, forbidden_passwords, counts)
        print(f"| {idx:<2} | {pwd:<20} | {len(pwd):<8} | {category:<14} |")

    print(divider)


# run_task1()

if __name__ == "__main__":
    run_task1()
