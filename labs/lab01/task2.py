# Завдання 2:

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
 "crypto_specialist": {"role": "cryptographer", "clearance": 4, "department": "Cryptography", "active": True},
 "privacy_officer": {"role": "privacy_analyst", "clearance": 3, "department": "Privacy", "active": True},
 "data_scientist": {"role": "data_analyst", "clearance": 2, "department": "Analytics", "active": True},
 "field_engineer": {"role": "field_support", "clearance": 2, "department": "Field Ops", "active": True},
 "test_account": {"role": "testing", "clearance": 1, "department": "QA", "active": False}
}
resources = [("encryption_keys", 4), ("privacy_policies", 3),
             ("anonymized_data", 2), ("field_reports", 2), 
             ("crypto_algorithms", 4),("consent_forms", 1), 
             ("data_classification", 3), ("key_management", 4),
             ("statistical_models", 2), ("public_datasets", 1)]
security_levels = ("Unclassified", "For Official Use", "Confidential", "Secret")
blocked_users = {"test_account", "gdpr_violation", "data_breach_user"}

print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

for resource_name, level_num in resources:
    #Оскільки список починається з 0, то аби мати правильні рівні віднімаємо 1
    level_text = security_levels[level_num - 1]
    print(f"• {resource_name:<20} -> {level_text} (Рівень {level_num})")

def access_check(username = str, resource_lvl = int):

    if username not in users:
        return "DENY (user not found)"
    
    if username in blocked_users:
        return "DENY (user is blocked)"
    
    if not users[username]["active"]:
        return "DENY (Account inactive)"
    
    # Крок 4-5: Перевірка рівня допуску
    if users[username]["clearance"] >= resource_lvl:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"

all_test_users = list(users.keys()) + list(blocked_users) + ["unknown_user"]
all_test_users = list(dict.fromkeys(all_test_users))  # Видаляємо дублікати з збереженням порядку

def run_task2():
    for username in all_test_users:
        for resource_name, resource_lvl in resources:
            result = access_check(username, resource_lvl)
            print(f"user={username} resource={resource_name} -> {result}")
    
# run_task2()

if __name__ == "__main__":
    run_task2()