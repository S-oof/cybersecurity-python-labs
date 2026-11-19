"""Валідація відповіді NVD API та аналіз вразливості за правилом варіанта."""

from __future__ import annotations

import math
import re
from typing import Any

CVE_ID_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

ALLOWED_FIELD_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _validate_cve_id(cve_id: str) -> None:
    """Перевіряє коректність формату ідентифікатора CVE."""
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Некоректний формат ідентифікатора CVE: {cve_id!r}")


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    """Перевіряє список descriptions та повертає перший непорожній опис англійською."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise TypeError("Поле descriptions має бути списком.")

    selected_description: str | None = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise TypeError("Елемент descriptions має бути словником.")
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise TypeError("Поля lang та value у descriptions мають бути рядками.")
        if selected_description is None and lang == "en" and value.strip():
            selected_description = value
    return selected_description


def _extract_optional_non_empty_str(container: dict[str, Any], key: str) -> str | None:
    """Повертає None, якщо ключ відсутній, або перевіряє, що значення є непорожнім рядком."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {key} має бути непорожнім рядком.")
    return value


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD API та повертає внутрішній запис CVE або None.

    Формат внутрішнього запису (словник):
        {
            "cve_id": str,
            "vuln_status": str | None,
            "description": str | None,
            "cvss_version": str | None,
            "score": float | None,
            "score_source": str | None,
            "vector": str | None,
            "cvss_data": dict[str, Any] | None,
        }
    Якщо запис не знайдено (vulnerabilities == []), повертається None.
    """
    _validate_cve_id(cve_id)

    if not isinstance(payload, dict):
        raise TypeError("Кореневий об'єкт відповіді має бути словником.")

    if "vulnerabilities" not in payload or not isinstance(
        payload["vulnerabilities"], list
    ):
        raise ValueError("Поле vulnerabilities відсутнє або не є списком.")

    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) > 1:
        raise ValueError("Очікується нуль або один запис у списку vulnerabilities.")
    if len(vulnerabilities) == 0:
        return None

    wrapper = vulnerabilities[0]
    if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
        raise TypeError("Елемент vulnerabilities має містити словник cve.")

    cve = wrapper["cve"]
    record_id = cve.get("id")
    if not isinstance(record_id, str) or record_id != cve_id:
        raise ValueError("Ідентифікатор cve.id не збігається із запитаним CVE.")

    vuln_status = _extract_optional_non_empty_str(cve, "vulnStatus")
    description = _extract_english_description(cve)

    base_record: dict[str, Any] = {
        "cve_id": cve_id,
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }

    if vuln_status is None or vuln_status == "Rejected":
        return base_record

    if "metrics" not in cve:
        return base_record
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise TypeError("Поле metrics має бути словником.")

    if "cvssMetricV31" not in metrics:
        return base_record
    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        raise TypeError("Поле cvssMetricV31 має бути списком.")
    if len(metric_list) == 0:
        return base_record

    for item in metric_list:
        if not isinstance(item, dict):
            raise TypeError("Елемент cvssMetricV31 має бути словником.")

    selected_metric = next(
        (item for item in metric_list if item.get("type") == "Primary"),
        metric_list[0],
    )

    cvss_data = selected_metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise TypeError("Поле cvssData вибраної оцінки має бути словником.")

    raw_score = cvss_data.get("baseScore")
    if (
        isinstance(raw_score, bool)
        or not isinstance(raw_score, (int, float))
        or not math.isfinite(raw_score)
        or not (0 <= raw_score <= 10)
    ):
        raise ValueError("Поле cvssData.baseScore має бути числом у межах від 0 до 10.")

    cvss_version = _extract_optional_non_empty_str(cvss_data, "version")
    if cvss_version is not None and cvss_version != "3.1":
        raise ValueError("Поле cvssData.version має дорівнювати '3.1'.")

    vector = _extract_optional_non_empty_str(cvss_data, "vectorString")
    score_source = _extract_optional_non_empty_str(selected_metric, "source")

    base_record["cvss_version"] = cvss_version
    base_record["score"] = float(raw_score)
    base_record["score_source"] = score_source
    base_record["vector"] = vector
    base_record["cvss_data"] = dict(cvss_data)
    return base_record


def build_report(
    record: dict[str, Any] | None,
    cve_id: str,
    variant: int,
) -> dict[str, Any]:
    """Застосовує правило варіанта до внутрішнього запису та формує словник звіту."""
    _validate_cve_id(cve_id)

    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError(f"Некоректний номер варіанта: {variant!r}")

    rule = dict(VARIANT_RULES[variant])

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    if not isinstance(record, dict):
        raise TypeError("Внутрішній запис має бути словником або None.")
    if "cve_id" in record and record["cve_id"] != cve_id:
        raise ValueError("Ідентифікатор запису не збігається із запитаним CVE.")

    description = record.get("description")
    vuln_status = record.get("vuln_status")

    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": "Rejected",
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "rejected",
        }

    score = record.get("score")
    cvss_data = record.get("cvss_data")

    if vuln_status is None or score is None or not isinstance(cvss_data, dict):
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not (0 <= score <= 10)
    ):
        raise ValueError("Некоректне значення оцінки score у внутрішньому записі.")

    field: str = rule["field"]
    allowed_values = ALLOWED_FIELD_VALUES[field]

    if field not in cvss_data:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": record.get("cvss_version"),
            "score": float(score),
            "score_source": record.get("score_source"),
            "vector": record.get("vector"),
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in allowed_values:
        raise ValueError(f"Недопустиме значення поля {field}: {observed!r}")

    decision = (
        "review"
        if float(score) >= rule["threshold"] and observed == rule["expected"]
        else "other"
    )

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": record.get("cvss_version"),
        "score": float(score),
        "score_source": record.get("score_source"),
        "vector": record.get("vector"),
        "rule": rule,
        "observed": observed,
        "decision": decision,
    }
