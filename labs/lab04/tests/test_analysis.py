"""Модульні тести перевірки структури даних і правила варіанта №8."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from labs.lab04 import analysis

CVE_ID = "CVE-2099-10001"
VARIANT = 8


@pytest.mark.parametrize(
    ("score", "scope", "expected_decision"),
    [
        (8.9, "CHANGED", "other"),  # нижче порога 9.0 за відповідної ознаки
        (9.0, "CHANGED", "review"),  # рівно на порозі 9.0 за відповідної ознаки
        (9.1, "CHANGED", "review"),  # вище порога 9.0 за відповідної ознаки
        (9.8, "UNCHANGED", "other"),  # висока оцінка, але невідповідна ознака
    ],
)
def test_variant8_threshold_and_scope(
    changed_scope_payload: dict[str, Any],
    score: float,
    scope: str,
    expected_decision: str,
) -> None:
    """Перевіряє порівняння на межі порога 9.0 та ознаку scope == CHANGED."""
    payload = copy.deepcopy(changed_scope_payload)
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    cvss_data["baseScore"] = score
    cvss_data["scope"] = scope

    snapshot_before = copy.deepcopy(payload)
    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert payload == snapshot_before
    assert report == {
        "cve_id": CVE_ID,
        "variant": 8,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": score,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {
            "threshold": 9.0,
            "field": "scope",
            "expected": "CHANGED",
        },
        "observed": scope,
        "decision": expected_decision,
    }


def test_not_found_returns_null_data_fields() -> None:
    """Порожній список vulnerabilities формує стан not_found."""
    payload = {"vulnerabilities": []}
    record = analysis.extract_record(payload, CVE_ID)
    assert record is None

    report = analysis.build_report(record, CVE_ID, VARIANT)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == VARIANT
    assert report["rule"] == {"threshold": 9.0, "field": "scope", "expected": "CHANGED"}
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_skips_metrics_analysis(changed_scope_payload: dict[str, Any]) -> None:
    """Статус Rejected формує rejected і обнуляє оцінку навіть за високого балу."""
    payload = copy.deepcopy(changed_scope_payload)
    payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None
    assert report["cvss_version"] is None


def test_missing_vuln_status_gives_insufficient_data(
    changed_scope_payload: dict[str, Any],
) -> None:
    """Відсутній vulnStatus формує insufficient_data без аналізу оцінок."""
    payload = copy.deepcopy(changed_scope_payload)
    del payload["vulnerabilities"][0]["cve"]["vulnStatus"]

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_cvss_v31_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Відсутня оцінка cvssMetricV31 за статусу Analyzed дає insufficient_data."""
    payload = copy.deepcopy(sample_payload)
    payload["vulnerabilities"][0]["cve"]["metrics"] = {}

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_scope_field_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Відсутність поля scope у cvssData означає брак даних (insufficient_data)."""
    payload = copy.deepcopy(sample_payload)
    del payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "scope"
    ]

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad_scope", [None, 123, True, "INVALID", ""])
def test_invalid_scope_value_raises_value_error(
    sample_payload: dict[str, Any],
    bad_scope: Any,
) -> None:
    """Null або недопустиме значення поля scope спричиняє ValueError."""
    payload = copy.deepcopy(sample_payload)
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "scope"
    ] = bad_scope

    record = analysis.extract_record(payload, CVE_ID)
    with pytest.raises(ValueError):
        analysis.build_report(record, CVE_ID, VARIANT)


@pytest.mark.parametrize(
    "bad_score", ["9.8", True, False, -0.1, 10.1, float("nan"), float("inf")]
)
def test_invalid_base_score_raises_value_error(
    sample_payload: dict[str, Any],
    bad_score: Any,
) -> None:
    """Некоректний тип або межі baseScore викликають ValueError."""
    payload = copy.deepcopy(sample_payload)
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = bad_score

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_primary_metric_has_priority_over_earlier_secondary(
    sample_payload: dict[str, Any],
) -> None:
    """Перша оцінка Primary має пріоритет над попередньою Secondary."""
    payload = copy.deepcopy(sample_payload)
    primary_metric = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    secondary_metric = {
        "source": "cna@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "scope": "CHANGED",
            "baseScore": 10.0,
        },
    }
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary_metric,
        primary_metric,
    ]

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"
    assert report["observed"] == "UNCHANGED"
    assert report["decision"] == "other"


def test_first_metric_selected_when_no_primary_exists(
    sample_payload: dict[str, Any],
) -> None:
    """За відсутності Primary вибирається перший елемент cvssMetricV31."""
    payload = copy.deepcopy(sample_payload)
    first_secondary = {
        "source": "first-cna@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "scope": "CHANGED",
            "baseScore": 9.3,
        },
    }
    second_secondary = {
        "source": "second-cna@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
            "scope": "UNCHANGED",
            "baseScore": 4.2,
        },
    }
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first_secondary,
        second_secondary,
    ]

    record = analysis.extract_record(payload, CVE_ID)
    report = analysis.build_report(record, CVE_ID, VARIANT)

    assert report["score"] == 9.3
    assert report["score_source"] == "first-cna@example.org"
    assert report["observed"] == "CHANGED"
    assert report["decision"] == "review"
