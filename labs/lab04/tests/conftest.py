"""Спільні фікстури та ізоляція мережі для тестів ЛР №4."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Видаляє NVD_API_KEY та блокує будь-які реальні HTTP-запити Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Повертає свіжу копію синтетичної відповіді NVD."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(data)


@pytest.fixture
def changed_scope_payload(sample_payload: dict[str, Any]) -> dict[str, Any]:
    """Повертає копію відповіді зі зміненою межею впливу scope='CHANGED'."""
    payload = copy.deepcopy(sample_payload)
    metric = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    metric["cvssData"]["scope"] = "CHANGED"
    return payload
