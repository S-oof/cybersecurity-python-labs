"""Інтеграційні тести CLI та локального режиму роботи."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.conftest import SAMPLE_PATH


def test_main_local_sample_outputs_other_for_variant8(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Локальний запуск на nvd_sample.json формує коректний JSON-звіт для варіанта 8."""
    exit_code = main.main(
        ["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)],
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 8
    assert report["score"] == 9.8
    assert report["observed"] == "UNCHANGED"
    assert report["decision"] == "other"


def test_main_local_custom_file_review_decision(
    tmp_path: Path,
    changed_scope_payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Локальний файл зі score >= 9.0 та scope='CHANGED' повертає decision='review'."""
    input_file = tmp_path / "custom_nvd.json"
    input_file.write_text(json.dumps(changed_scope_payload), encoding="utf-8")

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(input_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"
    assert report["observed"] == "CHANGED"


def test_main_missing_input_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Відсутній локальний файл завершується кодом 1 і повідомленням у stderr."""
    missing = tmp_path / "does_not_exist.json"
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_main_corrupted_json_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Пошкоджений JSON-файл завершується кодом 1 і повідомленням у stderr."""
    broken_file = tmp_path / "broken.json"
    broken_file.write_text("{not-valid-json", encoding="utf-8")

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(broken_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""


@pytest.mark.parametrize("invalid_cve", ["cve-2099-10001", "CVE-2021-123", "INVALID"])
def test_main_invalid_cve_exits_with_code_2(
    invalid_cve: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Некоректний формат --cve спричиняє завершення з кодом 2."""
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", invalid_cve, "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.err.strip() != ""


@pytest.mark.parametrize("bad_variant", [True, 0, 16, "8"])
def test_main_invalid_variant_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    bad_variant: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Некоректний VARIANT_NUMBER у модулі main повертає код 2."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad_variant)
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_main_http_error_does_not_leak_api_key_or_body(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Помилка HTTP у CLI повертає код 1 і не виводить ключ чи тіло відповіді."""
    secret_key = "SUPER-SECRET-API-KEY-999"
    monkeypatch.setenv("NVD_API_KEY", secret_key)

    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.text = "SECRET_BACKEND_BODY"
    response.raise_for_status.side_effect = requests.HTTPError(
        f"404 Not Found with key {secret_key}",
        response=response,
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    exit_code = main.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "404" in captured.err
    assert secret_key not in captured.err
    assert "SECRET_BACKEND_BODY" not in captured.err
