"""Модульні тести HTTP-клієнта NVD API з підміною requests.get."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_api_key() -> None:
    """Без NVD_API_KEY повертається лише заголовок Accept."""
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_ignores_whitespace_only_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Порожній або пробільний NVD_API_KEY не додається до заголовків."""
    monkeypatch.setenv("NVD_API_KEY", "   \t  ")
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_fake_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Непорожній NVD_API_KEY очищується від крайніх пробілів і передається в apiKey."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key-008  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key-008",
    }


def test_fetch_response_success_with_expected_params_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Перевіряє URL, параметри, заголовки, таймаут і вимкнення редіректів."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    monkeypatch.setenv("NVD_API_KEY", "fake-api-key")

    result = api_client.fetch_response("CVE-2099-10001")

    assert result == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json", "apiKey": "fake-api-key"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_response_raises_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP-помилка піднімає requests.HTTPError через raise_for_status()."""
    response = Mock(spec=requests.Response)
    response.status_code = 503
    response.raise_for_status.side_effect = requests.HTTPError(
        "503 Service Unavailable",
        response=response,
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_raises_on_redirect_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Неочікуваний статус редіректу (302) за allow_redirects=False викликає HTTPError."""
    response = Mock(spec=requests.Response)
    response.status_code = 302

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Таймаут з'єднання або читання передається як requests.Timeout."""
    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(side_effect=requests.Timeout("Read timed out")),
    )

    with pytest.raises(requests.Timeout):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_raises_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Некоректний JSON у тілі відповіді викликає JSONDecodeError."""
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON",
        "{",
        1,
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")