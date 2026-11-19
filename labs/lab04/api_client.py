"""HTTP-клієнт для отримання записів CVE з NVD API 2.0."""

from __future__ import annotations

import os
from typing import Any

import requests

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, float] = (3.05, 10)


def build_headers() -> dict[str, str]:
    """Формує HTTP-заголовки запиту з опціональним ключем NVD_API_KEY."""
    headers: dict[str, str] = {"Accept": "application/json"}
    raw_key = os.getenv("NVD_API_KEY")
    if raw_key is not None:
        cleaned_key = raw_key.strip()
        if cleaned_key:
            headers["apiKey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD CVE API 2.0 та повертає декодований JSON."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.HTTPError(
            f"Unexpected HTTP status code: {response.status_code}",
            response=response,
        )
    return response.json()
