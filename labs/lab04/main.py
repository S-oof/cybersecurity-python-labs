"""Точка входу CLI-утиліти аналізу вразливостей CVE з NVD."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_REGEX = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    """Зчитує та декодує локальну UTF-8 JSON-відповідь NVD з файла."""
    file_path = Path(path)
    content = file_path.read_text(encoding="utf-8")
    return json.loads(content)


def _parse_cve_argument(value: str) -> str:
    """Валідує формат аргументу --cve під час розбору CLI."""
    if not CVE_REGEX.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "Ідентифікатор CVE має відповідати шаблону CVE-YYYY-NNNN+ (верхній регістр)."
        )
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Аналіз запису CVE з NVD API або локального JSON-файла.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=_parse_cve_argument,
        help="Ідентифікатор вразливості у форматі CVE-YYYY-NNNN+.",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Шлях до локального JSON-файла відповіді NVD (без звернення до мережі).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Запускає обробку CLI-команди та повертає код завершення."""
    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or not (1 <= VARIANT_NUMBER <= 15)
    ):
        print(
            "Помилка конфігурації: номер варіанта має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.input is not None:
        try:
            payload = load_response(args.input)
        except (OSError, UnicodeDecodeError):
            print(
                "Помилка читання локального файла з відповіддю NVD.",
                file=sys.stderr,
            )
            return 1
        except json.JSONDecodeError:
            print(
                "Помилка декодування: локальний файл не містить коректний JSON.",
                file=sys.stderr,
            )
            return 1
    else:
        try:
            payload = api_client.fetch_response(args.cve)
        except requests.Timeout:
            print(
                "Помилка мережі: перевищено час очікування відповіді від NVD API.",
                file=sys.stderr,
            )
            return 1
        except requests.ConnectionError:
            print(
                "Помилка мережі: не вдалося встановити з'єднання із сервером NVD API.",
                file=sys.stderr,
            )
            return 1
        except requests.HTTPError as exc:
            status = (
                exc.response.status_code if exc.response is not None else "невідомий"
            )
            print(
                f"Помилка HTTP під час звернення до NVD API (статус: {status}).",
                file=sys.stderr,
            )
            return 1
        except (requests.exceptions.JSONDecodeError, json.JSONDecodeError):
            print(
                "Помилка декодування: відповідь NVD API не є коректним JSON.",
                file=sys.stderr,
            )
            return 1
        except requests.RequestException:
            print(
                "Помилка мережевого запиту до NVD API.",
                file=sys.stderr,
            )
            return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Помилка перевірки структури або значень даних: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
