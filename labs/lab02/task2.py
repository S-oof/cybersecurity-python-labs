import argparse
import csv
import logging
import math
import re
from collections import Counter
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

logger = logging.getLogger(__name__)

# Регулярні вирази для фільтрації доменів (re)
# Шукає піддомени завдовжки від 20 символів
LONG_SUBDOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9-]{20,}\.", re.IGNORECASE)
# Шукає специфічні/підозрілі доменні зони
SUSPICIOUS_TLD_REGEX = re.compile(
    r"\.(xyz|top|zip|click|kim|guru|tk|cc|cn|buzz)$", re.IGNORECASE
)


def calculate_entropy(
    text: str,
) -> float:  # Обчислює Ентропію Шеннона для оцінки випадковості символів
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counter.values()
    )


def load_blacklist(
    path: Path,
) -> set[str]:  # Зчитує файл чорного списку та повертає set із заблокованими доменами
    if not path.exists():
        logger.warning(f"Файл чорного списку '{path}' не знайдено.")
        return set()

    with open(path, "r", encoding="utf-8") as f:
        return {
            line.strip().lower()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        }


def parse_dns_log(log_path: Path, blacklist: set[str], min_domain_len: int):
    type_counter = Counter()
    suspicious_records = []  # Зчитує рядки, підраховує статистику типів запитів

    if not log_path.exists():
        logger.error(f"Файл логів '{log_path}' не знайдено!")
        return type_counter, suspicious_records, 0

    logger.info(f"Parsing DNS log file {log_path}...")

    total_records = 0
    with open(log_path, "r", encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)

        # Визначаємо роздільник
        delimiter = ","
        if ";" in sample and sample.count(";") > sample.count(","):
            delimiter = ";"
        elif "\t" in sample and sample.count("\t") > sample.count(","):
            delimiter = "\t"

        reader = csv.DictReader(f, delimiter=delimiter)

        for raw_row in reader:
            if not raw_row or not any(raw_row.values()):
                continue

            # Очищаємо ключі та значення від пробілів та лапок
            row = {
                (str(k).strip().strip("\"'").lower() if k else ""): (
                    str(v).strip().strip("\"'") if v else ""
                )
                for k, v in raw_row.items()
            }

            # Гнучкий пошук колонки домену за всіма можливими назвами
            domain = ""
            for key in ["domain", "qname", "host", "query", "name", "url"]:
                if row.get(key):
                    domain = row[key].lower()
                    break

            if not domain:
                vals = [v for v in row.values() if v]
                if len(vals) >= 3:
                    domain = vals[2].lower()

            if not domain:
                continue

            total_records += 1

            # Пошук типу запиту (A, AAAA, TXT, MX тощо)
            query_type = ""
            for key in ["querytype", "type", "qtype", "rrtype"]:
                if row.get(key):
                    query_type = row[key].upper()
                    break

            if not query_type:
                vals = [v for v in row.values() if v]
                query_type = vals[3].upper() if len(vals) > 3 else "A"

            # Пошук Timestamp та ClientIP
            timestamp = next(
                (v for k, v in row.items() if any(x in k for x in ["time", "date"])), ""
            )
            client_ip = next(
                (
                    v
                    for k, v in row.items()
                    if any(x in k for x in ["ip", "client", "src"])
                ),
                "127.0.0.1",
            )

            type_counter[query_type] += 1

            # Перевірка аномалій
            if any(domain == b or domain.endswith("." + b) for b in blacklist):
                reason = "BLACKMATCH"  # Перевірка на збіг із чорним
                detail = f"Client {client_ip} queried blacklisted domain: {domain}"

            elif LONG_SUBDOMAIN_REGEX.search(domain):
                reason = "REGEX-LONG-SUBDOMAIN"  # надто довгий піддомен
                detail = f"Overly long subdomain detected via regex in: {domain}"

            elif SUSPICIOUS_TLD_REGEX.search(domain):
                reason = "REGEX-SUSPICIOUS-TLD"
                detail = f"Specific/suspicious TLD detected in domain: {domain}"

            elif len(domain) >= min_domain_len:
                reason = "DGA-DETECT"
                detail = f"Abnormally long {query_type} query domain: {domain} (Length: {len(domain)})"

            else:
                first_subdomain = domain.split(".")[0]
                if (
                    len(first_subdomain) > 12
                    and calculate_entropy(first_subdomain) > 3.8
                ):
                    reason = "DGA-DETECT"
                    detail = f"High entropy / suspicious subdomain: {domain} (Client: {client_ip})"
                else:
                    continue

            suspicious_records.append(
                {  # Додавання аномального запису до списку
                    "Timestamp": timestamp,
                    "ClientIP": client_ip,
                    "Domain": domain,
                    "QueryType": query_type,
                    "Reason": reason,
                    "Details": detail,
                }
            )

    logger.info(f"Processed {total_records:,} DNS query records.")
    return type_counter, suspicious_records, total_records


def print_stats(type_counter: Counter, total_records: int):
    print("\n=== Query Type Breakdown ===")
    if total_records == 0:
        print("Записи відсутні.")
        return

    target_types = ["A", "AAAA", "TXT", "MX"]  ## Сортування
    all_types = sorted(
        set(target_types) | set(type_counter.keys()),
        key=lambda x: (
            x not in target_types,
            target_types.index(x) if x in target_types else x,
        ),
    )

    for qtype in all_types:
        count = type_counter[qtype]
        percentage = (count / total_records) * 100 if total_records > 0 else 0
        print(f"{qtype:<4} : {count:,} ({percentage:.1f}%)")


def print_suspicious_activity(records: list[dict]):  # Виводить список
    if not records:
        return
    print("\n=== Suspicious DNS Activity ===")
    for record in records:
        print(f"[{record['Reason']}] {record['Details']}")


def export_to_csv(
    records: list[dict], out_path: Path
):  # Записує всі виявлені аномальні
    if not records:
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["Timestamp", "ClientIP", "Domain", "QueryType", "Reason", "Details"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print()
    logger.info(f"Suspicious records exported to {out_path}")


def main():
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"

    # Конфігурація CLI
    parser = argparse.ArgumentParser(
        description="Утиліта аналізу DNS-логів на наявність DGA та аномалій."
    )
    parser.add_argument(
        "--dns-log",
        type=Path,
        default=data_dir / "dns_queries.csv",
        help="Шлях до CSV-файлу логів DNS",
    )
    parser.add_argument(
        "--blacklist",
        type=Path,
        default=data_dir / "blacklist.txt",
        help="Шлях до файлу чорного списку",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=base_dir / "dns_alerts.csv",
        help="Шлях для експорту аномалій у CSV",
    )
    parser.add_argument(
        "--min-domain-len",
        type=int,
        default=40,
        help="Мінімальна довжина домену для позначення як аномального",
    )

    args = parser.parse_args()

    blacklist = load_blacklist(args.blacklist)
    type_counter, suspicious_records, total_records = parse_dns_log(
        args.dns_log, blacklist, args.min_domain_len
    )

    print_stats(type_counter, total_records)
    print_suspicious_activity(suspicious_records)

    if suspicious_records:
        export_to_csv(suspicious_records, args.out_csv)


if __name__ == "__main__":
    main()
