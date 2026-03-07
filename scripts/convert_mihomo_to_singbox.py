#!/usr/bin/env python3

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "rules" / "mihomo"
TARGET_DIR = ROOT / "rules" / "sing-box"
VERSION = 4

DOMAIN_FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
IP_FIELDS = ("ip_cidr",)
ALL_FIELDS = DOMAIN_FIELDS + IP_FIELDS

CIDR_PATTERN = re.compile(r"^[0-9A-Fa-f:.]+/\d+$")


def strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_payload_yaml(path: Path) -> list[str]:
    items: list[str] = []
    in_payload = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "payload:":
            in_payload = True
            continue
        if not in_payload or not line.startswith("- "):
            continue
        items.append(strip_quotes(line[2:].strip()))

    if not items:
        raise ValueError(f"no payload items found in {path}")
    return items


def classify_payload_item(item: str) -> tuple[str, str]:
    if item.startswith("+."):
        return "domain_suffix", item[2:]
    if CIDR_PATTERN.match(item):
        return "ip_cidr", item
    return "domain", item


def parse_classical_line(line: str) -> tuple[str, str]:
    rule_type, separator, rule_value = line.partition(",")
    if not separator:
        raise ValueError(f"invalid classical rule: {line}")

    mapping = {
        "DOMAIN": "domain",
        "DOMAIN-SUFFIX": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword",
        "DOMAIN-REGEX": "domain_regex",
        "IP-CIDR": "ip_cidr",
        "IP-CIDR6": "ip_cidr",
    }
    field = mapping.get(rule_type)
    if field is None:
        raise ValueError(f"unsupported classical rule type: {rule_type}")
    return field, rule_value


def load_classical_list(path: Path) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(parse_classical_line(line))

    if not items:
        raise ValueError(f"no classical items found in {path}")
    return items


def build_rules(entries: list[tuple[str, str]]) -> list[dict[str, list[str]]]:
    grouped: dict[str, list[str]] = {field: [] for field in ALL_FIELDS}
    for field, value in entries:
        grouped[field].append(value)

    rules: list[dict[str, list[str]]] = []

    domain_rule = {
        field: values
        for field, values in grouped.items()
        if field in DOMAIN_FIELDS and values
    }
    if domain_rule:
        rules.append(domain_rule)

    ip_rule = {
        field: values
        for field, values in grouped.items()
        if field in IP_FIELDS and values
    }
    if ip_rule:
        rules.append(ip_rule)

    if not rules:
        raise ValueError("no supported entries were converted")
    return rules


def convert_file(path: Path) -> dict[str, object]:
    if path.suffix == ".list":
        entries = load_classical_list(path)
    else:
        entries = [classify_payload_item(item) for item in load_payload_yaml(path)]

    return {
        "version": VERSION,
        "rules": build_rules(entries),
    }


def main() -> None:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    for source_path in sorted(SOURCE_DIR.iterdir()):
        if not source_path.is_file():
            continue
        if "meituan" in source_path.stem.lower():
            continue

        converted = convert_file(source_path)
        target_path = TARGET_DIR / f"{source_path.stem}.json"
        target_path.write_text(
            json.dumps(converted, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {target_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
