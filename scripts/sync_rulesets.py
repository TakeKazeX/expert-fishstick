#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "rules" / "ruleset"
CANONICAL_DIR = ROOT / "rules" / "intermediate"
LOON_DIR = ROOT / "rules" / "Loon"
MIHOMO_DIR = ROOT / "rules" / "mihomo"
SINGBOX_DIR = ROOT / "rules" / "sing-box"

CANONICAL_VERSION = 1
SINGBOX_VERSION = 4

CIDR_PATTERN = re.compile(r"^[0-9A-Fa-f:.]+/\d+$")
RULE_TYPE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

RULE_TYPE_ALIASES = {
    "DEST-PORT": "DST-PORT",
}

SINGBOX_FIELD_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "SRC-IP-CIDR6": "source_ip_cidr",
    "DST-PORT": "port",
    "SRC-PORT": "source_port",
    "NETWORK": "network",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
    "PACKAGE-NAME": "package_name",
}

SINGBOX_RULE_GROUPS = (
    ("domain", "domain_suffix", "domain_keyword", "domain_regex"),
    ("process_name", "process_path", "package_name"),
    ("network", "port", "source_port"),
    ("ip_cidr", "source_ip_cidr"),
)

MIHOMO_DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}
MIHOMO_IP_TYPES = {"IP-CIDR", "IP-CIDR6"}


@dataclass(frozen=True)
class RuleEntry:
    rule_type: str
    value: str
    options: tuple[str, ...] = ()


def strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def normalize_rule_type(rule_type: str) -> str:
    normalized = rule_type.strip().upper()
    return RULE_TYPE_ALIASES.get(normalized, normalized)


def format_classical(entry: RuleEntry) -> str:
    parts = [entry.rule_type, entry.value, *entry.options]
    return ",".join(parts)


def format_loon(entry: RuleEntry) -> str:
    if entry.rule_type == "DOMAIN-WILDCARD":
        raise ValueError(f"loon export does not support mihomo wildcard domain: {entry.value}")

    rule_type = "DEST-PORT" if entry.rule_type == "DST-PORT" else entry.rule_type
    parts = [rule_type, entry.value, *entry.options]
    return ",".join(parts)


def infer_cidr_rule_type(value: str, source_type: str = "IP-CIDR") -> str:
    if ":" in value:
        return "IP-CIDR6" if source_type == "IP-CIDR" else "SRC-IP-CIDR6"
    return source_type


def parse_classical_line(line: str) -> RuleEntry:
    parts = [strip_quotes(part.strip()) for part in line.split(",")]
    if len(parts) < 2:
        raise ValueError(f"invalid classical rule: {line}")

    rule_type = normalize_rule_type(parts[0])
    if not RULE_TYPE_PATTERN.match(rule_type):
        raise ValueError(f"invalid classical rule type: {parts[0]}")

    value = parts[1]
    options = tuple(part for part in parts[2:] if part)
    return RuleEntry(rule_type=rule_type, value=value, options=options)


def parse_shorthand_rule(item: str) -> RuleEntry:
    if item.startswith("+."):
        return RuleEntry(rule_type="DOMAIN-SUFFIX", value=item[2:])
    if item.startswith(".") or "*" in item:
        return RuleEntry(rule_type="DOMAIN-WILDCARD", value=item)
    if CIDR_PATTERN.match(item):
        return RuleEntry(rule_type=infer_cidr_rule_type(item), value=item)
    return RuleEntry(rule_type="DOMAIN", value=item)


def parse_payload_item(item: str) -> RuleEntry:
    rule_type, separator, _ = item.partition(",")
    if separator and RULE_TYPE_PATTERN.match(normalize_rule_type(rule_type)):
        return parse_classical_line(item)
    return parse_shorthand_rule(item)


def load_payload_rules(path: Path) -> list[RuleEntry]:
    entries: list[RuleEntry] = []
    in_payload = False

    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "payload:":
            in_payload = True
            continue
        if not in_payload or not line.startswith("- "):
            continue
        item = strip_quotes(line[2:].strip())
        entries.append(parse_payload_item(item))

    if not entries:
        raise ValueError(f"no payload items found in {path}")
    return entries


def load_classical_rules(path: Path) -> list[RuleEntry]:
    entries: list[RuleEntry] = []

    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(parse_classical_line(line))

    if not entries:
        raise ValueError(f"no classical items found in {path}")
    return entries


def normalize_singbox_values(raw_value: object) -> list[str]:
    if isinstance(raw_value, list):
        values = raw_value
    else:
        values = [raw_value]

    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"unsupported sing-box value type: {type(value).__name__}")
        normalized.append(value)
    return normalized


def load_singbox_rules(path: Path) -> list[RuleEntry]:
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid sing-box JSON in {path}: {exc}") from exc

    rules = data.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"sing-box file missing rules array: {path}")

    entries: list[RuleEntry] = []

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError(f"invalid sing-box rule in {path}: expected object")

        unsupported_fields = sorted(
            key for key in rule.keys() if key not in set(SINGBOX_FIELD_MAP.values())
        )
        if unsupported_fields:
            raise ValueError(
                f"unsupported sing-box fields in {path}: {', '.join(unsupported_fields)}"
            )

        for rule_type, field in SINGBOX_FIELD_MAP.items():
            if field not in rule:
                continue
            for value in normalize_singbox_values(rule[field]):
                normalized_type = rule_type
                if rule_type == "IP-CIDR":
                    normalized_type = infer_cidr_rule_type(value, "IP-CIDR")
                elif rule_type == "SRC-IP-CIDR":
                    normalized_type = infer_cidr_rule_type(value, "SRC-IP-CIDR")
                entries.append(RuleEntry(rule_type=normalized_type, value=value))

    if not entries:
        raise ValueError(f"no supported sing-box items found in {path}")
    return entries


def detect_source_format(path: Path) -> str:
    text = read_text(path)
    stripped_lines = [
        line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
    ]
    if not stripped_lines:
        raise ValueError(f"empty rule file: {path}")

    first_line = stripped_lines[0]
    if first_line.startswith("{"):
        return "sing-box"
    if first_line == "payload:":
        return "mihomo"
    return "classical"


def load_source_entries(path: Path) -> tuple[str, list[RuleEntry]]:
    source_format = detect_source_format(path)

    if source_format == "sing-box":
        return source_format, load_singbox_rules(path)
    if source_format == "mihomo":
        return source_format, load_payload_rules(path)
    return source_format, load_classical_rules(path)


def dedupe_entries(entries: list[RuleEntry]) -> list[RuleEntry]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    result: list[RuleEntry] = []

    for entry in entries:
        key = (entry.rule_type, entry.value, entry.options)
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)

    return result


def build_canonical_document(
    name: str, source_specs: list[tuple[Path, str]], entries: list[RuleEntry]
) -> dict[str, object]:
    document: dict[str, object] = {
        "version": CANONICAL_VERSION,
        "name": name,
        "sources": [
            {
                "path": str(source_path.relative_to(ROOT)),
                "format": source_format,
            }
            for source_path, source_format in source_specs
        ],
        "entries": [
            {
                "type": entry.rule_type,
                "value": entry.value,
                **({"options": list(entry.options)} if entry.options else {}),
            }
            for entry in entries
        ],
    }
    if len(source_specs) == 1:
        document["source"] = document["sources"][0]
    return document


def split_logical_name(stem: str) -> tuple[str, str]:
    for suffix in ("_ip", "_classical"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)], suffix[1:]
    return stem, "base"


def group_inputs(paths: list[Path]) -> list[tuple[str, list[Path]]]:
    grouped: dict[str, list[Path]] = {}
    for path in sorted(paths):
        logical_name, _ = split_logical_name(path.stem)
        grouped.setdefault(logical_name, []).append(path)
    return sorted(grouped.items())


def load_group_entries(paths: list[Path]) -> tuple[list[tuple[Path, str]], list[RuleEntry]]:
    source_specs: list[tuple[Path, str]] = []
    entries: list[RuleEntry] = []

    for path in paths:
        source_format, path_entries = load_source_entries(path)
        source_specs.append((path, source_format))
        entries.extend(path_entries)

    return source_specs, entries


def render_loon(entries: list[RuleEntry]) -> str:
    lines = [format_loon(entry) for entry in entries]
    return "\n".join(lines) + "\n"


def render_mihomo_domain(entries: list[RuleEntry]) -> str:
    lines = ["payload:"]
    for entry in entries:
        if entry.rule_type == "DOMAIN":
            lines.append(f"  - {entry.value}")
        elif entry.rule_type == "DOMAIN-SUFFIX":
            lines.append(f"  - +.{entry.value}")
        elif entry.rule_type == "DOMAIN-WILDCARD":
            lines.append(f"  - {entry.value}")
        elif entry.rule_type == "DOMAIN-REGEX":
            lines.append(f"  - DOMAIN-REGEX,{entry.value}")
        else:
            raise ValueError(f"mihomo domain export does not support rule type: {entry.rule_type}")
    return "\n".join(lines) + "\n"


def render_mihomo_ipcidr(entries: list[RuleEntry]) -> str:
    lines = ["payload:"]
    lines.extend(f"  - {entry.value}" for entry in entries)
    return "\n".join(lines) + "\n"


def render_mihomo_classical(entries: list[RuleEntry]) -> str:
    lines = ["payload:"]
    lines.extend(f"  - {format_classical(entry)}" for entry in entries)
    return "\n".join(lines) + "\n"


def split_mihomo_entries(
    entries: list[RuleEntry],
) -> tuple[list[RuleEntry], list[RuleEntry], list[RuleEntry]]:
    domain_entries: list[RuleEntry] = []
    ip_entries: list[RuleEntry] = []
    classical_entries: list[RuleEntry] = []

    for entry in entries:
        if entry.options:
            classical_entries.append(entry)
            continue
        if entry.rule_type in MIHOMO_DOMAIN_TYPES:
            domain_entries.append(entry)
            continue
        if entry.rule_type in MIHOMO_IP_TYPES:
            ip_entries.append(entry)
            continue
        classical_entries.append(entry)

    return domain_entries, ip_entries, classical_entries


def build_singbox_rules(entries: list[RuleEntry]) -> list[dict[str, list[str]]]:
    grouped: dict[str, list[str]] = {}

    for entry in entries:
        if entry.options:
            raise ValueError(
                f"sing-box export does not support extra classical options: {format_classical(entry)}"
            )

        field = SINGBOX_FIELD_MAP.get(entry.rule_type)
        if field is None:
            raise ValueError(f"sing-box export does not support rule type: {entry.rule_type}")
        grouped.setdefault(field, []).append(entry.value)

    rules: list[dict[str, list[str]]] = []
    for fields in SINGBOX_RULE_GROUPS:
        rule = {field: grouped[field] for field in fields if grouped.get(field)}
        if rule:
            rules.append(rule)

    remaining_fields = sorted(set(grouped) - {field for group in SINGBOX_RULE_GROUPS for field in group})
    for field in remaining_fields:
        rules.append({field: grouped[field]})

    if not rules:
        raise ValueError("no supported entries were converted for sing-box")
    return rules


def render_singbox(entries: list[RuleEntry]) -> str:
    return (
        json.dumps(
            {
                "version": SINGBOX_VERSION,
                "rules": build_singbox_rules(entries),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def resolve_inputs(inputs: list[str]) -> list[Path]:
    if not inputs:
        return sorted(path for path in SOURCE_DIR.iterdir() if path.is_file() and not path.name.startswith("."))

    resolved: list[Path] = []
    for item in inputs:
        candidate = Path(item)
        if candidate.is_absolute() and candidate.exists():
            resolved.append(candidate)
            continue

        repo_relative = ROOT / item
        if repo_relative.exists():
            resolved.append(repo_relative)
            continue

        source_relative = SOURCE_DIR / item
        if source_relative.exists():
            resolved.append(source_relative)
            continue

        raise FileNotFoundError(f"cannot find input rule file: {item}")

    return resolved


def remove_stale_outputs(name: str, keep: set[Path]) -> None:
    stale_paths = {
        MIHOMO_DIR / f"{name}.yaml",
        MIHOMO_DIR / f"{name}_ip.yaml",
    }
    for path in stale_paths - keep:
        if path.exists():
            path.unlink()
            print(f"removed {path.relative_to(ROOT)}")


def write_outputs(name: str, source_specs: list[tuple[Path, str]], entries: list[RuleEntry]) -> None:
    canonical_doc = build_canonical_document(name, source_specs, entries)

    CANONICAL_DIR.mkdir(parents=True, exist_ok=True)
    LOON_DIR.mkdir(parents=True, exist_ok=True)
    MIHOMO_DIR.mkdir(parents=True, exist_ok=True)
    SINGBOX_DIR.mkdir(parents=True, exist_ok=True)

    canonical_path = CANONICAL_DIR / f"{name}.json"
    loon_path = LOON_DIR / f"{name}.list"
    singbox_path = SINGBOX_DIR / f"{name}.json"

    domain_entries, ip_entries, classical_entries = split_mihomo_entries(entries)
    mihomo_paths: set[Path] = set()

    canonical_path.write_text(
        json.dumps(canonical_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    loon_path.write_text(render_loon(entries), encoding="utf-8")
    singbox_path.write_text(render_singbox(entries), encoding="utf-8")

    if classical_entries:
        classical_path = MIHOMO_DIR / f"{name}.yaml"
        classical_path.write_text(render_mihomo_classical(entries), encoding="utf-8")
        mihomo_paths.add(classical_path)
    else:
        if domain_entries:
            domain_path = MIHOMO_DIR / f"{name}.yaml"
            domain_path.write_text(render_mihomo_domain(domain_entries), encoding="utf-8")
            mihomo_paths.add(domain_path)

        if ip_entries:
            ip_path = MIHOMO_DIR / f"{name}_ip.yaml"
            ip_path.write_text(render_mihomo_ipcidr(ip_entries), encoding="utf-8")
            mihomo_paths.add(ip_path)

    remove_stale_outputs(name, mihomo_paths)

    print(f"wrote {canonical_path.relative_to(ROOT)}")
    print(f"wrote {loon_path.relative_to(ROOT)}")
    for path in sorted(mihomo_paths):
        print(f"wrote {path.relative_to(ROOT)}")
    print(f"wrote {singbox_path.relative_to(ROOT)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize ruleset files and export to Loon, mihomo, and sing-box."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Rule files to process. Defaults to every file in rules/ruleset.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    for name, paths in group_inputs(resolve_inputs(args.inputs)):
        source_specs, raw_entries = load_group_entries(paths)
        entries = dedupe_entries(raw_entries)
        write_outputs(name, source_specs, entries)


if __name__ == "__main__":
    main()
