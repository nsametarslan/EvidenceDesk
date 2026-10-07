"""Strict canonical import: validate everything before touching the database."""
import csv
import hashlib
import io
import ipaddress
import json
from datetime import datetime, timezone

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 20_000
FIELDS = ("timestamp", "user", "source_ip", "host", "outcome", "log_source")


class ImportProblem(ValueError):
    pass


def clean_text(value, field, limit=160):
    if not isinstance(value, str) or not value.strip():
        raise ImportProblem(f"{field} must be a non-empty string.")
    value = value.strip()
    if len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ImportProblem(f"{field} is too long or contains control characters.")
    return value


def normalize(row):
    if not isinstance(row, dict) or any(k not in FIELDS for k in row):
        raise ImportProblem("Use only the documented canonical fields.")
    values = {f: clean_text(row.get(f), f) for f in FIELDS[:-1]}
    values["log_source"] = clean_text(row.get("log_source") or "unspecified", "log_source")
    try:
        stamp = datetime.fromisoformat(values["timestamp"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("timezone missing")
        stamp = stamp.astimezone(timezone.utc)
        values["timestamp"] = stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
        values["source_ip"] = str(ipaddress.ip_address(values["source_ip"]))
    except (ValueError, OverflowError) as exc:
        raise ImportProblem("timestamp needs an ISO-8601 timezone; source_ip needs a valid IP.") from exc
    if values["outcome"] not in {"success", "failure"}:
        raise ImportProblem("outcome must be exactly success or failure.")
    canonical = json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    values["id"] = hashlib.sha256(canonical.encode()).hexdigest()
    return values


def parse_upload(data, filename):
    if not data or len(data) > MAX_BYTES:
        raise ImportProblem("Upload a non-empty file no larger than 2 MiB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportProblem("The file must be UTF-8 CSV or JSONL.") from exc
    suffix = filename.lower().rsplit(".", 1)[-1]
    if suffix == "csv":
        reader = csv.DictReader(io.StringIO(text), strict=True)
        try:
            columns = reader.fieldnames
        except csv.Error as exc:
            raise ImportProblem('Malformed CSV header; no events were imported.') from exc
        if not columns or len(columns) != len(set(columns)) or not set(FIELDS[:-1]) <= set(columns) or not set(columns) <= set(FIELDS):
            raise ImportProblem("CSV headers must match the documented canonical schema.")
        rows = reader
    elif suffix == "jsonl":
        def json_rows():
            for line in text.splitlines():
                if not line.strip():
                    raise ImportProblem("JSONL must contain one event per line, without blank lines.")
                yield json.loads(line)
        rows = json_rows()
    else:
        raise ImportProblem("Only .csv and .jsonl files are supported.")
    events = []
    try:
        for number, row in enumerate(rows, 1):
            if number > MAX_ROWS:
                raise ImportProblem("Import limit: 20,000 events per file.")
            try:
                events.append(normalize(row))
            except ImportProblem as exc:
                raise ImportProblem(f"Event {number}: {exc}") from exc
    except (csv.Error, json.JSONDecodeError, RecursionError) as exc:
        raise ImportProblem("Malformed CSV or JSONL; no events were imported.") from exc
    if not events:
        raise ImportProblem("The file contains no events.")
    return events
