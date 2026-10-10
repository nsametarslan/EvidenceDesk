"""Read-only, explicit mapping preview for flattened Windows Security CSV."""
import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

from .ingest import MAX_BYTES, MAX_ROWS, ImportProblem, clean_text, normalize, unique_object

MAPPING_FIELDS = {"timestamp", "user", "source_ip", "host", "event_id"}
OUTCOMES = {"4624": "success", "4625": "failure"}
MAX_MAPPING_BYTES = 16 * 1024
PREVIEW_ROWS = 5


def parse_mapping(data):
    if not data or len(data) > MAX_MAPPING_BYTES:
        raise ImportProblem("Mapping must be non-empty and no larger than 16 KiB.")
    try:
        mapping = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ImportProblem("Mapping must be a UTF-8 JSON object.") from exc
    if not isinstance(mapping, dict) or set(mapping) != MAPPING_FIELDS:
        raise ImportProblem("Mapping must specify exactly timestamp, user, source_ip, host and event_id.")
    mapping = {key: clean_text(value, "mapping column") for key, value in mapping.items()}
    if len(set(mapping.values())) != len(mapping):
        raise ImportProblem("Each canonical field must map to a different source column.")
    return mapping


def preview(data, mapping_data):
    """Validate every row before returning a bounded preview; never import events."""
    mapping = parse_mapping(mapping_data)
    if not data or len(data) > MAX_BYTES:
        raise ImportProblem("CSV must be non-empty and no larger than 2 MiB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportProblem("CSV must be UTF-8.") from exc
    reader = csv.reader(io.StringIO(text), strict=True)
    samples, ids, counts = [], set(), {"success": 0, "failure": 0}
    total = 0
    try:
        headers = next(reader, None)
        if not headers or len(headers) != len(set(headers)):
            raise ImportProblem("CSV needs unique headers.")
        headers = [clean_text(header, "CSV header") for header in headers]
        if len(headers) != len(set(headers)) or not set(mapping.values()) <= set(headers):
            raise ImportProblem("Every mapped column must exist in the CSV without ambiguity.")
        indexes = {key: headers.index(column) for key, column in mapping.items()}
        for total, row in enumerate(reader, 1):
            if total > MAX_ROWS:
                raise ImportProblem("Preview limit: 20,000 events.")
            if len(row) != len(headers):
                raise ImportProblem(f"Row {total}: column count does not match the header.")
            event_id = row[indexes["event_id"]].strip()
            if event_id not in OUTCOMES:
                raise ImportProblem(f"Row {total}: only Windows Security event IDs 4624 and 4625 are supported.")
            canonical = {key: row[index] for key, index in indexes.items() if key != "event_id"}
            canonical.update(outcome=OUTCOMES[event_id], log_source="windows-security-preview")
            try:
                event = normalize(canonical)
            except ImportProblem as exc:
                raise ImportProblem(f"Row {total}: {exc}") from exc
            ids.add(event["id"])
            counts[event["outcome"]] += 1
            if len(samples) < PREVIEW_ROWS:
                samples.append(event)
    except csv.Error as exc:
        raise ImportProblem("Malformed CSV; no preview was produced.") from exc
    if not total:
        raise ImportProblem("CSV contains no events.")
    return {
        "preview_only": True,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "mapping": mapping,
        "ignored_columns": [column for column in headers if column not in mapping.values()],
        "row_count": total,
        "unique_event_count": len(ids),
        "outcome_counts": counts,
        "sample_events": samples,
    }


def _read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        return stream.read(limit + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", help="Local flattened Security-event CSV; not EVTX/XML")
    parser.add_argument("--mapping", required=True, help="Local explicit field-mapping JSON")
    args = parser.parse_args(argv)
    try:
        result = preview(_read_bounded(args.csv_file, MAX_BYTES), _read_bounded(args.mapping, MAX_MAPPING_BYTES))
    except OSError:
        print("Cannot read the local input files.", file=sys.stderr)
        return 2
    except ImportProblem as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
