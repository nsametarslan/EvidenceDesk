import hashlib
import json

import pytest

from evidencedesk.ingest import MAX_BYTES, ImportProblem, normalize
from evidencedesk.windows_preview import MAX_MAPPING_BYTES, main, preview

MAPPING = dict(timestamp="TimeCreated", user="TargetUserName", source_ip="IpAddress", host="Computer", event_id="EventID")
HEADER = "TimeCreated,TargetUserName,IpAddress,Computer,EventID,SubjectUserName\n"
ROW = "2026-10-09T10:00:00+03:00,demo-user,192.0.2.10,demo-host,4625,ignored-subject\n"


def run(data=HEADER + ROW, mapping=MAPPING):
    return preview(data.encode(), json.dumps(mapping).encode())


def test_explicit_mapping_matches_canonical_normalization():
    result = run()
    assert result["preview_only"] is True
    assert result["source_sha256"] == hashlib.sha256((HEADER + ROW).encode()).hexdigest()
    expected = normalize(dict(timestamp="2026-10-09T07:00:00Z", user="demo-user", source_ip="192.0.2.10", host="demo-host", outcome="failure", log_source="windows-security-preview"))
    assert result["sample_events"] == [expected]
    assert result["ignored_columns"] == ["SubjectUserName"]
    assert "ignored-subject" not in json.dumps(result)


def test_duplicates_counts_and_bounded_sample():
    result = run(HEADER + ROW * 7 + ROW.replace("4625", "4624"))
    assert result["row_count"] == 8
    assert result["unique_event_count"] == 2
    assert result["outcome_counts"] == dict(success=1, failure=7)
    assert len(result["sample_events"]) == 5


@pytest.mark.parametrize("mapping", [None, [], {}, {**MAPPING, "extra": "x"}, {**MAPPING, "user": 3}, {**MAPPING, "user": ""}, {**MAPPING, "user": "Computer"}, {**MAPPING, "user": "Missing"}, {**MAPPING, "user": "bad\x00header"}])
def test_invalid_mapping_rejected(mapping):
    with pytest.raises(ImportProblem):
        run(mapping=mapping)


@pytest.mark.parametrize("data", ["", HEADER, HEADER + ROW.replace("4625", "4634"), HEADER + ROW.replace("192.0.2.10", "-"), HEADER + ROW.replace("+03:00", ""), HEADER + ROW.replace("demo-user", "bad\x00name"), HEADER + ROW + "short,row\n", HEADER + ROW + '\"unterminated', HEADER.replace("SubjectUserName", "Computer") + ROW, HEADER.replace("SubjectUserName", " Computer ") + ROW, HEADER + "\n"])
def test_invalid_or_late_invalid_row_rejected(data):
    with pytest.raises(ImportProblem):
        run(data)


@pytest.mark.parametrize("csv_data,mapping_data", [(b"\xff", json.dumps(MAPPING).encode()), (b"x" * (MAX_BYTES + 1), b"{}"), ((HEADER + ROW).encode(), b"x" * (MAX_MAPPING_BYTES + 1)), ((HEADER + ROW).encode(), b'{"user":"x","user":"y"}'), ((HEADER + ROW).encode(), b"[" * 2000)], ids=["invalid-utf8", "csv-too-large", "mapping-too-large", "duplicate-keys", "deep-json"])
def test_resource_and_encoding_limits(csv_data, mapping_data):
    with pytest.raises(ImportProblem):
        preview(csv_data, mapping_data)


def test_row_limit(monkeypatch):
    monkeypatch.setattr("evidencedesk.windows_preview.MAX_ROWS", 1)
    with pytest.raises(ImportProblem, match="limit"):
        run(HEADER + ROW * 2)


def test_cli_rejects_late_failure_without_stdout_or_database(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "events.csv").write_text(HEADER + ROW + ROW.replace("4625", "9999"))
    (tmp_path / "mapping.json").write_text(json.dumps(MAPPING))
    assert main(["events.csv", "--mapping", "mapping.json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Row 2" in captured.err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["events.csv", "mapping.json"]


def test_cli_success_and_missing_file(tmp_path, capsys):
    csv_path, mapping_path = tmp_path / "events.csv", tmp_path / "mapping.json"
    csv_path.write_text(HEADER + ROW)
    mapping_path.write_text(json.dumps(MAPPING))
    assert main([str(csv_path), "--mapping", str(mapping_path)]) == 0
    assert json.loads(capsys.readouterr().out)["row_count"] == 1
    assert main([str(tmp_path / "private-name.csv"), "--mapping", str(mapping_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-name" not in captured.err


def test_normalized_csv_roundtrip_preserves_all_rows():
    from evidencedesk.windows_preview import normalized_csv
    from evidencedesk.ingest import parse_upload
    data = (HEADER + ROW * 7 + ROW.replace("4625", "4624")).encode()
    output = normalized_csv(data, json.dumps(MAPPING).encode())
    events = parse_upload(output.encode(), "normalized.csv")
    assert len(events) == 8
    assert events[-1]["outcome"] == "success"
    assert events[0]["timestamp"] == "2026-10-09T07:00:00.000000Z"
    assert "ignored-subject" not in output


def test_normalized_cli_rejects_late_bad_row_without_output(tmp_path, capsys):
    csv_file = tmp_path / "events.csv"
    mapping = tmp_path / "mapping.json"
    csv_file.write_text(HEADER + ROW * 6 + ROW.replace("4625", "9999"))
    mapping.write_text(json.dumps(MAPPING))
    assert main([str(csv_file), "--mapping", str(mapping), "--normalized-csv"]) == 2
    assert capsys.readouterr().out == ""
    assert sorted(p.name for p in tmp_path.iterdir()) == ["events.csv", "mapping.json"]


def test_normalized_output_size_limit(monkeypatch):
    from evidencedesk.windows_preview import normalized_csv
    monkeypatch.setattr("evidencedesk.ingest.MAX_BYTES", 10)
    with pytest.raises(ImportProblem, match="2 MiB"):
        normalized_csv((HEADER + ROW).encode(), json.dumps(MAPPING).encode())


def test_cli_to_workspace_end_to_end(tmp_path):
    import io
    import subprocess
    import sys
    from evidencedesk import create_app
    source = tmp_path / "windows.csv"
    mapping = tmp_path / "mapping.json"
    # Five distinct failures followed by a success: real CLI, then web API.
    rows = [ROW.replace("10:00:00", f"10:0{i}:00") for i in range(5)]
    rows.append(ROW.replace("10:00:00", "10:05:00").replace("4625", "4624"))
    source.write_text(HEADER + "".join(rows), encoding="utf-8")
    mapping.write_text(json.dumps(MAPPING), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "evidencedesk.windows_preview",
        str(source), "--mapping", str(mapping), "--normalized-csv"], capture_output=True)
    assert result.returncode == 0, result.stderr
    client = create_app(tmp_path / "workspace", testing=True).test_client()
    client.get("/")
    with client.session_transaction() as session:
        headers = {"X-CSRF-Token": session["csrf"]}
    def upload():
        return client.post("/api/import", headers=headers,
            data={"file": (io.BytesIO(result.stdout), "normalized.csv")})
    assert upload().json["added"] == 6
    workspace = client.get("/api/workspace").json
    assert workspace["summary"]["events"] == 6
    finding = next(f for f in workspace["findings"] if f["rule"] == "success_after_failures")
    identity = finding["id"]
    assert client.post(f"/api/findings/{identity}", headers=headers,
        json={"status": "reviewing", "note": "Synthetic CSV handoff verified"}).status_code == 200
    report = client.get(f"/api/findings/{identity}/export").json
    assert report["finding"]["note"] == "Synthetic CSV handoff verified"
    assert upload().json["added"] == 0
    assert client.get("/api/workspace").json["summary"]["events"] == 6
