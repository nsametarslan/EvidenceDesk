import json
import pytest
from evidencedesk.ingest import ImportProblem, MAX_BYTES, normalize, parse_upload


def row(**changes):
    return dict(timestamp="2026-10-07T08:00:00Z", user="demo", source_ip="203.0.113.1", host="lab", outcome="failure", **changes)


@pytest.mark.parametrize("changes", [
    {"timestamp": "2026-10-07T08:00:00"}, {"timestamp": "yesterday"},
    {"source_ip": "999.1.1.1"}, {"user": ""}, {"host": "x\x00y"},
    {"outcome": "unknown"}, {"user": "a"*161}, {"extra": "unmapped"},
    {"user": 42}, {"log_source": "x\ny"},
])
def test_invalid_event(changes):
    event = row(); event.update(changes)
    with pytest.raises(ImportProblem): normalize(event)


def test_timezone_and_equivalent_ipv6_are_canonical():
    a = row(); a.update(timestamp="2026-10-07T11:00:00+03:00", source_ip="2001:0db8::1")
    b = row(); b.update(source_ip="2001:db8::1")
    assert normalize(a) == normalize(b)


def test_microseconds_are_preserved():
    a = row(); b = row(); b["timestamp"] = "2026-10-07T08:00:00.000001Z"
    assert normalize(a)["id"] != normalize(b)["id"]


@pytest.mark.parametrize("data,name", [(b"", "a.csv"), (b"a"*(MAX_BYTES+1), "a.csv"), (b"\xff", "a.csv"),
    (b"{}", "a.txt"), (b"timestamp,user\n", "a.csv"),
    (b"timestamp,user,source_ip,host,outcome,user\n", "a.csv"),
    (b"{no}", "a.jsonl"), (b"[]", "a.jsonl"), (b"{}\n\n{}", "a.jsonl")], ids=['empty','oversize','encoding','extension','headers','duplicate-header','json','array','blank-line'])
def test_rejects_bad_files(data, name):
    with pytest.raises(ImportProblem): parse_upload(data, name)


def test_bom_jsonl():
    events = parse_upload(('\ufeff' + json.dumps(row())).encode(), 'sample.jsonl')
    assert len(events) == 1


def test_csv_extra_value_is_rejected():
    data = b'timestamp,user,source_ip,host,outcome\n2026-10-07T08:00:00Z,demo,203.0.113.1,lab,failure,extra\n'
    with pytest.raises(ImportProblem): parse_upload(data, 'a.csv')
