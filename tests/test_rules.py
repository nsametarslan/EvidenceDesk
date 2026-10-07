from datetime import datetime, timedelta, timezone
from evidencedesk.ingest import normalize
from evidencedesk.rules import detect


def events(count=5, spacing=60, **kwargs):
    start = datetime(2026, 10, 7, 8, tzinfo=timezone.utc)
    return [normalize(dict(timestamp=(start+timedelta(seconds=i*spacing)).isoformat(), user="demo", source_ip="203.0.113.1", host="lab", outcome="failure", **kwargs)) for i in range(count)]


def test_burst_boundary_and_outside_window():
    assert len(detect(events(spacing=150))) == 1  # exactly 10 minutes
    assert detect(events(spacing=151)) == []
    assert detect(events(count=4)) == []


def test_success_is_context_candidate():
    data = events()
    success = dict(data[-1]); success.update(timestamp="2026-10-07T08:15:00Z", outcome="success"); success.pop("id")
    data.append(normalize(success))
    findings = detect(data)
    assert {f['rule'] for f in findings} == {'failure_burst', 'success_after_failures'}
    assert len(next(f for f in findings if f['severity'] == 'high')['evidence']) == 6
    success['timestamp'] = "2026-10-07T08:15:01Z"
    assert len(detect(events()+[normalize(success)])) == 1


def test_success_resets_failure_episode():
    data = events(count=4)
    success = {k: v for k,v in data[-1].items() if k != 'id'}
    success.update(timestamp='2026-10-07T08:04:00Z', outcome='success')
    later = {k: v for k,v in data[-1].items() if k != 'id'}
    later['timestamp'] = '2026-10-07T08:05:00Z'
    assert detect(data+[normalize(success), normalize(later)]) == []


def test_distinct_accounts_and_host_scoping():
    data = events()
    for i, event in enumerate(data):
        event['user'] = f'demo.{i}'; event.pop('id'); data[i] = normalize(event)
    assert [f['rule'] for f in detect(data)] == ['multi_account_failures']
    data[-1]['host'] = 'another'; data[-1].pop('id'); data[-1] = normalize(data[-1])
    assert detect(data) == []


def test_order_is_deterministic_and_appending_preserves_existing_ids():
    data = events(count=10)
    first = {f['id'] for f in detect(data[:5])}
    assert detect(data) == detect(list(reversed(data)))
    assert first <= {f['id'] for f in detect(data)}
    assert len(detect(data)) == 2


def test_spray_window_boundary():
    data = events(spacing=300)
    for i, e in enumerate(data):
        e['user'] = f'u{i}'; e.pop('id'); data[i] = normalize(e)
    assert len(detect(data)) == 1
    data[-1]['timestamp'] = '2026-10-07T08:20:01.000000Z'
    assert detect(data) == []
