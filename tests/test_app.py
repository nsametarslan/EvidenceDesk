import io
import json
from pathlib import Path
import pytest
from evidencedesk import create_app, storage


@pytest.fixture
def client(tmp_path):
    return create_app(tmp_path, testing=True).test_client()


def headers(client):
    client.get('/')
    with client.session_transaction() as session:
        return {'X-CSRF-Token': session['csrf']}


def load(client):
    assert client.post('/api/demo', headers=headers(client)).status_code == 200
    return client.get('/api/workspace').json['findings'][0]['id']


def test_demo_dedup_and_evidence_provenance(client):
    identity = load(client)
    current = client.get('/api/workspace').json
    assert current['summary'] == dict(events=16, failures=11, findings=3, sources=5,
        first_seen='2026-10-07T08:00:00.000000Z', last_seen='2026-10-07T08:35:00.000000Z')
    repeated = client.post('/api/demo', headers=headers(client)).json
    assert repeated == dict(added=0, duplicates=16, repeated_file=True)
    evidence = client.get(f'/api/findings/{identity}').json['evidence']
    assert len(evidence) == 6
    assert all(len(e['source_files'][0]['hash']) == 64 for e in evidence)


def test_atomic_import_failure(client):
    load(client)
    data = b'timestamp,user,source_ip,host,outcome\n2026-10-07T09:00:00Z,x,203.0.113.2,lab,success\nbad,x,bad,lab,success\n'
    response = client.post('/api/import', headers=headers(client), data={'file': (io.BytesIO(data), 'a.csv')})
    assert response.status_code == 400
    assert client.get('/api/workspace').json['summary']['events'] == 16
    assert len(client.get('/api/workspace').json['imports']) == 1


def test_canonical_duplicates_across_different_source_files(client):
    load(client)
    source = Path(client.application.root_path)/'samples/authentication.csv'
    response = client.post('/api/import', headers=headers(client), data={'file': (io.BytesIO(source.read_bytes()+b'\n'), '../another.csv')})
    assert response.json['added'] == 0
    assert response.json['duplicates'] == 16
    current = client.get('/api/workspace').json
    assert current['imports'][0]['filename'] == 'another.csv'
    identity = current['findings'][0]['id']
    assert len(client.get(f'/api/findings/{identity}').json['evidence'][0]['source_files']) == 2


def test_case_notes_persist_with_safe_export(client):
    identity = load(client)
    note = "<script>alert(1)</script>\n'; DROP TABLE events;--"
    response = client.post(f'/api/findings/{identity}', headers=headers(client), json={'status': 'reviewing', 'note': note})
    assert response.status_code == 200
    assert client.get(f'/api/findings/{identity}').json['finding']['note'] == note
    exported = client.get(f'/api/findings/{identity}/export')
    assert exported.mimetype == 'application/json'
    assert exported.headers['Content-Disposition'].startswith('attachment;')
    assert json.loads(exported.data)['finding']['status'] == 'reviewing'
    assert client.get('/api/workspace').json['summary']['events'] == 16


@pytest.mark.parametrize('payload', [[], {'status': []}, {'status': [], 'note': ''},
    {'status': 'confirmed attack', 'note': ''}, {'status': 'new', 'note': 'x'*4001},
    {'status': 'new', 'note': '\x00'}])
def test_invalid_case_updates(client, payload):
    identity = load(client)
    assert client.post(f'/api/findings/{identity}', headers=headers(client), json=payload).status_code == 400


def test_csrf_origin_and_host_guard(client):
    assert client.post('/api/demo').status_code == 403
    assert client.post('/api/demo', headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    valid = headers(client)
    assert client.post('/api/demo', headers={**valid, 'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/api/demo', headers={**valid, 'Sec-Fetch-Site': 'cross-site'}).status_code == 403
    assert client.get('/', headers={'Host': 'evil.example'}).status_code == 400
    assert client.get('/api/workspace', base_url='http://127.0.0.1:8765').status_code == 200


def test_security_headers_and_missing_resources(client):
    response = client.get('/')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert "script-src 'self'" in response.headers['Content-Security-Policy']
    assert 'HttpOnly' in response.headers['Set-Cookie']
    assert 'SameSite=Strict' in response.headers['Set-Cookie']
    assert client.get('/api/findings/missing').status_code == 404
    assert client.get('/api/findings/missing/export').status_code == 404
    assert client.post('/api/import', headers=headers(client)).status_code == 400
    assert client.post('/api/demo', data=b'x'*(3*1024*1024), headers=headers(client)).status_code == 413


def test_note_survives_restart(tmp_path):
    client = create_app(tmp_path, testing=True).test_client()
    identity = load(client)
    client.post(f'/api/findings/{identity}', headers=headers(client), json={'status': 'dismissed', 'note': 'Synthetic training scenario; no response action.'})
    restarted = create_app(tmp_path, testing=True).test_client()
    assert restarted.get(f'/api/findings/{identity}').json['finding']['status'] == 'dismissed'


def test_workspace_capacity_is_atomic(client, monkeypatch):
    monkeypatch.setattr(storage, 'MAX_WORKSPACE_EVENTS', 2)
    assert client.post('/api/demo', headers=headers(client)).status_code == 400
    assert client.get('/api/workspace').json['summary']['events'] == 0
