"""Synthetic adversarial regression tests for the local-only threat model."""
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


@pytest.mark.parametrize('field', ['user', 'host', 'log_source'])
def test_surrogate_import_fails_atomically(client, field):
    event = dict(timestamp='2026-10-08T08:00:00Z', user='demo',
                 source_ip='203.0.113.1', host='lab', outcome='failure')
    good = json.dumps(event)
    event[field] = '\ud800'
    response = client.post('/api/import', headers=headers(client),
        data={'file': (io.BytesIO((good+'\n'+json.dumps(event)).encode()), 'bad.jsonl')})
    assert response.status_code == 400
    assert client.get('/api/workspace').json['summary']['events'] == 0
    assert client.get('/api/workspace').json['imports'] == []


@pytest.mark.parametrize('note', ['\ud800', '\udfff'])
def test_invalid_unicode_note_keeps_saved_review(client, note):
    identity = load(client)
    h = headers(client)
    assert client.post('/api/findings/'+identity, headers=h,
        json={'status':'reviewing','note':'Original review'}).status_code == 200
    assert client.post('/api/findings/'+identity, headers=h,
        json={'status':'dismissed','note':note}).status_code == 400
    saved = client.get('/api/findings/'+identity).json['finding']
    assert (saved['status'], saved['note']) == ('reviewing', 'Original review')


@pytest.mark.parametrize('body', [
    '['*2000+'0'+']'*2000,
    '{"status":"new","status":"dismissed","note":"x"}',
    '{"status":"new","note":"a","note":"b"}',
    '{broken}',
])
def test_malformed_case_json_has_controlled_error(client, body):
    identity = load(client)
    response = client.post('/api/findings/'+identity, headers=headers(client),
                           data=body, content_type='application/json')
    assert response.status_code == 400
    assert response.is_json and 'Traceback' not in response.get_data(as_text=True)
    assert client.get('/api/findings/'+identity).json['finding']['status'] == 'new'


def test_duplicate_jsonl_field_is_not_silently_overwritten(client):
    body = b'{"timestamp":"2026-10-08T08:00:00Z","user":"first","user":"last","source_ip":"203.0.113.1","host":"lab","outcome":"failure"}'
    response = client.post('/api/import', headers=headers(client),
        data={'file': (io.BytesIO(body), 'duplicate.jsonl')})
    assert response.status_code == 400
    assert client.get('/api/workspace').json['summary']['events'] == 0


def test_valid_multilingual_note_and_emoji_export(client):
    identity = load(client)
    note = 'İnceleme — Überprüfung — 確認 🔎'
    assert client.post('/api/findings/'+identity, headers=headers(client),
                      json={'status':'reviewing','note':note}).status_code == 200
    exported = client.get('/api/findings/'+identity+'/export')
    assert exported.json['finding']['note'] == note


def test_session_tampering_and_cross_session_token_fail_closed(client):
    h = headers(client)
    other = client.application.test_client()
    headers(other)
    assert other.post('/api/demo', headers=h).status_code == 403
    client.set_cookie('session', 'tampered-signature')
    assert client.post('/api/demo', headers=h).status_code == 403
    assert client.get('/api/workspace').json['summary']['events'] == 0


@pytest.mark.parametrize('path', [
    '/static/../../SECURITY.md', '/static/%2e%2e/%2e%2e/SECURITY.md',
    '/api/findings/%27%20OR%201=1--/export', '/api/findings/missing',
])
def test_unknown_or_traversal_resources_do_not_leak_files(client, path):
    response = client.get(path)
    assert response.status_code == 404
    assert 'Security model' not in response.get_data(as_text=True)
    assert 'sqlite3' not in response.get_data(as_text=True)


def test_sql_and_html_evidence_remain_inert_labels(client):
    event = dict(timestamp='2026-10-08T08:00:00Z',
                 user="'; DROP TABLE events;--", source_ip='203.0.113.1',
                 host='<img src=x onerror=alert(1)>', outcome='failure')
    response = client.post('/api/import', headers=headers(client),
        data={'file': (io.BytesIO(json.dumps(event).encode()), '../../attack.jsonl')})
    assert response.status_code == 200
    current = storage.workspace(client.application.config['DATABASE'])
    assert current['events'][0]['user'] == event['user']
    assert current['events'][0]['host'] == event['host']
    assert current['imports'][0]['filename'] == 'attack.jsonl'
    assert not (Path(client.application.config['DATABASE']).parent / 'attack.jsonl').exists()
    assert 'Access-Control-Allow-Origin' not in client.get('/api/workspace',
        headers={'Origin':'https://evil.example'}).headers


def test_deep_import_json_and_multipart_part_limit(client):
    h = headers(client)
    deep = ('['*2000+'0'+']'*2000).encode()
    assert client.post('/api/import', headers=h,
        data={'file':(io.BytesIO(deep),'deep.jsonl')}).status_code == 400
    files = {f'part{i}': (io.BytesIO(b'x'), 'a.csv') for i in range(9)}
    assert client.post('/api/import', headers=h, data=files).status_code == 413
    assert client.get('/api/workspace').json['summary']['events'] == 0


def test_database_failure_is_generic_without_sensitive_path(client, monkeypatch):
    def unavailable(_path):
        import sqlite3
        raise sqlite3.OperationalError('sensitive-user/private-directory/event-data')
    monkeypatch.setattr(storage, 'workspace', unavailable)
    response = client.get('/api/workspace')
    assert response.status_code == 503
    assert 'sensitive-user' not in response.get_data(as_text=True)
