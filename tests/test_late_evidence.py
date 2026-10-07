import io
import json
from evidencedesk import create_app
from test_app import headers, load


def test_late_evidence_preserves_saved_review_snapshot(tmp_path):
    client = create_app(tmp_path, testing=True).test_client()
    identity = load(client)
    client.post(f'/api/findings/{identity}', headers=headers(client), json={'status': 'reviewing', 'note': 'Keep this original review.'})
    late = dict(timestamp='2026-10-07T08:04:30Z', user='demo.alex', source_ip='203.0.113.24', host='lab-gateway', outcome='failure', log_source='late-synthetic-demo')
    response = client.post('/api/import', headers=headers(client), data={'file': (io.BytesIO(json.dumps(late).encode()), 'late.jsonl')})
    assert response.status_code == 200
    original = client.get(f'/api/findings/{identity}').json
    assert original['finding']['historical'] is True
    assert original['finding']['note'] == 'Keep this original review.'
    assert len(original['evidence']) == 6
    assert any(f['id'] == identity for f in client.get('/api/workspace').json['findings'])
