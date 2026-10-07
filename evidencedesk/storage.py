"""SQLite ownership and transactions. No imported value becomes SQL syntax."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .ingest import ImportProblem, MAX_ROWS
from .rules import detect

MAX_WORKSPACE_EVENTS = 50_000


@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, user TEXT NOT NULL,
            source_ip TEXT NOT NULL, host TEXT NOT NULL, outcome TEXT NOT NULL,
            log_source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS imports (
            hash TEXT PRIMARY KEY, filename TEXT NOT NULL, imported_at TEXT NOT NULL,
            rows INTEGER NOT NULL, added INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS provenance (
            event_id TEXT REFERENCES events(id), import_hash TEXT REFERENCES imports(hash),
            PRIMARY KEY(event_id, import_hash));
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'new',
            note TEXT NOT NULL DEFAULT '', updated_at TEXT, snapshot TEXT);
        CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
        """)
        if 'snapshot' not in {r[1] for r in db.execute('PRAGMA table_info(cases)')}:
            db.execute('ALTER TABLE cases ADD COLUMN snapshot TEXT')


def import_events(path, events, data, filename):
    fingerprint = hashlib.sha256(data).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    # Treat the supplied name as a label, never as a path.
    safe_name = filename.replace("\\", "/").split("/")[-1][:120]
    safe_name = "".join(c for c in safe_name if ord(c) >= 32 and ord(c) != 127)
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM imports WHERE hash=?", (fingerprint,)).fetchone():
            return dict(added=0, duplicates=len(events), repeated_file=True)
        existing = {r[0] for r in db.execute("SELECT id FROM events")}
        new_ids = {e["id"] for e in events} - existing
        if len(existing) + len(new_ids) > MAX_WORKSPACE_EVENTS or len(events) > MAX_ROWS:
            raise ImportProblem("Workspace limit: 50,000 unique events. Use a new local data directory.")
        db.execute("INSERT INTO imports VALUES (?,?,?,?,?)", (fingerprint, safe_name, timestamp, len(events), len(new_ids)))
        for event in events:
            db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)", tuple(event[k] for k in ("id", "timestamp", "user", "source_ip", "host", "outcome", "log_source")))
            db.execute("INSERT OR IGNORE INTO provenance VALUES (?,?)", (event["id"], fingerprint))
        return dict(added=len(new_ids), duplicates=len(events)-len(new_ids), repeated_file=False)


def workspace(path):
    with connect(path) as db:
        events = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY timestamp,id")]
        cases = {r["id"]: dict(r) for r in db.execute("SELECT * FROM cases")}
        imports = [dict(r) for r in db.execute("SELECT * FROM imports ORDER BY imported_at DESC")]
    findings = detect(events)
    for finding in findings:
        case = cases.get(finding["id"], dict(status="new", note="", updated_at=None))
        finding.update({k: case[k] for k in ('status', 'note', 'updated_at')})
        finding['historical'] = False
    current_ids = {f['id'] for f in findings}
    for identity, case in cases.items():
        if identity not in current_ids and case['snapshot']:
            previous = json.loads(case['snapshot'])['finding']
            previous.update({k: case[k] for k in ('status', 'note', 'updated_at')})
            previous['historical'] = True
            findings.append(previous)
    return dict(events=events, findings=findings, imports=imports)


def detail(path, identity):
    current = workspace(path)
    finding = next((f for f in current["findings"] if f["id"] == identity), None)
    if finding is None:
        return None
    if finding['historical']:
        with connect(path) as db:
            snapshot = json.loads(db.execute('SELECT snapshot FROM cases WHERE id=?', (identity,)).fetchone()[0])
        snapshot['finding'] = finding
        return snapshot
    evidence_ids = set(finding['evidence'])
    evidence = [e for e in current["events"] if e["id"] in evidence_ids]
    with connect(path) as db:
        for event in evidence:
            event["source_files"] = [dict(r) for r in db.execute("SELECT i.hash,i.filename FROM imports i JOIN provenance p ON i.hash=p.import_hash WHERE p.event_id=? ORDER BY i.hash", (event["id"],))]
    return dict(finding=finding, evidence=evidence, disclaimer="Heuristic candidate. Human review required. Hashes are content fingerprints, not proof of log authenticity.")


def save_case(path, identity, status, note):
    snapshot = detail(path, identity)
    with connect(path) as db:
        db.execute("INSERT INTO cases (id,status,note,updated_at,snapshot) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,note=excluded.note,updated_at=excluded.updated_at,snapshot=excluded.snapshot", (identity, status, note, datetime.now(timezone.utc).isoformat(), json.dumps(snapshot)))
