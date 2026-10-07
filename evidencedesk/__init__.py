"""EvidenceDesk application factory; local single-user threat model."""
import hmac
import json
import secrets
import sqlite3
from pathlib import Path
from flask import Flask, abort, jsonify, render_template, request, session, Response
from werkzeug.exceptions import HTTPException
from . import storage
from .ingest import ImportProblem, MAX_BYTES, parse_upload


def create_app(data_dir=None, testing=False):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), TESTING=testing,
                      MAX_CONTENT_LENGTH=MAX_BYTES+64*1024, MAX_FORM_PARTS=8,
                      MAX_FORM_MEMORY_SIZE=16*1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      TRUSTED_HOSTS=["127.0.0.1", "localhost", "[::1]"])
    directory = Path(data_dir) if data_dir else Path.cwd() / "instance"
    path = directory / "evidencedesk.sqlite3"
    storage.initialize(path)
    app.config["DATABASE"] = path

    @app.before_request
    def guard():
        if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            abort(413, description="Request is too large. File imports are limited to 2 MiB.")
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                abort(403, description="Cross-origin changes are not allowed.")
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                abort(403, description="Cross-site changes are not allowed.")
            expected = session.get("csrf", "")
            given = request.headers.get("X-CSRF-Token", "")
            if not expected or not hmac.compare_digest(expected.encode(), given.encode()):
                abort(403, description="Refresh the workspace and retry; CSRF validation failed.")

    @app.after_request
    def headers(response):
        response.headers.update({"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                                 "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                 "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.description), exc.code

    @app.errorhandler(ImportProblem)
    def import_error(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(sqlite3.Error)
    def database_error(exc):
        app.logger.error("Local database operation failed: %s", type(exc).__name__)
        return jsonify(error="The local database is busy or unavailable. Retry after checking the data directory."), 503

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_hex(32))
        return render_template("index.html", csrf=session["csrf"])

    @app.get("/api/workspace")
    def get_workspace():
        current = storage.workspace(path)
        events = current.pop("events")
        current["summary"] = dict(events=len(events), failures=sum(e["outcome"] == "failure" for e in events),
                                  sources=len({e["source_ip"] for e in events}), findings=len(current["findings"]),
                                  first_seen=events[0]["timestamp"] if events else None,
                                  last_seen=events[-1]["timestamp"] if events else None)
        return jsonify(current)

    def accept(data, filename):
        events = parse_upload(data, filename)
        return jsonify(storage.import_events(path, events, data, filename))

    @app.post("/api/import")
    def upload():
        file = request.files.get("file")
        if not file or not file.filename:
            raise ImportProblem("Select a CSV or JSONL file.")
        return accept(file.stream.read(MAX_BYTES+1), file.filename)

    @app.post("/api/demo")
    def demo():
        sample = Path(app.root_path) / "samples" / "authentication.csv"
        return accept(sample.read_bytes(), sample.name)

    @app.get("/api/findings/<identity>")
    def finding(identity):
        result = storage.detail(path, identity)
        if result is None:
            abort(404, description="Finding not found in the current evidence set.")
        return jsonify(result)

    @app.post("/api/findings/<identity>")
    def update(identity):
        if storage.detail(path, identity) is None:
            abort(404, description="Finding not found.")
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {"status", "note"}:
            abort(400, description="Provide status and note.")
        status, note = payload["status"], payload["note"]
        if not isinstance(status, str) or status not in {"new", "reviewing", "dismissed", "escalated"}:
            abort(400, description="Unknown case status.")
        if not isinstance(note, str) or len(note) > 4000 or any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 for c in note):
            abort(400, description="Notes must be text, at most 4,000 characters, without control characters.")
        storage.save_case(path, identity, status, note)
        return jsonify(saved=True)

    @app.get("/api/findings/<identity>/export")
    def export(identity):
        result = storage.detail(path, identity)
        if result is None:
            abort(404, description="Finding not found.")
        # JSON avoids spreadsheet formula execution and retains full fingerprints.
        return Response(json.dumps(result, indent=2, ensure_ascii=False), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="evidencedesk-{result["finding"]["id"][:12]}.json"'})

    @app.get("/sample.csv")
    def download_sample():
        data = (Path(app.root_path) / "samples" / "authentication.csv").read_bytes()
        return Response(data, mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="synthetic-authentication.csv"'})

    return app
