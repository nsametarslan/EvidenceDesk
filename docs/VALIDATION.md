# v0.1 validation

Validation date: 7 October 2026. Environment: Windows, Python 3.12, Flask 3.1.3, Waitress 3.0.2; exact runtime dependencies in `requirements-tested.txt`.

* Editable installation through the documented `pip install -e ".[dev]"` completed successfully.
* `python -m pytest -q`: **44 tests passed**. Coverage includes input rejection, timezone normalisation, inclusive rule windows, deterministic output, benign non-matches, host scoping, deduplication, atomic import, persistence after app restart, historical review snapshots, capacity limits, request size, CSRF, origins, host validation and response headers. No test-coverage percentage is claimed.
* Actual browser: demo loaded 16 events, 11 failures, 5 source addresses and 3 candidates; the highest-priority candidate showed six supporting events.
* Actual browser: search by source address and filter by reviewing status returned the expected candidate; a synthetic investigation note was saved and visible after server restart.
* Actual browser: malformed CSV was rejected with an event-level error and no change to the event count.
* Actual browser: exported JSON downloaded successfully. Its content contained six evidence records, reviewing status and source fingerprints.
* Screenshots are captured from the running app with labelled synthetic data. They are not generated UI mockups.

The pre-publication heuristic scan and manual file review are recorded separately in the portfolio build report. They do not establish absence of all secrets or vulnerabilities. No real incident data was used, no production deployment tested and no performance or detection-accuracy claim is made.
