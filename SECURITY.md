# Security model

EvidenceDesk v0.1 is a single-user offline evidence workspace. The supported deployment is a loopback-only process on a trusted user's computer. It is not a hosted service or production monitoring system.

## Data and boundaries

Only import logs you are authorised to process. Usernames, IP addresses, hostnames and case notes may be sensitive. The app stores canonical events, file fingerprints, file-name labels, provenance links and saved review snapshots in a local SQLite database. It does not retain uploaded original files. It performs no remote lookup, analytics, telemetry, scanning or automatic response.

The database and exported JSON reports are unencrypted. Restrict filesystem permissions, use appropriate disk encryption and follow your organisation's retention policy. The app has no user authentication, role separation, tenant isolation or tamper-evident audit log. A content hash identifies bytes; it does not prove source authenticity or chain of custody.

## Implemented controls

* Loopback binding through the CLI; allowlisted HTTP host names.
* Session-bound random CSRF token and same-origin checks for changes; no permissive CORS.
* HTTP-only, SameSite=Strict cookie. Secure-cookie mode is not used because the supported endpoint is local HTTP.
* Restrictive CSP, no inline scripts, no external resources, no iframe embedding and no MIME sniffing.
* Text-only rendering for imported values and notes; no untrusted HTML interpolation.
* Parameterised SQLite statements and transactional ingestion.
* Upload, event-count, workspace-count and field-length limits.
* File names are labels, never filesystem paths. No file execution, shell command or URL fetch is derived from evidence.
* JSON attachment export avoids executable HTML and spreadsheet formula interpretation. Treat the exported content as untrusted if converting it to another format.

## Residual risks

Same-user local processes may bypass browser protections. A user can deliberately supply misleading logs. Resource limits are application limits, not OS isolation; do not use hostile inputs without additional containment. Correlation can miss attacks or flag benign behaviour. No production validation or formal security audit is claimed. SQLite snapshots preserve review context but are editable by anyone who can modify the database.

Do not expose this app with a reverse proxy, tunnel or `0.0.0.0`. Multi-user hosting requires a different threat model, authentication, TLS, access control, logging and independent review.

If reporting an issue publicly, include a minimal **synthetic** reproduction. Never attach credentials or real customer/event data to a GitHub issue.
