# Local security review — 8 October 2026

Reviewed starting commit: `b1cb17aedb16d8ab7be9e2c285b5b9e0ea07ebfe` on `main`.
All 25 tracked files were compared with the live Git tree; the only local byte difference was CSS line endings. All application Python modules, the template and JavaScript were reviewed. This is a scoped code review and synthetic regression exercise, not an independent penetration test or security certification.

## Threat model

Supported use remains one trusted user, loopback HTTP, no shared service. Untrusted exported event files and web pages visited by that user are relevant inputs. The CLI binds to `127.0.0.1`; there is no authentication, tenant separation or internet deployment permission. Browser sessions protect writes from other sites; they do not establish user identity or isolate local processes.

## Findings and changes

| Finding | Reproduction before the patch | Resolution | Local impact |
| --- | --- | --- | --- |
| ED-01: invalid Unicode text | JSONL `user` containing escaped `\ud800`, or a case note with a lone surrogate, raised `UnicodeEncodeError` rather than a validation response | Reject surrogate code points in canonical text and notes; preserve valid multilingual text and emoji | Malformed input could fail a request. No persistent corruption or authentication bypass was demonstrated |
| ED-02: exceptional case JSON | An authorised case request containing 2,000 nested arrays raised `RecursionError` | Catch malformed/deep JSON at the case input boundary and return a generic 400 response | Request availability / predictable error handling |
| ED-03: ambiguous JSON fields | A JSONL event with two `user` keys returned 200, silently using the last value | Reject repeated object keys in both JSONL imports and case updates | Evidence interpretation ambiguity; no privilege escalation demonstrated |
| ED-04: vulnerable development dependency | Exact-version pip-audit flagged pytest 8.4.2 under CVE-2025-71176 / GHSA-6w46-j5rx-g56g (duplicate advisory rows, **one unique vulnerability**) | Tested pytest 9.0.3; updated tested requirements and dev range to `>=9.0.3,<10` | Advisory concerns UNIX temporary-directory handling in the test tool. It is not a Flask/Waitress runtime flaw and was not exploited on this Windows host |

CSRF comparison also rejects non-ASCII supplied tokens before constant-time string comparison. Import validation still completes before any database transaction. Invalid note updates preserve the original saved review.

## Controls reviewed

| Area / OWASP Top 10:2025 mapping | Evidence and limits |
| --- | --- |
| Authentication, authorization, IDOR — A01/A07 | Deliberately absent user accounts and roles. Finding IDs locate evidence, not access grants. Unknown IDs return 404; there is no tenant model to claim protected. Anyone able to reach the local endpoint can read the workspace. Do not share or expose it |
| Host, origin, CSRF, cookies, configuration — A02/A06 | Host allowlist; random session-bound CSRF; same-origin and Fetch Metadata checks on writes; signed HttpOnly/SameSite=Strict cookie; no CORS grants. Secure cookie / HSTS would require HTTPS and are not enabled for loopback HTTP. Session tampering and cross-session token rejection tested. No debug server or proxy trust added |
| XSS / SQL injection — A05 | Imported values and notes use DOM `textContent` / textarea value, with restrictive CSP. SQLite queries use bound parameters; SQL-looking usernames remain data. JSON exports are attachments with `nosniff`, not HTML or spreadsheet files. Python tests do not execute JavaScript; the XSS conclusion also depends on manual sink review |
| SSRF / path traversal / uploads — A01/A05/A06 | No evidence-driven URL fetch, shell invocation, file execution or path choice. Uploaded files are parsed in memory; originals are not stored. File names become stripped labels. Sample path is fixed. Static traversal and unknown resources tested. Extension allowlist is backed by actual CSV/JSONL schema validation, not MIME trust |
| Supply chain / secrets — A03 | Exact 14-package runtime-and-test manifest scanned against PyPI advisories. No CI workflows are present. Heuristic file scan and manual synthetic sample review supplement dependency scanning. Package artifacts are not hash-locked; registry/build tooling and upstream compromise remain outside this check |
| Crypto / sensitive data — A04 | Random session secret and SHA-256 fingerprints; no embedded credentials identified. SQLite and exports are unencrypted. File hashes identify bytes, not source authenticity. Filesystem access, disk encryption and retention remain the operator's responsibility |
| Integrity — A08 | Atomic import, canonical deduplication, duplicate-key rejection, provenance and historical review snapshots. Misleading authorised logs and database tampering remain possible; no chain-of-custody guarantee |
| Logging — A09 | Database error responses are generic; logs contain exception class rather than database paths/data. No tamper-evident audit trail or security alerting is implemented. This is a local review tool, not a monitored hosted service |
| Exceptional conditions / resources — A10 | 2 MiB upload, 20,000 events/file, 50,000 unique workspace events, bounded fields, 8 multipart parts; recursion/invalid text failures reject safely. Repeated distinct files and saved snapshots still grow disk usage. No OS sandbox, request-rate limit, performance stress certification or hostile-file isolation claimed |

## Executed checks on 8 October

Windows / Python 3.12. Tests use temporary databases and synthetic inputs only.

* Baseline: **45 passed in 0.85s**, before changes, pytest 8.4.2. This was a new execution today; the 7 October history remains separate.
* After fixes and pytest 9.0.3 upgrade: **64 passed in 0.86s** (45 existing + 19 new parametrized cases), zero failures.
* `pip check`: no broken requirements.
* Bandit 1.9.4, all five application Python modules: no reported issues; no skipped checks or `nosec` suppressions. It does not analyse browser JavaScript, prove authorization or detect every flaw.
* pip-audit 2.10.1 against the complete exact-version 14-package manifest: after upgrade, **no known vulnerabilities reported**. `--no-deps --disable-pip` audited every listed package; ranges, build tools and packages outside that manifest are not a fully locked supply chain.
* New tests cover invalid Unicode, atomic rollback, saved-note preservation, duplicate JSON keys, excessive nesting, valid international text, session tampering, cross-session CSRF, traversal, SQL/HTML-shaped evidence, multipart limits and generic database errors.
* Actual patched-app browser exercise: demo loaded, candidate selected, multilingual HTML/SQL-shaped note saved as text, and JSON attachment downloaded and inspected (six evidence records, saved status and note). No JavaScript execution or database loss was observed during this limited exercise; it is not comprehensive browser fuzzing.
* Publication heuristic scan after review documentation: **25 text files scanned, zero items requiring review**. This scanner has limited patterns and does not prove that no secret exists in repository history or images.

No critical exploitable issue was established within this scoped local review. This statement does **not** make EvidenceDesk safe for network hosting. Residual boundaries above remain mandatory.

## Primary references

* [OWASP Top 10:2025](https://top10.owasp.org/2025/)
* [A10:2025 — exceptional conditions](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
* [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [OWASP file-upload guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
* [Flask security guidance](https://flask.palletsprojects.com/en/stable/web-security/)
* [Python JSON input considerations](https://docs.python.org/3/library/json.html)
* [Reviewed pytest advisory](https://github.com/advisories/GHSA-6w46-j5rx-g56g)
* [pytest 9.0.3 release](https://github.com/pytest-dev/pytest/releases/tag/9.0.3)
