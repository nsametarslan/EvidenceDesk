# Mapping preview validation — 9 October 2026

Base: main commit `3d18aa2b972fcb291f6d4c41f25ee5fe4f4f2dcb`.
Environment: Windows / Python 3.12, existing tested dependency environment.

- Fresh baseline on that checkout: **64 passed in 1.32s**.
- After the read-only mapping preview and adversarial tests: **94 passed in 0.96s**.
- Bandit scanned all application Python modules including the new preview:
  no reported issues, no added suppression.
- Publication heuristic scanner: 28 text files at the time of the first scan,
  zero items requiring review. It is not a guarantee about secrets or history.

The 30 additional cases cover canonical normalization, outcome mapping, duplicate
counting, bounded output, invalid/ambiguous mappings, duplicate headers/JSON keys,
unsupported event IDs, missing IP/timezone, control characters, late invalid rows,
encoding/size/row limits, nested JSON, no partial stdout, no database creation
and generic file-read errors. Oversized pytest parameter IDs initially caused
Windows fixture setup errors; explicit short case IDs resolved them before the
successful full run. No application boundary was relaxed to make tests pass.

No new dependency or web route was added. Preview output can contain sensitive
account/host/IP samples and must remain private for real exports. Missing IPs,
domain ambiguity and lost provider-specific fields are documented limitations.
No claim is made about native EVTX parsing, production log coverage, internet
hosting, detection accuracy or source authenticity. Existing local-only security
requirements in SECURITY.md still apply.

Reproduce from the repository root:

```console
python -m pytest -q
python -m bandit -r evidencedesk -q
python scripts/scan_secrets.py
```

Bandit is a separate review tool, not a new runtime dependency. Older validation
results in VALIDATION.md retain their original dates.
