# Windows Security CSV mapping preview

A read-only CLI checks whether a **flattened Windows Security CSV** can represent
EvidenceDesk authentication events. It validates every row before returning a
maximum of five normalized sample events. It does not touch SQLite, import data,
collect live logs, parse EVTX/XML or change the web application's local-only boundary.

## Try it with synthetic data

Create `windows-demo.csv` locally:

```csv
TimeCreated,TargetUserName,IpAddress,Computer,EventID,SubjectUserName
2026-10-09T10:00:00+03:00,demo-user,192.0.2.10,demo-host,4625,ignored-subject
2026-10-09T10:01:00+03:00,demo-user,192.0.2.10,demo-host,4624,ignored-subject
```

Create `mapping.json` locally:

```json
{
  "timestamp": "TimeCreated",
  "user": "TargetUserName",
  "source_ip": "IpAddress",
  "host": "Computer",
  "event_id": "EventID"
}
```

From the repository root, with its existing environment installed:

```console
python -m evidencedesk.windows_preview windows-demo.csv --mapping mapping.json
```

The result reports 2 rows, 2 unique normalized events, one success and one failure.
The source SHA-256 identifies the original bytes; it does not prove authenticity.
The output is a preview report, **not an import file** or evidence-chain export.

## Explicit decisions and limits

- Mapping has exactly five required keys; source column names must be distinct.
  No guessed mappings or fallback from target account to subject account.
- Only event IDs **4624 (success)** and **4625 (failure)** are supported.
  Export only the relevant events beforehand; unsupported rows cause the entire
  preview to fail. There is no silent filtering or partial successful output.
- Timestamp needs an explicit ISO-8601 offset/UTC; IP must be valid. Windows
  exports containing `-` for unavailable IP cannot be represented by the current
  canonical schema and are rejected. Do not invent an IP or timezone.
- Use an export produced from the **Security** provider. The CSV alone cannot
  authenticate its origin. Column labels differ by exporter and must be inspected.
- A plain TargetUserName may collide between domains. For mixed-domain data,
  explicitly prepare a domain-qualified account column and map `user` to it.
  Domain, logon type, event record ID and other columns are not preserved in
  canonical sample events; their names are listed as ignored columns.
- Input limits: 2 MiB UTF-8 CSV, 20,000 events, 16 KiB mapping JSON. Duplicate
  headers/JSON keys, malformed rows and invalid canonical values are rejected.
- The CLI reads only the two supplied local paths, performs no network requests
  and writes no files. Its stdout may contain account/host/IP sample data; keep
  real exports and preview output private. Publish synthetic examples only.

Microsoft references: [4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
and [4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625).

This is a narrow preview, not a complete Windows log adapter or production SIEM.
