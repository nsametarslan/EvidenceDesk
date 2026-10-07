"""Deterministic candidates, not verdicts. No network lookups or ML scoring."""
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
import hashlib

RULES = {
    "failure_burst": ("Repeated authentication failures", "medium", "5 failures for one user, IP and host within 10 minutes.", "A stale saved password or a mistyped password can cause this pattern."),
    "success_after_failures": ("Success after a failure burst", "high", "Success follows at least 5 failures for the same user, IP and host within 15 minutes.", "A legitimate user may have corrected their password. Verify context before escalation."),
    "multi_account_failures": ("Multi-account failure pattern", "medium", "One IP reaches 5 distinct users on one host within 20 minutes.", "Shared egress, a broken identity integration or a test can resemble password spraying."),
}


def detect(events):
    ordered = sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    windows = defaultdict(deque)
    bursts = defaultdict(deque)
    spray_windows = defaultdict(deque)
    spray_counts = defaultdict(Counter)
    # Non-overlapping evidence episodes bound output and keep finding IDs stable
    # when later imports append events. Late data can create another candidate.
    findings = []

    def emit(rule, evidence):
        title, severity, description, alternative = RULES[rule]
        ids = sorted(e["id"] for e in evidence)
        identity = hashlib.sha256((rule + ":" + ":".join(ids)).encode()).hexdigest()
        findings.append(dict(id=identity, rule=rule, title=title, severity=severity,
                             description=description, alternative=alternative,
                             evidence=ids, first_seen=min(e["timestamp"] for e in evidence),
                             last_seen=max(e["timestamp"] for e in evidence),
                             user=evidence[-1]["user"] if rule != "multi_account_failures" else f"{len({e['user'] for e in evidence})} accounts",
                             source_ip=evidence[-1]["source_ip"], host=evidence[-1]["host"]))

    for event in ordered:
        now = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        key = (event["user"], event["source_ip"], event["host"])
        window = windows[key]
        while window and now - window[0][0] > timedelta(minutes=15):
            window.popleft()
        if event["outcome"] == "failure":
            window.append((now, event))
            while len(window) > 5:
                window.popleft()
            burst = bursts[key]
            while burst and now - burst[0][0] > timedelta(minutes=10):
                burst.popleft()
            burst.append((now, event))
            if len(burst) >= 5:
                emit("failure_burst", [e for _, e in burst])
                burst.clear()
            spray_key = (event["source_ip"], event["host"])
            ip_window = spray_windows[spray_key]
            counts = spray_counts[spray_key]
            while ip_window and now - ip_window[0][0] > timedelta(minutes=20):
                _, expired = ip_window.popleft()
                counts[expired["user"]] -= 1
                if counts[expired["user"]] == 0:
                    del counts[expired["user"]]
            ip_window.append((now, event))
            counts[event["user"]] += 1
            if len(counts) >= 5:
                # Keep one event per account in the exported evidence.
                representatives = {e["user"]: e for _, e in ip_window}
                emit("multi_account_failures", list(representatives.values()))
                ip_window.clear()
                counts.clear()
        else:
            if len(window) >= 5:
                emit("success_after_failures", [e for _, e in list(window)[-5:]] + [event])
            window.clear()
            bursts[key].clear()
    return sorted(findings, key=lambda f: (f["severity"] != "high", f["last_seen"], f["id"]))
