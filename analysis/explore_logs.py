#!/usr/bin/env python3
"""Read-only profile of the original logs. Prints facts only - no conclusions."""
import collections
import json
import re
from pathlib import Path

LOGS = Path("logs")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
ERR_RE = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*(\d+) (.*)$"
)
RID_RE = re.compile(r"request_id=([^,\s]+)")


def H(v):
    """Make any JSON value hashable while keeping its type visible."""
    return v if v is None or isinstance(v, (str, int, float, bool)) else repr(v)


def show(title, counter, limit=15):
    print(f"{title}:")
    for value, count in counter.most_common(limit):
        print(f"   {count:6d}  {value!r}")


def load_jsonl(path):
    valid, bad = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    raise ValueError("JSON but not an object")
                valid.append((n, obj, raw))
            except ValueError as exc:
                bad.append((n, str(exc)[:40], raw))
    return valid, bad


def profile_json(name, extra):
    valid, bad = load_jsonl(LOGS / name)
    print(f"\n===== {name} =====")
    print(f"total lines={len(valid) + len(bad)}  valid={len(valid)}  malformed={len(bad)}")
    for n, why, raw in bad[:10]:
        print(f"   malformed line {n}: {why} | {raw[:100]!r}")
    show("distinct key sets", collections.Counter(tuple(sorted(o)) for _, o, _ in valid))
    ids = collections.Counter(H(o.get("request_id")) for _, o, _ in valid)
    repeated = {k: v for k, v in ids.items() if k is not None and v > 1}
    print(f"records without request_id: {ids.get(None, 0)}")
    print(f"distinct request_id: {len([k for k in ids if k is not None])}")
    print(f"request_ids appearing more than once: {len(repeated)} "
          f"(extra records: {sum(v - 1 for v in repeated.values())})")
    raws = collections.Counter(raw for _, _, raw in valid)
    print(f"byte-identical duplicate lines (extra copies): "
          f"{sum(v - 1 for v in raws.values() if v > 1)}")
    stamps = [o.get("timestamp") for _, o, _ in valid]
    good = sorted(t for t in stamps if isinstance(t, str) and TS_RE.match(t))
    odd = [t for t in stamps if not (isinstance(t, str) and TS_RE.match(t))]
    print(f"timestamps not in expected format: {len(odd)} {odd[:3]!r}")
    if good:
        print(f"first / last valid timestamp: {good[0]}  ->  {good[-1]}")
    extra(valid)
    return valid


def numeric_summary(label, values):
    nums = [x for x in values if isinstance(x, (int, float)) and not isinstance(x, bool)]
    line = f"{label}: numeric={len(nums)} non-numeric={len(values) - len(nums)}"
    if nums:
        line += f" min={min(nums)} max={max(nums)}"
    print(line)


def access_extra(valid):
    show("status", collections.Counter(H(o.get("status")) for _, o, _ in valid))
    show("method", collections.Counter(H(o.get("method")) for _, o, _ in valid))
    show("path", collections.Counter(H(o.get("path")) for _, o, _ in valid), 20)
    ups = [str(o.get("upstream")) for _, o, _ in valid]
    print(f"upstream values containing a comma (retry attempts): {sum(',' in u for u in ups)}")
    show("upstream", collections.Counter(ups), 20)
    show("upstream_status", collections.Counter(str(o.get("upstream_status")) for _, o, _ in valid), 20)
    numeric_summary("request_time (seconds)", [o.get("request_time") for _, o, _ in valid])


def app_extra(valid):
    show("level", collections.Counter(H(o.get("level")) for _, o, _ in valid))
    show("event", collections.Counter(H(o.get("event")) for _, o, _ in valid))
    show("instance_id", collections.Counter(H(o.get("instance_id")) for _, o, _ in valid))
    show("status", collections.Counter(H(o.get("status")) for _, o, _ in valid))
    show("path", collections.Counter(H(o.get("path")) for _, o, _ in valid), 20)
    numeric_summary("duration_ms (milliseconds)", [o.get("duration_ms") for _, o, _ in valid])


def profile_error():
    lines = (LOGS / "error.log").read_text(encoding="utf-8", errors="replace").splitlines()
    ok, bad = [], []
    for n, line in enumerate(lines, 1):
        m = ERR_RE.match(line)
        (ok if m else bad).append((n, m, line))
    print("\n===== error.log =====")
    print(f"total lines={len(lines)}  matched pattern={len(ok)}  unmatched={len(bad)}")
    for n, _, line in bad[:10]:
        print(f"   unmatched line {n}: {line[:100]!r}")
    show("level", collections.Counter(m.group(2) for _, m, _ in ok))
    show("message type", collections.Counter(m.group(6).split(", request_id=")[0][:100] for _, m, _ in ok))
    stamps = sorted(m.group(1) for _, m, _ in ok)
    if stamps:
        print(f"first / last timestamp: {stamps[0]}  ->  {stamps[-1]}")
    rids = [RID_RE.search(line).group(1) if RID_RE.search(line) else None for _, _, line in ok]
    counted = collections.Counter(r for r in rids if r)
    repeated = {k: v for k, v in counted.items() if v > 1}
    print(f"lines without request_id: {rids.count(None)}")
    print(f"distinct request_id: {len(counted)}")
    print(f"request_ids appearing more than once: {len(repeated)} "
          f"(extra records: {sum(v - 1 for v in repeated.values())})")
    ups = collections.Counter(u for _, _, line in ok for u in re.findall(r'upstream: "http://([\d.]+:\d+)', line))
    show("upstream address", ups)
    return set(counted)


if __name__ == "__main__":
    acc = profile_json("access.log", access_extra)
    app = profile_json("application.log", app_extra)
    err_ids = profile_error()
    a = {o.get("request_id") for _, o, _ in acc} - {None}
    p = {o.get("request_id") for _, o, _ in app} - {None}
    print("\n===== request_id overlap between files =====")
    print(f"access={len(a)}  application={len(p)}  error={len(err_ids)}")
    print(f"in access AND application: {len(a & p)}")
    print(f"in access only: {len(a - p)}   in application only: {len(p - a)}")
    print(f"error ids also in access: {len(err_ids & a)}   also in application: {len(err_ids & p)}")
