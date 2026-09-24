#!/usr/bin/env python3
"""Answers log_analysis.md Q1-Q9 from the ORIGINAL logs (read-only)."""
import collections
import csv
import json
import math
import re
import statistics
from pathlib import Path

LOGS = Path("logs")
OUT = Path("analysis/output")
OUT.mkdir(parents=True, exist_ok=True)
ERR_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*(\d+) (.*)$")
RID_RE = re.compile(r"request_id=([^,\s]+)")
UP_RE = re.compile(r'upstream: "http://([\d.]+:\d+)')


def h(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def read_jsonl(name):
    good, bad = [], []
    text = (LOGS / name).read_text(encoding="utf-8", errors="replace")
    for n, line in enumerate(text.splitlines(), 1):
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("not an object")
            good.append((n, obj, line))
        except ValueError:
            bad.append((n, line))
    return good, bad


def dedupe(records, keyfn):
    first, kept, dups = {}, [], []
    for n, obj, raw in records:
        key = keyfn(obj)
        if key in first:
            dups.append((n, raw == first[key]))
        else:
            first[key] = raw
            kept.append(obj)
    return kept, dups


def nearest_rank(vals, p):
    return vals[max(1, math.ceil(p / 100 * len(vals))) - 1]


def linear(vals, p):
    pos = (len(vals) - 1) * p / 100
    lo, hi = math.floor(pos), math.ceil(pos)
    return vals[lo] + (vals[hi] - vals[lo]) * (pos - lo)


def final_up(o):
    return o["upstream"].split(",")[-1].strip()


def main():
    acc_good, acc_bad = read_jsonl("access.log")
    app_good, app_bad = read_jsonl("application.log")
    acc, acc_dups = dedupe(acc_good, lambda o: o.get("request_id"))
    app, app_dups = dedupe(app_good, lambda o: (o.get("request_id"), o.get("event")))

    err_text = (LOGS / "error.log").read_text(encoding="utf-8", errors="replace").splitlines()
    err, err_other = [], []
    for n, line in enumerate(err_text, 1):
        m = ERR_RE.match(line)
        if not m:
            err_other.append((n, line))
            continue
        msg = m.group(6)
        rid, up = RID_RE.search(msg), UP_RE.search(msg)
        kind = "refused" if "Connection refused" in msg else "timeout" if "timed out" in msg else "other"
        err.append({"ts": m.group(1), "minute": m.group(1).replace("/", "-").replace(" ", "T")[:16],
                    "rid": rid.group(1) if rid else None, "up": up.group(1) if up else None,
                    "kind": kind, "raw": line})
    err_by_id = {e["rid"]: e for e in err}
    app_http = {o["request_id"]: o for o in app if o.get("event") == "http_request"}

    h("Q1  UTC interval, valid / malformed / duplicate lines")
    for name, good, bad, dups in (("access.log", acc_good, acc_bad, acc_dups),
                                  ("application.log", app_good, app_bad, app_dups)):
        stamps = sorted(o["timestamp"] for _, o, _ in good)
        same = sum(1 for _, identical in dups if identical)
        print(f"{name}: total={len(good) + len(bad)} valid={len(good)} malformed={len(bad)} "
              f"duplicate_extra={len(dups)} (byte-identical={same})  {stamps[0]} -> {stamps[-1]}")
        for n, line in bad:
            print(f"    malformed line {n}: {line[:90]!r}")
    stamps = sorted(e["ts"] for e in err)
    print(f"error.log: total={len(err_text)} request_errors={len(err)} other_lines={len(err_other)} "
          f"duplicate_request_ids={len(err) - len({e['rid'] for e in err})}  {stamps[0]} -> {stamps[-1]}")
    for n, line in err_other:
        print(f"    non-request line {n}: {line[:90]!r}")
    per_id = collections.Counter(o["request_id"] for o in app)
    print(f"application.log: {sum(1 for c in per_id.values() if c > 1)} request_ids carry 2 different "
          f"events (http_request + dependency_error) - NOT duplicates")

    h("Q2  distinct client requests")
    print(f"distinct client requests (access.log deduplicated by request_id) = {len(acc)}")
    print(f"excluded: {len(acc_bad)} malformed line(s), {len(acc_dups)} duplicate record(s)")
    print(f"requests listing several upstream attempts (counted once): "
          f"{sum(1 for o in acc if ',' in o['upstream'])}")

    h("Q3  final client status counts and error rate")
    total = len(acc)
    status = collections.Counter(o["status"] for o in acc)
    for s, c in sorted(status.items()):
        print(f"  {s}: {c:4d}  {c / total * 100:5.2f}%")
    e5 = sum(c for s, c in status.items() if s >= 500)
    e4 = sum(c for s, c in status.items() if 400 <= s < 500)
    probe = sum(1 for o in acc if o["status"] == 404 and o["path"] == "/missing")
    print(f"denominator = {total} distinct client requests")
    print(f"5xx rate = {e5}/{total} = {e5 / total * 100:.2f}%")
    print(f"4xx = {e4} (of which {probe} are the /missing probe)")
    print(f"4xx+5xx rate = {e4 + e5}/{total} = {(e4 + e5) / total * 100:.2f}%")

    h("Q4  failures by path, minute and backend")
    fail = [o for o in acc if o["status"] >= 500]
    print("5xx by (path, status):")
    for (p, s), c in sorted(collections.Counter((o["path"], o["status"]) for o in fail).items(), key=str):
        print(f"   {p:10s} {s}  {c}")
    per_min = collections.defaultdict(collections.Counter)
    for o in fail:
        per_min[o["timestamp"][:16]][o["status"]] += 1
    print("5xx per minute (UTC)      502  503  504")
    for m in sorted(per_min):
        c = per_min[m]
        print(f"   {m}   {c[502]:4d} {c[503]:4d} {c[504]:4d}")
    ipmap = collections.Counter((final_up(o), app_http[o["request_id"]]["instance_id"])
                                for o in acc if o["request_id"] in app_http)
    print("upstream IP -> app instance (proved by request_id join):")
    for (ip, inst), c in sorted(ipmap.items(), key=str):
        print(f"   {ip:18s} -> {inst}: {c}")
    print("5xx by final upstream:")
    for (ip, s), c in sorted(collections.Counter((final_up(o), o["status"]) for o in fail).items(), key=str):
        print(f"   {ip:18s} {s}: {c}")
    print("error.log lines by (kind, upstream):")
    for (k, u), c in sorted(collections.Counter((e["kind"], e["up"]) for e in err).items(), key=str):
        print(f"   {k:8s} {u}: {c}")

    h("Q5  client latency (access.log request_time: seconds, shown in ms)")

    def latency(label, rows):
        v = sorted(o["request_time"] for o in rows)
        print(f"{label}: n={len(v)} median={statistics.median(v) * 1000:.1f} ms  "
              f"p95(nearest-rank)={nearest_rank(v, 95) * 1000:.1f} ms  "
              f"p95(linear)={linear(v, 95) * 1000:.1f} ms  max={v[-1] * 1000:.1f} ms")

    latency("all distinct requests", acc)
    latency("status 200 only", [o for o in acc if o["status"] == 200])
    latency("status >= 500 only", fail)

    h("Q6  upstream retries")
    retried = [o for o in acc if "," in o["upstream"]]
    ok = [o for o in retried if o["status"] == 200]
    print(f"requests with more than one upstream attempt: {len(retried)}; final 200 after retry: {len(ok)}")
    combos = collections.Counter((o["upstream"], o["upstream_status"], o["status"]) for o in retried)
    for (u, us, s), c in combos.items():
        print(f"   upstream={u} upstream_status={us} final_status={s}: {c}")
    print(f"of these, present in error.log: {sum(1 for o in retried if o['request_id'] in err_by_id)}")

    h("Q7  incident timeline per minute (access 5xx + error.log + application dependency_error)")
    tl = collections.defaultdict(collections.Counter)
    for o in fail:
        tl[o["timestamp"][:16]][f"access_{o['status']}"] += 1
    for e in err:
        tl[e["minute"]][f"error_{e['kind']}"] += 1
    for o in app:
        if o.get("event") == "dependency_error":
            tl[o["timestamp"][:16]][f"app_dep_{o.get('dependency')}"] += 1
    cols = sorted({c for v in tl.values() for c in v})
    with open(OUT / "timeline_per_minute.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["minute_utc"] + cols)
        for m in sorted(tl):
            w.writerow([m] + [tl[m][c] for c in cols])
    print("minute_utc        " + "  ".join(cols))
    for m in sorted(tl):
        print(f"{m}  " + "  ".join(f"{tl[m][c]:>{len(c)}d}" for c in cols))
    print("first -> last minute per signal:")
    for c in cols:
        ms = [m for m in tl if tl[m][c]]
        print(f"   {c}: {min(ms)} -> {max(ms)}")

    h("Q8  correlated examples (same request_id across the three logs)")
    app_by_id = collections.defaultdict(list)
    for o in app:
        app_by_id[o["request_id"]].append(o)
    acc_by_id = {o["request_id"]: o for o in acc}

    def pick(pred):
        return next((o["request_id"] for o in acc if pred(o)), None)

    examples = (("FAILED 502", pick(lambda o: o["status"] == 502)),
                ("FAILED 503", pick(lambda o: o["status"] == 503)),
                ("FAILED 504", pick(lambda o: o["status"] == 504)),
                ("RETRY THEN 200", pick(lambda o: "," in o["upstream"])),
                ("PLAIN 200", pick(lambda o: o["status"] == 200 and "," not in o["upstream"])))
    for label, rid in examples:
        if not rid:
            continue
        print(f"\n--- {label}  request_id={rid}")
        print("  access     :", json.dumps(acc_by_id[rid]))
        print("  error.log  :", err_by_id[rid]["raw"] if rid in err_by_id else "(no line)")
        if rid in app_by_id:
            for o in app_by_id[rid]:
                print("  application:", json.dumps(o))
        else:
            print("  application: (no record)")

    h("Q9  proxy/connectivity vs dependency/application")
    for st in (502, 504, 503):
        i = [o["request_id"] for o in acc if o["status"] == st]
        kinds = collections.Counter(err_by_id[x]["kind"] for x in i if x in err_by_id)
        print(f"HTTP {st}: n={len(i)}  in error.log={sum(1 for x in i if x in err_by_id)} {dict(kinds)}  "
              f"in application.log={sum(1 for x in i if x in app_http)}")
    d504 = sorted(app_http[o["request_id"]]["duration_ms"] for o in acc
                  if o["status"] == 504 and o["request_id"] in app_http)
    print(f"app duration_ms of the 504 requests: {d504}")
    dep = collections.Counter((o.get("dependency"), o.get("error_type")) for o in app
                              if o.get("event") == "dependency_error")
    print(f"dependency_error events by (dependency, error_type): {dict(dep)}")
    print(f"503 whose upstream_status is also 503 (the app itself answered): "
          f"{sum(1 for o in acc if o['status'] == 503 and o['upstream_status'] == '503')}")
    refused = sum(1 for e in err if e["kind"] == "refused")
    refused_502 = sum(1 for o in acc if o["status"] == 502 and o["request_id"] in err_by_id
                      and err_by_id[o["request_id"]]["kind"] == "refused")
    print(f"reconciliation: refused lines={refused}  vs  final-502-with-refused({refused_502}) "
          f"+ retried-then-200({len(ok)}) = {refused_502 + len(ok)}  -> match={refused == refused_502 + len(ok)}")


if __name__ == "__main__":
    main()
