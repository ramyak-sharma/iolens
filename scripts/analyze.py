#!/usr/bin/env python3
"""number crunching for the validation scripts. every subcommand prints
json (or a table for show-*), the shell scripts glue them together.
kept in one file so the math is in one place to review."""
import json
import math
import re
import statistics
import sys
from datetime import datetime


def load(p):
    with open(p) as f:
        return json.load(f)


def rel(a, b):
    """relative difference of a vs reference b"""
    if b == 0:
        return 0.0 if a == 0 else math.inf
    return abs(a - b) / b


# ---- V1 ----

def v1(ms, iolens_path, fio_path):
    ms = float(ms)
    want_us = ms * 1000
    io = load(iolens_path)
    fio = load(fio_path)
    # all reads on nullb0 folded together, there is only one cgroup anyway
    # but sum just in case
    reads = [s for s in io["summary"] if s["device"] == "nullb0" and s["op"] == "read"]
    reads.sort(key=lambda s: -s["count"])
    if not reads:
        raise SystemExit("no nullb0 reads seen by iolens")
    top = reads[0]
    pct = fio["jobs"][0]["read"]["clat_ns"]["percentile"]
    fio50, fio99 = pct["50.000000"] / 1000, pct["99.000000"] / 1000
    r = {
        "configured_ms": ms,
        "requests": top["count"],
        "iolens_p50_us": top["total_p50_us"],
        "iolens_p99_us": top["total_p99_us"],
        "fio_p50_us": fio50,
        "fio_p99_us": fio99,
    }
    r["err_vs_configured_p50"] = rel(top["total_p50_us"], want_us)
    r["err_vs_configured_p99"] = rel(top["total_p99_us"], want_us)
    r["err_vs_fio_p50"] = rel(top["total_p50_us"], fio50)
    r["err_vs_fio_p99"] = rel(top["total_p99_us"], fio99)
    r["pass"] = all(r[k] <= 0.25 for k in r if k.startswith("err_"))
    print(json.dumps(r))


def show_v1(p):
    d = load(p)
    print(f"{'ms':>4} {'n':>7} {'p50':>9} {'p99':>9} {'fio p50':>9} {'fio p99':>9}  pass")
    for r in d["runs"]:
        print(f"{r['configured_ms']:>4.0f} {r['requests']:>7} {r['iolens_p50_us']:>8.0f}u {r['iolens_p99_us']:>8.0f}u"
              f" {r['fio_p50_us']:>8.0f}u {r['fio_p99_us']:>8.0f}u  {r['pass']}")


# ---- V2 ----

def v2(dev, iolens_path, iostat_path):
    io = load(iolens_path)
    st = load(iostat_path)
    ours = []
    for w in io["windows"]:
        for d in w["devices"]:
            if d["device"] == dev:
                ours.append((datetime.fromisoformat(w["time"][:26]), d))
    theirs = []
    for s in st["sysstat"]["hosts"][0]["statistics"]:
        for d in s["disk"]:
            if d["disk_device"] == dev:
                theirs.append((datetime.fromisoformat(s["timestamp"][:19]), d))
    # both tools tick on whole seconds (see v2_iostat.sh). iostat prints its
    # timestamp truncated to the second, ours is a few ms past it, so pair
    # on the truncated second
    by_sec = {t.replace(microsecond=0): d for t, d in ours}
    pairs = [(by_sec[t], d) for t, d in theirs if t in by_sec]
    cols = {
        "r/s": ("r_s", "r/s", 0.02), "w/s": ("w_s", "w/s", 0.02),
        "rkB/s": ("rkB_s", "rkB/s", 0.02), "wkB/s": ("wkB_s", "wkB/s", 0.02),
        "r_await": ("r_await", "r_await", 0.05), "w_await": ("w_await", "w_await", 0.05),
    }
    out = {"device": dev, "windows": len(pairs), "columns": {}}
    for name, (a, b, tol) in cols.items():
        errs = [rel(o[a], t[b]) for o, t in pairs if t[b] > 0]
        if not errs:
            continue
        out["columns"][name] = {
            "median_err": statistics.median(errs),
            "p90_err": sorted(errs)[int(len(errs) * 0.9) - 1] if len(errs) >= 10 else max(errs),
            "tolerance": tol,
            "pass": statistics.median(errs) <= tol,
        }
    out["pass"] = bool(out["columns"]) and all(c["pass"] for c in out["columns"].values())
    print(json.dumps(out))


def show_v2(p):
    d = load(p)["result"]
    print(f"{d['windows']} aligned 1s windows on {d['device']}")
    for k, c in d["columns"].items():
        print(f"  {k:8} median {c['median_err']*100:5.2f}%  p90 {c['p90_err']*100:5.2f}%  (<= {c['tolerance']*100:.0f}%) {c['pass']}")


# ---- V3 ----

def parse_iostat_file(p):
    out = {}
    for line in open(p):
        f = line.split()
        if not f:
            continue
        kv = dict(x.split("=", 1) for x in f[1:] if "=" in x)
        out[f[0]] = {k: int(v) for k, v in kv.items() if v.isdigit()}
    return out


def v3(mode, dev, raw):
    io = load(f"{raw}/v3-{mode}-iolens.json")
    res = {"mode": mode, "cgroups": {}}
    ok = True
    for c in "ab":
        fio = load(f"{raw}/v3-{mode}-fio-{c}.json")
        wrote = fio["jobs"][0]["write"]["io_bytes"]
        ours = sum(s["bytes"] for s in io["summary"]
                   if s["device"] == dev and s["op"] == "write" and s["cgroup_path"].endswith(f"iolens-v3/{c}"))
        ios = parse_iostat_file(f"{raw}/v3-{mode}-iostat-{c}.txt")
        # io.stat is keyed by maj:min, pick the line with most writes. the
        # loop/fs underneath can show up too
        kstat = max((v.get("wbytes", 0) for v in ios.values()), default=0)
        e_fio, e_kern = rel(ours, wrote), rel(ours, kstat)
        res["cgroups"][c] = {"fio_bytes": wrote, "iolens_bytes": ours, "io_stat_wbytes": kstat,
                             "err_vs_fio": e_fio, "err_vs_io_stat": e_kern}
        ok = ok and e_fio <= 0.01 and e_kern <= 0.01
    # bytes nobody owns, should be just journal/metadata
    res["unattributed_or_root_bytes"] = sum(
        s["bytes"] for s in io["summary"] if s["device"] == dev and s["cgroup_path"] in ("", "/"))
    res["pass"] = ok
    print(json.dumps(res))


def show_v3(p):
    for r in load(p)["runs"]:
        print(f"{r['mode']}: pass={r['pass']}  root/unattributed {r['unattributed_or_root_bytes']/2**20:.1f} MiB")
        for c, v in r["cgroups"].items():
            print(f"  {c}: fio {v['fio_bytes']/2**20:8.1f} MiB  iolens {v['iolens_bytes']/2**20:8.1f} MiB"
                  f"  io.stat {v['io_stat_wbytes']/2**20:8.1f} MiB  err {v['err_vs_fio']*100:.2f}% / {v['err_vs_io_stat']*100:.2f}%")


# ---- V4 ----

def v4(kind, env, off, on, cpu_cores, rss_kb, bpf_path):
    off = [float(x) for x in off.split()]
    on = [float(x) for x in on.split()]
    ns = {}
    for line in open(bpf_path):
        m = re.match(r'iolens_agent_bpf_run_ns_per_event\{program="(\w+)"\} (\S+)', line)
        if m:
            ns[m.group(1)] = float(m.group(2))
    mo, mn = statistics.mean(off), statistics.mean(on)
    r = {
        "env": json.loads(env), "device": kind,
        "iops_off": off, "iops_on": on,
        "iops_off_mean": mo, "iops_off_sd": statistics.stdev(off) if len(off) > 1 else 0,
        "iops_on_mean": mn, "iops_on_sd": statistics.stdev(on) if len(on) > 1 else 0,
        "loss_pct": (mo - mn) / mo * 100,
        "ns_per_event": ns,
        # insert is skipped on direct issue, so per request it is roughly
        # issue + complete (+ insert when the scheduler is used)
        "ns_per_request": sum(ns.values()),
        "agent_cpu_cores": float(cpu_cores),
        "agent_rss_mib": int(rss_kb) / 1024,
    }
    r["pass"] = r["loss_pct"] <= 5
    print(json.dumps(r))


def show_v4(p):
    r = load(p)
    print(f"device: {r['device']}")
    print(f"  off: {r['iops_off_mean']:.0f} +- {r['iops_off_sd']:.0f} iops")
    print(f"  on:  {r['iops_on_mean']:.0f} +- {r['iops_on_sd']:.0f} iops")
    print(f"  loss {r['loss_pct']:.2f}%  (target <= 5%)  pass={r['pass']}")
    print(f"  ns/event {r['ns_per_event']}  agent {r['agent_cpu_cores']*100:.2f}% of a core, {r['agent_rss_mib']:.0f} MiB rss")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    fn = {"v1": v1, "show-v1": show_v1, "v2": v2, "show-v2": show_v2,
          "v3": v3, "show-v3": show_v3, "v4": v4, "show-v4": show_v4}[cmd]
    fn(*args)
