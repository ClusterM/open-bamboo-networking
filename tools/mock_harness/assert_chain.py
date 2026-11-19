#!/usr/bin/env python3
"""assert_chain.py — D-08 pass/fail verdict for plugin_runner --log-out JSONL.

Pass contract (D-08, tools/plugin_runner/README.md section 9 golden stream):
    bind_detect rc=0 -> connect_printer_call rc=0 -> local_connect status=0
    -> session_ready got=true -> start_subscribe -> kickstart_pushall rc=0
    -> idle_done
as an ORDERED subsequence of the log, with per-event payload checks.

The runner's exit code is NEVER the verdict (`--action none` exits 0 even
when the flow failed — main.cpp:2402-2417). Exit code of this
script is the verdict: 0 = chain passed, 1 = failed.

Usage: assert_chain.py --log PATH [--ssdp {off,soft,hard}]
"""
import argparse
import json
import sys

CHAIN = ["bind_detect", "connect_printer_call", "local_connect",
         "session_ready", "start_subscribe", "kickstart_pushall", "idle_done"]


def main():
    ap = argparse.ArgumentParser(description="D-08 ordered JSONL chain assertion")
    ap.add_argument("--log", required=True, help="plugin_runner --log-out file")
    ap.add_argument("--ssdp", choices=["off", "soft", "hard"], default="off",
                    help="ssdp_msg assert mode (run_harness.sh derives it from README)")
    args = ap.parse_args()

    first = {}   # kind -> first event dict (line order)
    order = []   # kinds in first-appearance order
    ssdp_seen = False
    try:
        fh = open(args.log, errors="replace")
    except OSError as e:
        print("FAIL cannot read log: %s" % e)
        return 1
    with fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue  # skip unparseable lines
            kind = ev.get("_kind")
            if kind == "ssdp_msg":
                ssdp_seen = True
            if kind and kind not in first:
                first[kind] = ev
                order.append(kind)

    failures = []

    # --- payload checks (D-08 explicit fails) ---
    bd = first.get("bind_detect")
    if bd is None:
        failures.append("FAIL missing bind_detect")
    elif bd.get("rc") != 0:
        failures.append("FAIL bind_detect rc!=0")

    cc = first.get("connect_printer_call")
    if cc is None:
        failures.append("FAIL missing connect_printer_call")
    elif cc.get("rc") != 0:
        failures.append("FAIL connect_printer_call rc!=0")

    lc = first.get("local_connect")
    if lc is None:
        failures.append("FAIL missing local_connect")
    else:
        st = lc.get("status")
        if st == 1:
            failures.append("FAIL local_connect status=1")
        elif st != 0:
            failures.append("FAIL local_connect status=%s" % st)

    sr = first.get("session_ready")
    if sr is None:
        failures.append("FAIL missing session_ready")
    elif sr.get("got") is not True:
        failures.append("FAIL session_ready got=false")

    if "start_subscribe" not in first:
        failures.append("FAIL missing start_subscribe")

    kp = first.get("kickstart_pushall")
    if kp is None:
        failures.append("FAIL missing kickstart_pushall")
    elif kp.get("rc") != 0:
        failures.append("FAIL kickstart_pushall rc!=0")

    if "idle_done" not in first:
        failures.append("FAIL missing idle_done")

    # --- ordered subsequence check (first-appearance positions must ascend) ---
    present = [k for k in CHAIN if k in first]
    if len(present) == len(CHAIN):
        pos = [order.index(k) for k in CHAIN]
        if pos != sorted(pos):
            failures.append("FAIL out-of-order chain")

    # --- ssdp mode ---
    if args.ssdp == "hard" and not ssdp_seen:
        failures.append("FAIL missing ssdp_msg")
    elif args.ssdp == "soft" and not ssdp_seen:
        print("WARN ssdp_msg not present (soft assert: not failing)", file=sys.stderr)

    if failures:
        for f in failures:
            print(f)
        return 1
    print("PASS D-08 chain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
