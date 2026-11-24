"""Command line:  python -m canids train|detect ..."""

from __future__ import annotations

import argparse
import json
from collections import Counter

from .baseline import Baseline, learn
from .candump import read_log
from .detect import ALL_RULES, run_all


def cmd_train(args) -> int:
    frames = read_log(args.capture)
    baseline = learn(frames)
    baseline.save(args.out)
    print(f"Learned {len(baseline.profiles)} IDs from {len(frames):,} frames "
          f"({baseline.duration_s:.1f} s). Saved to {args.out}")
    return 0


def cmd_detect(args) -> int:
    baseline = Baseline.load(args.baseline)
    frames = read_log(args.capture)
    findings = run_all(frames, baseline, args.rules)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 1 if findings else 0

    t0 = frames[0].ts if frames else 0.0
    print(f"Scanned {len(frames):,} frames against {len(baseline.profiles)} known IDs. "
          f"{len(findings)} finding(s).\n")
    for f in findings:
        cid = "many" if f.can_id is None else f"0x{f.can_id:03X}"
        print(f"[{f.severity.upper()}] {f.rule}  id={cid}")
        print(f"    t+{f.start - t0:.3f}s to t+{f.end - t0:.3f}s, {f.frames:,} frames")
        print(f"    {f.summary}\n")
    if findings:
        c = Counter(f.severity for f in findings)
        print("Summary: " + ", ".join(f"{c[s]} {s}" for s in ("critical", "high", "medium") if c[s]))
    return 1 if findings else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="canids", description="Baseline-driven CAN bus intrusion detection.")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="learn a baseline from an attack-free capture")
    t.add_argument("capture", help="candump -L log of normal traffic")
    t.add_argument("-o", "--out", default="baseline.json")
    t.set_defaults(func=cmd_train)

    d = sub.add_parser("detect", help="scan a capture against a baseline")
    d.add_argument("capture", help="candump -L log to scan")
    d.add_argument("-b", "--baseline", default="baseline.json")
    d.add_argument("--rules", nargs="+", choices=sorted(ALL_RULES))
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_detect)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
