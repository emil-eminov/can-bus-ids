"""Detectors that compare a capture against a learned baseline.

CAN has no sender authentication: any node can transmit any ID. These rules
look for the traces that common in-vehicle attacks leave in the traffic itself.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .baseline import Baseline
from .candump import Frame

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    can_id: int | None
    start: float
    end: float
    frames: int
    summary: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "can_id": None if self.can_id is None else f"0x{self.can_id:03X}",
            "start": round(self.start, 6),
            "end": round(self.end, 6),
            "frames": self.frames,
            "summary": self.summary,
        }


def _group(frames: list[Frame]) -> dict[int, list[Frame]]:
    g: dict[int, list[Frame]] = defaultdict(list)
    for fr in frames:
        g[fr.can_id].append(fr)
    return g


def unknown_ids(
    frames: list[Frame],
    baseline: Baseline,
    flood_rate_hz: float = 500.0,
    flood_min_frames: int = 50,
    fuzz_min_ids: int = 10,
) -> list[Finding]:
    """IDs never seen in the baseline: a flood (DoS), fuzzing, or a stray ID.

    A flooded ID that is lower than every legitimate ID wins arbitration on
    every bit, which starves the real ECUs off the bus.
    """
    unknown = _group([fr for fr in frames if fr.can_id not in baseline.profiles])
    findings, strays = [], {}
    for can_id, frs in unknown.items():
        span = max(frs[-1].ts - frs[0].ts, 1e-6)
        rate = len(frs) / span
        if len(frs) >= flood_min_frames and rate >= flood_rate_hz:
            note = (
                ", outranks every legitimate ID in arbitration"
                if can_id < baseline.lowest_id
                else ""
            )
            findings.append(
                Finding("flood_dos", "critical", can_id, frs[0].ts, frs[-1].ts, len(frs),
                        f"unknown ID at {rate:,.0f} frames/s{note}")
            )
        else:
            strays[can_id] = frs

    if len(strays) >= fuzz_min_ids:
        all_frs = sorted((fr for frs in strays.values() for fr in frs), key=lambda f: f.ts)
        findings.append(
            Finding("fuzzing", "high", None, all_frs[0].ts, all_frs[-1].ts, len(all_frs),
                    f"{len(strays)} distinct unknown IDs, {len(all_frs)} frames")
        )
    else:
        for can_id, frs in strays.items():
            findings.append(
                Finding("unknown_id", "medium", can_id, frs[0].ts, frs[-1].ts, len(frs),
                        "ID not present in baseline")
            )
    return findings


def rate_injection(
    frames: list[Frame],
    baseline: Baseline,
    window_s: float = 1.0,
    factor: float = 2.0,
    slack: int = 3,
) -> list[Finding]:
    """A known ID arriving far faster than its normal period.

    Injected frames compete with the real ECU's frames, so the ID's rate
    jumps. Consecutive flagged windows are merged into one finding.
    """
    if not frames:
        return []
    t0 = frames[0].ts
    findings = []
    for can_id, frs in _group(frames).items():
        prof = baseline.profiles.get(can_id)
        if prof is None or prof.period_ms <= 0:
            continue
        expected = window_s * 1000 / prof.period_ms
        limit = expected * factor + slack
        counts: dict[int, list[Frame]] = defaultdict(list)
        for fr in frs:
            counts[int((fr.ts - t0) // window_s)].append(fr)
        flagged = sorted(w for w, c in counts.items() if len(c) > limit)
        runs: list[list[int]] = []
        for w in flagged:
            if runs and w == runs[-1][-1] + 1:
                runs[-1].append(w)
            else:
                runs.append([w])
        for run in runs:
            run_frames = [fr for w in run for fr in counts[w]]
            observed = len(run_frames) / (len(run) * window_s)
            findings.append(
                Finding("rate_injection", "high", can_id, run_frames[0].ts, run_frames[-1].ts,
                        len(run_frames),
                        f"{observed:,.0f} frames/s vs normal {1000 / prof.period_ms:,.0f}/s "
                        f"({observed * prof.period_ms / 1000:.1f}x)")
            )
    return findings


def dlc_mismatch(frames: list[Frame], baseline: Baseline) -> list[Finding]:
    """A known ID sent with a payload length it never uses."""
    findings = []
    for can_id, frs in _group(frames).items():
        prof = baseline.profiles.get(can_id)
        if prof is None:
            continue
        bad = [fr for fr in frs if fr.dlc not in prof.dlcs]
        if bad:
            seen = sorted({fr.dlc for fr in bad})
            findings.append(
                Finding("dlc_mismatch", "medium", can_id, bad[0].ts, bad[-1].ts, len(bad),
                        f"DLC {seen} but baseline only uses {sorted(prof.dlcs)}")
            )
    return findings


def constant_byte_violation(frames: list[Frame], baseline: Baseline) -> list[Finding]:
    """A byte that never changed in normal traffic suddenly holds a new value.

    Typical of a spoofed or tampered frame built by hand rather than by the ECU.
    """
    findings = []
    for can_id, frs in _group(frames).items():
        prof = baseline.profiles.get(can_id)
        if prof is None or not prof.constant_bytes:
            continue
        bad, positions = [], set()
        for fr in frs:
            hits = [i for i, v in prof.constant_bytes.items() if i < fr.dlc and fr.data[i] != v]
            if hits:
                bad.append(fr)
                positions.update(hits)
        if bad:
            detail = ", ".join(
                f"byte {i} expected 0x{prof.constant_bytes[i]:02X}" for i in sorted(positions)
            )
            findings.append(
                Finding("constant_byte_violation", "high", can_id, bad[0].ts, bad[-1].ts, len(bad),
                        f"{len(bad)} frame(s) changed fixed bytes ({detail})")
            )
    return findings


ALL_RULES = {
    "unknown_ids": unknown_ids,
    "rate_injection": rate_injection,
    "dlc_mismatch": dlc_mismatch,
    "constant_byte_violation": constant_byte_violation,
}


def run_all(frames: list[Frame], baseline: Baseline, rules=None) -> list[Finding]:
    findings: list[Finding] = []
    for name in rules or ALL_RULES:
        findings.extend(ALL_RULES[name](frames, baseline))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.start))
