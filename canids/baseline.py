"""Learn a per-ID profile of normal bus traffic from a clean capture."""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .candump import Frame

MIN_FRAMES_FOR_CONSTANTS = 20  # too few frames and every byte looks constant


@dataclass
class IdProfile:
    can_id: int
    count: int
    period_ms: float  # median inter-arrival time
    dlcs: set[int]
    constant_bytes: dict[int, int] = field(default_factory=dict)  # byte index -> value

    def to_dict(self) -> dict:
        return {
            "can_id": f"0x{self.can_id:03X}",
            "count": self.count,
            "period_ms": round(self.period_ms, 3),
            "dlcs": sorted(self.dlcs),
            "constant_bytes": {str(i): f"0x{v:02X}" for i, v in sorted(self.constant_bytes.items())},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IdProfile":
        return cls(
            can_id=int(d["can_id"], 16),
            count=d["count"],
            period_ms=d["period_ms"],
            dlcs=set(d["dlcs"]),
            constant_bytes={int(i): int(v, 16) for i, v in d["constant_bytes"].items()},
        )


@dataclass
class Baseline:
    duration_s: float
    profiles: dict[int, IdProfile]

    @property
    def lowest_id(self) -> int:
        return min(self.profiles)

    def save(self, path: str | Path) -> None:
        payload = {
            "duration_s": round(self.duration_s, 3),
            "ids": [p.to_dict() for _, p in sorted(self.profiles.items())],
        }
        Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        profiles = [IdProfile.from_dict(p) for p in d["ids"]]
        return cls(d["duration_s"], {p.can_id: p for p in profiles})


def learn(frames: list[Frame]) -> Baseline:
    """Build a baseline. `frames` must be attack-free and sorted by time."""
    if len(frames) < 2:
        raise ValueError("need at least two frames to learn a baseline")
    by_id: dict[int, list[Frame]] = defaultdict(list)
    for fr in frames:
        by_id[fr.can_id].append(fr)

    profiles = {}
    for can_id, frs in by_id.items():
        gaps = [(b.ts - a.ts) * 1000 for a, b in zip(frs, frs[1:])]
        constants: dict[int, int] = {}
        if len(frs) >= MIN_FRAMES_FOR_CONSTANTS:
            for i in range(min(fr.dlc for fr in frs)):
                values = {fr.data[i] for fr in frs}
                if len(values) == 1:
                    constants[i] = values.pop()
        profiles[can_id] = IdProfile(
            can_id=can_id,
            count=len(frs),
            period_ms=statistics.median(gaps) if gaps else 0.0,
            dlcs={fr.dlc for fr in frs},
            constant_bytes=constants,
        )
    return Baseline(frames[-1].ts - frames[0].ts, profiles)
