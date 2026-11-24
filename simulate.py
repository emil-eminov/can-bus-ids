"""Simulate in-vehicle CAN traffic, with and without attacks.

Usage: python simulate.py [--out-dir data] [--seconds 30]

Writes three candump -L logs:
  train.log        clean drive, used to learn the baseline
  clean_test.log   a different clean drive (should produce zero findings)
  attack.log       a third drive with five labelled attacks injected

No real vehicle data is used. The ECU set, periods and payload layouts are
invented but follow common patterns: fixed-period broadcast, big-endian
signals, reserved zero bytes and a 4-bit rolling counter in the last byte.
"""

from __future__ import annotations

import argparse
import math
import random
from pathlib import Path

from canids.candump import Frame, format_frame

T0 = 1795000000.0
IFACE = "can0"


def _u16(v: float) -> list[int]:
    v = max(0, min(0xFFFF, int(v)))
    return [v >> 8, v & 0xFF]


def speed_kmh(t: float) -> float:
    return 60 + 40 * math.sin(t / 8)


# (CAN ID, period in ms, payload builder(t, counter, rng) -> list of bytes)
ECUS = [
    (0x0C4, 10, lambda t, c, r: _u16(800 + 2200 * (0.5 + 0.5 * math.sin(t / 5)) + r.uniform(-20, 20))
     + [0, 0, 0, 0, 0, c]),                                                          # engine RPM
    (0x1A0, 20, lambda t, c, r: [min(6, 1 + int(speed_kmh(t) // 20)), 0x00, 0x80, c]),  # gear
    (0x244, 20, lambda t, c, r: _u16(speed_kmh(t) * 100) + [0, 0, c]),                # vehicle speed
    (0x2C0, 10, lambda t, c, r: [int(max(0, -math.cos(t / 8)) * 100), 0x00, c]),       # brake pedal
    (0x3E9, 10, lambda t, c, r: _u16(32768 + 3000 * math.sin(t / 3)) + [r.randint(0, 40), 0, 0, c]),  # steering
    (0x40A, 100, lambda t, c, r: [0x0F, c]),                                          # doors: all closed
    (0x5F0, 500, lambda t, c, r: [21, 3, 0x01, 0, 0, 0, 0, c]),                       # climate
]


def normal_traffic(seconds: float, rng: random.Random) -> list[Frame]:
    frames = []
    for can_id, period_ms, build in ECUS:
        period = period_ms / 1000
        phase = rng.uniform(0, period)
        for k in range(int(seconds / period)):
            t = phase + k * period + rng.gauss(0, 0.03 * period)  # 3% timing jitter
            payload = build(t, k % 16, rng)
            frames.append(Frame(T0 + t, IFACE, can_id, bytes(payload)))
    return frames


def attacks(rng: random.Random) -> tuple[list[Frame], list[dict]]:
    known = {e[0] for e in ECUS}
    frames, labels = [], []

    def add(label: str, frs: list[Frame]) -> None:
        frames.extend(frs)
        labels.append({"attack": label, "start": frs[0].ts - T0, "frames": len(frs)})

    # 1. DoS: flood the highest-priority ID 0x000 for one second
    add("flood_dos", [Frame(T0 + 5 + i * 0.00025, IFACE, 0x000, bytes(8)) for i in range(4000)])

    # 2. Fuzzing: random unknown IDs, random lengths and payloads, for two seconds
    fuzz_ids = [i for i in range(0x001, 0x800) if i not in known]
    add("fuzzing", [
        Frame(T0 + 10 + i * 0.002, IFACE, rng.choice(fuzz_ids),
              bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 8))))
        for i in range(1000)
    ])

    # 3. Injection: spoof vehicle speed = 0 km/h every 5 ms for three seconds.
    #    The attacker copied the real layout, so only the rate gives it away.
    add("rate_injection", [
        Frame(T0 + 15 + i * 0.005, IFACE, 0x244, bytes([0, 0, 0, 0, i % 16])) for i in range(600)
    ])

    # 4. Tampering: hand-built door frames claiming the doors are open
    add("constant_byte_violation", [
        Frame(T0 + 22 + i * 0.2, IFACE, 0x40A, bytes([0x00, i % 16])) for i in range(5)
    ])

    # 5. Malformed: brake frames with the wrong length
    add("dlc_mismatch", [
        Frame(T0 + 25 + i * 0.1, IFACE, 0x2C0, bytes([0x64, 0, 0, 0, 0, 0, 0, i])) for i in range(3)
    ])
    return frames, labels


def write_log(path: Path, frames: list[Frame]) -> None:
    frames = sorted(frames, key=lambda f: f.ts)
    path.write_text("\n".join(format_frame(f) for f in frames) + "\n", encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out-dir", default="data")
    p.add_argument("--seconds", type=float, default=30)
    args = p.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_log(out / "train.log", normal_traffic(args.seconds, random.Random(1)))
    write_log(out / "clean_test.log", normal_traffic(args.seconds, random.Random(2)))
    attack_frames, labels = attacks(random.Random(3))
    write_log(out / "attack.log", normal_traffic(args.seconds, random.Random(4)) + attack_frames)

    print(f"wrote train.log, clean_test.log, attack.log to {out}/")
    for lab in labels:
        print(f"  attack {lab['attack']:<24} at t+{lab['start']:.1f}s, {lab['frames']:,} frames")


if __name__ == "__main__":
    main()
