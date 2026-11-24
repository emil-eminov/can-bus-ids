"""Read and write classic CAN frames in Linux can-utils `candump -L` format.

Example line:  (1700000000.123456) can0 244#0A1B000003
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

LINE = re.compile(r"^\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})#([0-9A-Fa-f]{0,16})$")


@dataclass(frozen=True)
class Frame:
    ts: float  # seconds
    iface: str
    can_id: int
    data: bytes

    @property
    def dlc(self) -> int:
        return len(self.data)


def parse_line(line: str, lineno: int = 0) -> Frame:
    m = LINE.match(line.strip())
    if not m or len(m.group(4)) % 2:
        raise ValueError(f"line {lineno}: not a classic CAN candump frame: {line.strip()!r}")
    ts, iface, can_id, payload = m.groups()
    return Frame(float(ts), iface, int(can_id, 16), bytes.fromhex(payload))


def read_log(path: str | Path) -> list[Frame]:
    """Parse a candump log, skipping blank lines and # comments, sorted by time."""
    frames = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.strip() and not line.lstrip().startswith("#"):
                frames.append(parse_line(line, n))
    return sorted(frames, key=lambda fr: fr.ts)


def format_frame(fr: Frame) -> str:
    width = 3 if fr.can_id <= 0x7FF else 8
    return f"({fr.ts:.6f}) {fr.iface} {fr.can_id:0{width}X}#{fr.data.hex().upper()}"
