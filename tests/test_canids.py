import random
import subprocess
import sys
from pathlib import Path

import pytest

from canids import Baseline, learn, read_log, run_all
from canids.candump import Frame, format_frame, parse_line
from canids.detect import constant_byte_violation, dlc_mismatch, rate_injection, unknown_ids

ROOT = Path(__file__).resolve().parent.parent


def periodic(can_id, period_ms, seconds, payload, start=0.0):
    p = period_ms / 1000
    return [Frame(start + k * p, "can0", can_id, bytes(payload)) for k in range(int(seconds / p))]


@pytest.fixture
def baseline():
    frames = periodic(0x100, 10, 5, [1, 0, 0xAA]) + periodic(0x200, 100, 5, [0x0F, 0])
    return learn(sorted(frames, key=lambda f: f.ts))


def test_candump_roundtrip():
    line = "(1795000000.123456) can0 244#0A1B000003"
    fr = parse_line(line)
    assert (fr.can_id, fr.dlc, fr.data[1]) == (0x244, 5, 0x1B)
    assert format_frame(fr) == line


@pytest.mark.parametrize("bad", ["can0 244#00", "(1.0) can0 24#00", "(1.0) can0 244#0A1", "(1.0) can0 244##00"])
def test_candump_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_line(bad)


def test_learn_profiles(baseline):
    p = baseline.profiles[0x100]
    assert p.period_ms == pytest.approx(10)
    assert p.dlcs == {3}
    assert p.constant_bytes == {0: 1, 1: 0, 2: 0xAA}


def test_baseline_json_roundtrip(baseline, tmp_path):
    path = tmp_path / "b.json"
    baseline.save(path)
    loaded = Baseline.load(path)
    assert loaded.profiles[0x200].constant_bytes == baseline.profiles[0x200].constant_bytes
    assert loaded.profiles[0x100].period_ms == pytest.approx(10)


def test_flood_of_low_id_is_critical(baseline):
    flood = [Frame(1 + i * 0.0005, "can0", 0x000, bytes(8)) for i in range(200)]
    [f] = unknown_ids(flood, baseline)
    assert f.rule == "flood_dos" and f.severity == "critical" and "outranks" in f.summary


def test_many_stray_ids_become_one_fuzzing_finding(baseline):
    rng = random.Random(0)
    fuzz = [Frame(i * 0.01, "can0", rng.randint(0x300, 0x7FF), b"\x00") for i in range(40)]
    findings = unknown_ids(fuzz, baseline)
    assert [f.rule for f in findings] == ["fuzzing"]


def test_single_stray_id_is_medium(baseline):
    [f] = unknown_ids([Frame(1.0, "can0", 0x555, b"\x01")], baseline)
    assert (f.rule, f.severity) == ("unknown_id", "medium")


def test_rate_injection_flags_and_merges_windows(baseline):
    normal = periodic(0x100, 10, 5, [1, 0, 0xAA])
    injected = periodic(0x100, 2, 2, [1, 0, 0xAA], start=1.0)  # 5x extra traffic for 2 s
    [f] = rate_injection(sorted(normal + injected, key=lambda x: x.ts), baseline)
    assert f.can_id == 0x100 and f.end - f.start > 1.5


def test_normal_rate_is_quiet(baseline):
    assert rate_injection(periodic(0x100, 10, 5, [1, 0, 0xAA]), baseline) == []


def test_dlc_and_constant_byte_rules(baseline):
    frames = [Frame(1.0, "can0", 0x200, bytes([0x00, 0])), Frame(2.0, "can0", 0x100, bytes(8))]
    assert [f.can_id for f in constant_byte_violation(frames, baseline)] == [0x200, 0x100]
    assert [f.can_id for f in dlc_mismatch(frames, baseline)] == [0x100]


def test_simulation_end_to_end(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "simulate.py"), "--out-dir", str(tmp_path)],
                   check=True, capture_output=True, cwd=ROOT)
    baseline = learn(read_log(tmp_path / "train.log"))
    assert run_all(read_log(tmp_path / "clean_test.log"), baseline) == []
    found = {(f.rule, f.can_id) for f in run_all(read_log(tmp_path / "attack.log"), baseline)}
    assert found == {
        ("flood_dos", 0x000),
        ("fuzzing", None),
        ("rate_injection", 0x244),
        ("constant_byte_violation", 0x40A),
        ("dlc_mismatch", 0x2C0),
    }
