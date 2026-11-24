# can-bus-ids

Baseline-driven intrusion detection for in-vehicle CAN bus traffic.

CAN (Controller Area Network) connects a car's electronic control units (ECUs), and it has no sender authentication: any node on the bus can transmit any message ID. That makes the traffic itself the best place to spot an attack. This tool learns what normal traffic looks like from a clean capture, then scans other captures for the traces that common in-vehicle attacks leave behind.

It reads the standard Linux [can-utils](https://github.com/linux-can/can-utils) `candump -L` format, so it works on real captures as well as the included simulator.

```
$ python -m canids train data/train.log -o data/baseline.json
Learned 7 IDs from 12,360 frames (30.0 s). Saved to data/baseline.json

$ python -m canids detect data/attack.log -b data/baseline.json
Scanned 17,968 frames against 7 known IDs. 5 finding(s).

[CRITICAL] flood_dos  id=0x000
    t+4.998s to t+5.997s, 4,000 frames
    unknown ID at 4,001 frames/s, outranks every legitimate ID in arbitration

[HIGH] fuzzing  id=many
    t+9.998s to t+11.996s, 1,000 frames
    784 distinct unknown IDs, 1000 frames

[HIGH] rate_injection  id=0x244
    t+15.001s to t+17.993s, 749 frames
    250 frames/s vs normal 50/s (5.0x)

[HIGH] constant_byte_violation  id=0x40A
    t+21.998s to t+22.798s, 5 frames
    5 frame(s) changed fixed bytes (byte 0 expected 0x0F)

[MEDIUM] dlc_mismatch  id=0x2C0
    t+24.998s to t+25.198s, 3 frames
    DLC [8] but baseline only uses [3]

Summary: 1 critical, 3 high, 1 medium
```

The same baseline run against a second, attack-free drive (`clean_test.log`, 12,360 frames) produces **zero findings**.

## What it learns

For every CAN ID seen in the clean capture, the baseline records:

- **Period**: median time between frames (most ECUs broadcast on a fixed cycle, such as every 10 or 100 ms)
- **DLC**: the payload lengths the ID actually uses (DLC is the Data Length Code)
- **Constant bytes**: payload positions that never changed (reserved bytes, fixed flags), learned only for IDs with at least 20 frames

The baseline is plain JSON, so it can be reviewed and edited by hand.

## Detections

| Rule | Severity | Attack it catches | How |
|---|---|---|---|
| `flood_dos` | critical | Denial of service | An unknown ID sent at 500+ frames/s. Flagged as outranking the bus when it is lower than every legitimate ID, because the lowest ID wins arbitration and starves real ECUs. |
| `fuzzing` | high | Fuzzing or reconnaissance | 10+ distinct unknown IDs, reported as one finding rather than hundreds |
| `unknown_id` | medium | Stray or new node | A few unknown IDs that are not a flood or a fuzzing pattern |
| `rate_injection` | high | Message injection / spoofing | A known ID arriving at more than 2x its normal rate in a 1 s window. Consecutive windows merge into one finding. |
| `constant_byte_violation` | high | Hand-built or tampered frames | A byte that never changed in normal traffic holds a new value |
| `dlc_mismatch` | medium | Malformed frames | A known ID sent with a payload length it never uses |

Design notes:

- **Injection that copies the real payload layout is still caught.** The simulated speed spoof uses the correct format and counter, so only the rate gives it away, which is why timing matters as much as content.
- **Thresholds are keyword arguments** in `canids/detect.py`, so they can be tuned per vehicle.
- **Exit code 1 when anything is found**, so a scan can gate a test bench or CI job.
- **Limits:** this is a rule-based baseline, not a learned model. It does not decode signals, so an attacker who replaces a real ECU's frames one-for-one with plausible values (a masquerade attack) needs signal-level checks on top. Classic CAN only; CAN FD frames are rejected by the parser.

## Quick start

Requires Python 3.10+. No third-party dependencies.

```bash
git clone https://github.com/emil-eminov/can-bus-ids.git
cd can-bus-ids
python simulate.py                                       # writes data/*.log
python -m canids train data/train.log -o data/baseline.json
python -m canids detect data/clean_test.log -b data/baseline.json   # 0 findings
python -m canids detect data/attack.log -b data/baseline.json       # 5 findings
python -m canids detect data/attack.log -b data/baseline.json --json
```

To use a real capture: `candump -L can0 > drive.log` on a Linux machine with a CAN interface, drive normally to build the baseline, then scan later captures.

## Simulator

`simulate.py` generates 30 seconds of traffic from seven invented ECUs (engine RPM, gear, speed, brake, steering, doors, climate) with 3% timing jitter, big-endian signals, reserved zero bytes and a 4-bit rolling counter. It writes a training drive, a separate clean drive, and an attack drive with five labelled attacks:

| Attack | When | Frames |
|---|---|---|
| DoS flood on ID 0x000 | t+5 s, 1 s | 4,000 |
| Fuzzing with random IDs and payloads | t+10 s, 2 s | 1,000 |
| Speed spoof on 0x244 (reads 0 km/h) | t+15 s, 3 s | 600 |
| Door status tampering on 0x40A | t+22 s | 5 |
| Wrong-length brake frames on 0x2C0 | t+25 s | 3 |

No real vehicle data is used.

## Tests

```bash
pip install pytest
python -m pytest
```

The end-to-end test checks that the clean drive produces nothing and the attack drive produces exactly the five expected findings.

## Credits

Detection design and direction by [Emil Eminov](https://github.com/emil-eminov), drawing on automotive cybersecurity work and anomaly detection research. Implementation written with an AI pair-programmer.

## License

MIT
