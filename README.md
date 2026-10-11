# python-tcp-iot-ev

Python TCP IoT bridge for EV vehicles — translates between the **DiLu**
binary device protocol and the **Omni** ASCII server protocol.

> **Status: discontinued.** This repository is published as a single commit
> for reference. It is not maintained and is not production-ready — see
> [Security notes](#security-notes) before running it anywhere.

## What it does

A fleet server speaks Omni. The vehicles speak DiLu. This bridge sits
between them so neither side has to change:

```
  EV vehicle (DiLu binary)  <--TCP-->  bridge  <--TCP-->  fleet server (Omni ASCII)
                                      :9000              upstream :7072
```

Both directions are translated, not tunnelled: raw DiLu binary is never
forwarded upstream, and Omni text is never forwarded to the device.
State the server may ask for at any time (GPS, ICCID, BLE MAC, scooter
info) is served from a per-connection cache of the last status packet.

- **Device → server:** status notifications, heartbeats, auth and device
  info are parsed and re-emitted as Omni `Q0` (sign-in), `H0` (heartbeat),
  `D0`, `E0`, `I0`, `M0`, `S6`, `G0`.
- **Server → device:** Omni commands are decoded and turned into DiLu
  command packets — locks (`L0`/`L1`/`L5`), settings (`S5`/`S7`/`S4`),
  beeper (`V0`), restart (`S1`). Unsupported commands are logged and
  dropped rather than guessed at.
- **Sign-in gating:** `Q0` is only sent once auth, device info and a first
  status packet have all arrived (in any order). Heartbeats before that
  are held.
- **AES-128-ECB** payload encryption is implemented (DiLu spec 4.3): the
  device-generated session key arrives in the auth packet encrypted under
  a per-device root key. Disabled by default.

## Layout

| Path | Contents |
|---|---|
| [`mainserver/pythonserver.py`](mainserver/pythonserver.py) | Entry point — TCP listener, per-device state, both relay directions |
| [`mainserver/from_device.py`](mainserver/from_device.py) | DiLu packet parsers (status, auth, device info, version, OTA result) |
| [`mainserver/to_device.py`](mainserver/to_device.py) | Omni command handlers → DiLu command packets |
| [`mainserver/to_server.py`](mainserver/to_server.py) | Omni message builders (`Q0`, `H0`, `D0`, `E0`, …) |
| [`mainserver/aes_handler.py`](mainserver/aes_handler.py) | AES-128-ECB payload encrypt/decrypt, session-key unwrap |
| [`mainserver/shared.py`](mainserver/shared.py) | CRC16 over packet content |
| [`mainserver/helpers.py`](mainserver/helpers.py) | Sign-in / heartbeat gating |
| [`doc and test/document.txt`](doc%20and%20test/document.txt) | **Protocol reference** — per-command field mapping, Omni↔DiLu overlap table, what is implemented vs not applicable |
| [`doc and test/test.py`](doc%20and%20test/test.py) | Fake device — sends hand-built DiLu packets to the bridge |
| [`doc and test/main_server_test.py`](doc%20and%20test/main_server_test.py) | Fake upstream — sends Omni commands down to the bridge |
| [`doc and test/test_log.txt`](doc%20and%20test/test_log.txt) | Sanitised sample run |

### Wire format (DiLu)

```
0x5155 | length (2B LE) | content | CRC16 (2B)
content = head (1B) | cmd (1B) | payload
```

Multi-byte numerics are little-endian; CRC16 covers the content only.
Omni frames are `*SCOR,OM,<IMEI>,<TYPE>,<args>#` with an `0xFFFF` prefix
inbound.

## Running it

Requires Python 3.11+ and [pycryptodome](https://pypi.org/project/pycryptodome/):

```sh
pip install pycryptodome
```

Edit the configuration block at the top of
[`mainserver/pythonserver.py`](mainserver/pythonserver.py) — `UPSTREAM_HOST`
is a placeholder (`upstream.example.com`) and must be pointed at your own
server — then:

```sh
cd mainserver
python pythonserver.py        # listens on 0.0.0.0:9000
```

To exercise it without hardware, run all three locally: set
`UPSTREAM_HOST = "127.0.0.1"`, start `main_server_test.py` (fake upstream
on :8000, so set `UPSTREAM_PORT` to match), then `test.py` as the fake
device. Both harnesses are menu-driven — `test.py`'s docstring gives the
packet order that drives a full sign-in.

## Security notes

Read these before running the bridge on any reachable interface. They are
repeated as `SECURITY` comments at the relevant lines.

- **The listener is unauthenticated.** The source-IP check in
  `handle_client()` is commented out, so any host that can reach port 9000
  is relayed upstream. The DiLu auth packet carries a device-supplied ID
  and root key, and a mismatch is logged rather than enforced. Re-enable
  the allowlist, or put the port behind a firewall / VPN / private APN.
- **The AES root key in `device_state` is a public placeholder** — the same
  dummy key used by the test fixture. Left as-is, AES provides no real
  protection. Load per-device keys from provisioning data kept out of
  version control.
- **`aes_enabled` is hardcoded `False`**; there is no negotiation to detect
  an encrypting device automatically.
- **Logging is verbose by design** and prints parsed device fields to
  stdout. The root key is redacted, but IMEI, ICCID and IMSI are not —
  treat captured logs as containing subscriber identifiers.

### About the published data

Real device identifiers (IMEI / ICCID / IMSI), device source IPs, the
upstream hostname and local user paths have been replaced with
well-formed placeholders throughout. See the header of
[`doc and test/test_log.txt`](doc%20and%20test/test_log.txt) for the exact
substitutions. No value in this repository is a live credential or a real
subscriber identity.
