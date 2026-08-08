# voipscope

A standalone, offline VoIP analysis tool written in C++20. Reads PCAP files,
reconstructs SIP dialogs per RFC 3261, correlates RTP streams per RFC 3550,
and emits one CDR-style JSON record per completed call leg.

## Features

- **SIP parser** — written from scratch against RFC 3261; request/response
  lines, header folding, tag & Via-branch extraction, retransmission dedup
- **Dialog FSM** — TRYING → RINGING → ESTABLISHED → TERMINATED with
  re-INVITE and EOF incomplete-call handling
- **SDP offer/answer** — `c=`/`m=`/`a=rtpmap` parsing; static PT table for
  PCMU (0), PCMA (8), G.722 (9), G.729 (18)
- **RTP/RTCP** — RFC 3550 §A.8 running jitter estimator; RTCP RR cumulative
  loss as authoritative override; 5-tuple + SSRC correlation; late-arrival
  buffer (1000 packets cap)
- **MOS estimation** — simplified E-model with per-codec R₀ baseline
  (G.711 = 93.2, G.722 = 93.0, G.729 = 82.0) and Ie_eff packet-loss
  impairment; output clamped to [1.0, 4.5]
- **NDJSON output** — one JSON object per line; ISO 8601 UTC timestamps;
  `null` for no-media dialogs; `"status": "incomplete"` for truncated captures

## Requirements

| Dependency | Version | How supplied |
|-----------|---------|-------------|
| GCC or Clang | ≥ 12 / ≥ 18 | system |
| CMake | ≥ 3.20 | system |
| Conan | ≥ 2.0 | `pip install conan` |
| libpcap | any recent | system (`apt install libpcap-dev`) |
| nlohmann/json | 3.11.3 | Conan Center (auto) |
| GoogleTest | 1.14.0 | Conan Center (auto) |

## Build

```bash
# Ubuntu / Debian — system prerequisites
sudo apt install libpcap-dev cmake build-essential python3-pip
pip3 install "conan>=2.0"

git clone https://github.com/vlantonov/voipscope
cd voipscope

# Install C++ dependencies from Conan Center
conan profile detect          # one-time: detect local compiler
conan install . --output-folder=build --build=missing -s compiler.cppstd=20

# Configure, build
cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Run

```
./build/voipscope [OPTIONS] <pcap-file>

Options:
  -o, --output <file>   Write CDR NDJSON to <file> (default: stdout)
  -v, --verbose         Print per-packet diagnostics to stderr
  --help                Print help and exit
```

### Example

```bash
./build/voipscope -v capture.pcap | python3 -m json.tool
```

## CDR Output Format

One JSON object per call, newline-delimited:

```json
{
  "call_id": "a84b4c76e66710@pc33.atlanta.com",
  "caller":  "sip:alice@example.com",
  "callee":  "sip:bob@example.com",
  "start_time":   "2024-03-15T10:23:45.123Z",
  "end_time":     "2024-03-15T10:25:01.456Z",
  "duration_sec": 76.333,
  "codec":        "PCMU",
  "payload_type": 0,
  "streams": [
    {
      "direction":       "caller_to_callee",
      "ssrc":            305419896,
      "mos":             4.21,
      "mean_jitter_ms":  2.34,
      "packet_loss_pct": 0.12
    },
    {
      "direction":       "callee_to_caller",
      "ssrc":            2882400018,
      "mos":             4.15,
      "mean_jitter_ms":  3.10,
      "packet_loss_pct": 0.00
    }
  ],
  "mos":             4.21,
  "mean_jitter_ms":  2.34,
  "packet_loss_pct": 0.12,
  "ssrc":            305419896,
  "status":          "complete"
}
```

Fields `mos`, `mean_jitter_ms`, `packet_loss_pct`, `ssrc` at the top level
are copied from the first stream (caller→callee) and are `null` when no RTP
was observed.

## Test

```bash
cmake --build build --target voipscope_tests
ctest --test-dir build --output-on-failure
```

The test suite contains 47 unit and integration tests across:

| File | Coverage |
|------|---------|
| `test_sip_parser.cpp` | RFC 3261 request/response parsing, SDP bodies, malformed input |
| `test_dialog_fsm.cpp` | All FSM transitions, re-INVITE, retransmission dedup, EOF flush |
| `test_jitter.cpp` | RFC 3550 §A.8 jitter algorithm, sequence wraparound, single-packet edge case |
| `test_mos.cpp` | E-model formulas, codec baselines, MOS clamping |
| `test_cdr.cpp` | NDJSON serialisation, null fields, timestamp format, two-stream CDR |
| `test_integration.cpp` | End-to-end inline pipeline without a PCAP file |

One additional test (`Integration.RealPcapProducesCdr`) is automatically
**skipped** unless you place a real SIP/RTP capture at
`tests/fixtures/sip_rtp_pcmu.pcap`. A suitable file can be downloaded from
the [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
page (look for SIP + RTP traces with G.711 audio).

## Architecture

```
PCAP file
   │
   ▼
PcapReader          libpcap; yields UdpPacket per UDP frame
   │
   ├─► SipParser    RFC 3261; string_view zero-copy parse
   │       │
   │       └─► DialogManager   FSM + call registry
   │                │
   │                └─► RtpTracker   associate() on ESTABLISHED
   │
   ├─► RtpTracker   ingest(); §A.8 jitter + seq-loss
   │
   └─► RtcpParser   compound SR/RR; feeds loss override to RtpTracker
              │
              ▼
         MosEstimator   simplified E-model
              │
              ▼
         CdrEmitter     NDJSON via nlohmann/json → stdout / file
```

## Limitations (v1.0)

- UDP transport only (no TCP-carried SIP or RTP)
- Classic PCAP only (no PCAP-NG)
- Two-party calls only (no forking, no conferencing)
- Ethernet/IPv4 link layer only
- No SRTP / encrypted media

## Licence

MIT — see [LICENSE](LICENSE).
