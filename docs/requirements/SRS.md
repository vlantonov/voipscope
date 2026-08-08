# Software Requirements Specification

**Project:** voipscope  
**Version:** 1.0.0-draft  
**Date:** 2026-08-09  
**Status:** Draft — pending stakeholder sign-off

---

## Table of Contents

1. [Overview](#1-overview)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [External Interfaces](#4-external-interfaces)
5. [Constraints and Assumptions](#5-constraints-and-assumptions)
6. [Out of Scope](#6-out-of-scope)
7. [Acceptance Criteria](#7-acceptance-criteria)
8. [Open Questions](#8-open-questions)

---

## 1. Overview

**voipscope** is a standalone, offline VoIP analysis tool written in C++20. It reads PCAP files, reconstructs SIP dialogs per RFC 3261, correlates associated RTP streams per RFC 3550, and emits one CDR-style JSON record per completed call leg. The primary portfolio goal is to demonstrate mastery of network protocol parsing, finite-state machines, and signal-quality estimation in idiomatic modern C++.

**Intended users:** Telecoms engineers and portfolio reviewers inspecting call quality from captured network traces.

---

## 2. Functional Requirements

### 2.1 PCAP Ingestion

| ID | Requirement |
|----|-------------|
| FR-01 | The tool shall accept a PCAP file path as a mandatory CLI argument and open the file for offline (non-live) packet reading. |
| FR-02 | The tool shall iterate every packet in the PCAP file in capture order, extracting Ethernet/IP/UDP layers. |
| FR-03 | The tool shall silently skip non-UDP packets and non-SIP/RTP UDP payloads without aborting processing. |
| FR-04 | The tool shall report a fatal error and exit with a non-zero status code if the PCAP file cannot be opened or is malformed. |

### 2.2 SIP Parsing (RFC 3261)

| ID | Requirement |
|----|-------------|
| FR-05 | The tool shall include a SIP parser written from scratch (no third-party SIP stack) capable of identifying SIP request and response messages from raw UDP payloads. |
| FR-06 | The SIP parser shall extract the following headers: `Via`, `From`, `To`, `Call-ID`, `CSeq`, `Contact`, `Content-Type`, `Content-Length`. |
| FR-07 | The SIP parser shall extract the `tag` parameter from `From` and `To` headers to uniquely identify a dialog leg. |
| FR-08 | The SIP parser shall parse the SDP body (content type `application/sdp`) attached to `INVITE` and `200 OK` messages to extract media connection and codec information. |
| FR-09 | The SIP parser shall treat a SIP message as malformed and discard it (logging a warning) if any of the mandatory headers (From, To, Call-ID, CSeq) are absent. |

### 2.3 SIP Dialog Tracking

| ID | Requirement |
|----|-------------|
| FR-10 | The tool shall implement a SIP dialog state machine with at least the following states: `IDLE`, `TRYING`, `RINGING`, `ESTABLISHED`, `TERMINATED`. |
| FR-11 | The tool shall transition a dialog to `TRYING` upon observing an `INVITE` request for a new `Call-ID`. |
| FR-12 | The tool shall transition a dialog to `RINGING` upon observing a `180 Ringing` or `183 Session Progress` provisional response matching an active `Call-ID` + `CSeq`. |
| FR-13 | The tool shall transition a dialog to `ESTABLISHED` upon observing a `200 OK` response to an `INVITE` and shall record the answer SDP at that point. |
| FR-14 | The tool shall transition a dialog to `TERMINATED` upon observing a `BYE` request or a `4xx`/`5xx`/`6xx` final response that closes the dialog, recording the termination timestamp. |
| FR-15 | The tool shall record start-of-call time as the timestamp of the `200 OK` packet and end-of-call time as the timestamp of the `BYE` (or error response) packet. |
| FR-16 | The tool shall handle re-INVITE (mid-dialog `INVITE`) by updating SDP codec/media information without creating a duplicate CDR. |

### 2.4 SDP Codec Extraction

| ID | Requirement |
|----|-------------|
| FR-17 | The tool shall parse SDP `m=` (media), `c=` (connection), `a=rtpmap`, and `a=fmtp` lines from INVITE and 200 OK bodies. |
| FR-18 | The tool shall extract the negotiated codec name and RTP payload type number from the offer/answer exchange and record them in the dialog context. |
| FR-19 | The tool shall map well-known static payload type numbers (0=PCMU, 8=PCMA, 9=G722, 18=G729) to their codec names even when no `a=rtpmap` is present. |

### 2.5 RTP Stream Correlation

| ID | Requirement |
|----|-------------|
| FR-20 | The tool shall identify RTP streams by the 5-tuple (src IP, src port, dst IP, dst port, protocol=UDP) combined with the SSRC field from the RTP header. |
| FR-21 | The tool shall associate an RTP stream with a SIP dialog when the stream's 5-tuple matches the media address/port extracted from the dialog's SDP. |
| FR-22 | The tool shall track each RTP stream independently (forward and reverse legs are separate streams correlated to the same dialog). |
| FR-23 | The tool shall collect per-packet RTP sequence number and timestamp for use in jitter and loss calculations. |
| FR-24 | The tool shall tolerate RTP packets arriving before the matching SIP `200 OK` is seen (late association) by buffering stream identity until dialog context is available. |

### 2.6 RTCP Statistics Ingestion

| ID | Requirement |
|----|-------------|
| FR-25 | The tool shall parse RTCP Sender Report (SR) and Receiver Report (RR) packets (RFC 3550 §6) found in the PCAP. |
| FR-26 | The tool shall extract from RTCP RR blocks: fraction lost (8-bit), cumulative packets lost (24-bit), interarrival jitter (32-bit), and last SR / delay since last SR fields. |
| FR-27 | The tool shall associate RTCP reports with the corresponding RTP stream via matching SSRC. |

### 2.7 Jitter Calculation

| ID | Requirement |
|----|-------------|
| FR-28 | The tool shall compute interarrival jitter per RFC 3550 §A.8 using the running estimator: `J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16`, where `D` is the difference between transit times of consecutive packets. |
| FR-29 | The tool shall report mean jitter (average of all per-packet estimates) for each RTP stream in the CDR, in milliseconds rounded to two decimal places. |

### 2.8 Packet Loss Calculation

| ID | Requirement |
|----|-------------|
| FR-30 | The tool shall compute packet loss percentage from RTP sequence numbers as: `loss% = (expected - received) / expected × 100`, where `expected = highest_seq - first_seq + 1`. |
| FR-31 | The tool shall supplement sequence-number-based loss with the RTCP RR cumulative loss field when RTCP data is available for the same SSRC, preferring the RTCP value as authoritative. |

### 2.9 MOS Estimation

| ID | Requirement |
|----|-------------|
| FR-32 | The tool shall compute a MOS-LQO estimate using a simplified E-model (ITU-T G.107) based on the following inputs: codec-baseline R-value, jitter-induced impairment (Id), and packet-loss impairment (Ie). |
| FR-33 | The tool shall use per-codec baseline R-values: G.711 (PCMU/PCMA) = 93.2, G.722 = 93.0, G.729 = 82.0, unknown codec = 80.0. |
| FR-34 | The tool shall derive MOS from R using the standard conversion: if R < 0, MOS = 1.0; if R > 100, MOS = 4.5; otherwise MOS = 1 + 0.035·R + R·(R−60)·(100−R)·7×10⁻⁶. |
| FR-35 | The MOS value recorded in the CDR shall be clamped to the range [1.0, 4.5] and rounded to two decimal places. |

### 2.10 CDR JSON Emission

| ID | Requirement |
|----|-------------|
| FR-36 | The tool shall emit exactly one JSON object per terminated SIP dialog to the configured output destination. |
| FR-37 | Each CDR JSON object shall contain at minimum the following fields: `call_id`, `caller`, `callee`, `start_time`, `end_time`, `duration_sec`, `codec`, `payload_type`, `mos`, `mean_jitter_ms`, `packet_loss_pct`, `ssrc`. |
| FR-38 | Time fields (`start_time`, `end_time`) shall be formatted as ISO 8601 UTC strings (e.g., `"2024-03-15T10:23:45.123Z"`). |
| FR-39 | When a dialog has two correlated RTP legs (caller→callee and callee→caller), the CDR shall include a `streams` array containing one entry per direction, each with per-stream `mos`, `mean_jitter_ms`, `packet_loss_pct`, and `ssrc`. |
| FR-40 | Dialogs that never reach `ESTABLISHED` state (e.g., unanswered calls) shall not produce a CDR. |
| FR-41 | The tool shall write each CDR as a newline-delimited JSON record (NDJSON) — one complete JSON object per line — to allow streaming consumption. |

---

## 3. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-01 | The project shall be written in C++20 and shall compile without warnings under `-std=c++20 -Wall -Wextra -Wpedantic`. |
| NFR-02 | The build system shall be CMake ≥ 3.20, with a top-level `CMakeLists.txt` that produces the main executable and the test suite as separate targets. |
| NFR-03 | The primary development and CI platform is Linux (Ubuntu 22.04 LTS or later); Windows and macOS portability is a stretch goal, not a requirement. |
| NFR-04 | The tool shall process a 100 MB PCAP file containing up to 10,000 SIP dialogs in under 30 seconds on a single core of a modern x86-64 CPU. |
| NFR-05 | Peak heap allocation shall not exceed 512 MB when processing the reference 100 MB PCAP file. |
| NFR-06 | The tool shall be single-threaded; no thread-safety guarantees are required. |
| NFR-07 | Third-party dependencies shall be managed via CMake `FetchContent` or vcpkg; no manual source-tree copying of dependencies is permitted. |
| NFR-08 | The unit and integration test suite shall use GoogleTest ≥ 1.14 and shall be runnable with `ctest`. |
| NFR-09 | Test coverage of SIP parser, dialog state machine, jitter calculator, MOS estimator, and CDR serialiser shall each have at minimum one positive and one negative unit test. |
| NFR-10 | The codebase shall carry an open-source licence (MIT, as already present in `LICENSE`). |

---

## 4. External Interfaces

### 4.1 CLI Interface

```
voipscope [OPTIONS] <pcap-file>

Options:
  -o, --output <file>   Write CDR NDJSON to <file> instead of stdout
  -v, --verbose         Print per-packet diagnostic messages to stderr
  --help                Print usage and exit
```

- Exit code 0 on success (including zero CDRs produced).
- Exit code 1 on any fatal error (bad file, unsupported format).

### 4.2 JSON CDR Schema (Illustrative)

```json
{
  "call_id": "abc123@192.168.1.10",
  "caller": "sip:alice@example.com",
  "callee": "sip:bob@example.com",
  "start_time": "2024-03-15T10:23:45.123Z",
  "end_time":   "2024-03-15T10:25:01.456Z",
  "duration_sec": 76.333,
  "codec": "PCMU",
  "payload_type": 0,
  "streams": [
    {
      "direction": "caller_to_callee",
      "ssrc": 305419896,
      "mos": 4.21,
      "mean_jitter_ms": 2.34,
      "packet_loss_pct": 0.12
    },
    {
      "direction": "callee_to_caller",
      "ssrc": 2882400018,
      "mos": 4.15,
      "mean_jitter_ms": 3.10,
      "packet_loss_pct": 0.00
    }
  ]
}
```

### 4.3 Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| PcapPlusPlus | ≥ 22.11 | PCAP file reading and Ethernet/IP/UDP dissection |
| nlohmann/json | ≥ 3.11 | JSON serialisation |
| GoogleTest | ≥ 1.14 | Unit and integration testing |

> **Note:** If PcapPlusPlus proves difficult to integrate via FetchContent, libpcap + custom Ethernet/IP/UDP dissection is an acceptable fallback; this decision is deferred to the System Architect.

---

## 5. Constraints and Assumptions

| ID | Statement |
|----|-----------|
| CA-01 | Only UDP transport is in scope for both SIP and RTP. TCP-carried SIP and TCP-carried RTP are explicitly out of scope. |
| CA-02 | Only a subset of SIP headers must be parsed: `Via`, `From`, `To`, `Call-ID`, `CSeq`, `Contact`, `Content-Type`, `Content-Length`. All other headers may be ignored. |
| CA-03 | The tool processes PCAP files offline; live capture interfaces are out of scope. |
| CA-04 | The SIP parser is written from scratch against RFC 3261; no third-party SIP stack (e.g., PJSIP, Sofia-SIP) may be used. |
| CA-05 | The MOS estimator is a simplified E-model approximation sufficient for portfolio demonstration; it does not need to be ITU-T G.107 certified. |
| CA-06 | The PCAP files used for integration testing are the open-licensed Wireshark SampleCaptures SIP traces, assumed to be freely redistributable for testing. |
| CA-07 | A dialog producing no RTP packets (e.g., a call that connects but sends no media) shall still emit a CDR with `mos: null`, `mean_jitter_ms: null`, `packet_loss_pct: null`. |
| CA-08 | Retransmitted SIP requests (same `Via` branch + CSeq) shall be detected and deduplicated to avoid duplicate state transitions. |

---

## 6. Out of Scope

| Item |
|------|
| SRTP / encrypted media streams |
| RTSP, H.323, MGCP, SCCP, or any other VoIP signalling protocol |
| TCP-carried SIP (RFC 3261 §18.1.2) |
| SIP over TLS (SIPS URI scheme) |
| ICE/STUN/TURN NAT traversal |
| Live packet capture from network interfaces |
| PCAP-NG file format (only classic PCAP is required; PCAP-NG is a stretch goal) |
| G.711 or codec waveform decoding / audio output |
| Graphical or web-based UI |
| Multi-threaded processing |
| Call forking (a single INVITE producing multiple 200 OKs) — first 200 OK wins |

---

## 7. Acceptance Criteria

The following conditions define a releasable v1.0:

| AC | Criterion |
|----|-----------|
| AC-01 | `cmake --build` completes without errors or warnings on GCC ≥ 12 and Clang ≥ 16 with `-std=c++20`. |
| AC-02 | `ctest` passes all unit tests (SIP parser, dialog FSM, jitter, MOS, CDR serialiser). |
| AC-03 | Running the tool against at least two Wireshark SampleCaptures SIP PCAP files produces valid NDJSON output, parseable by `python3 -m json.tool`. |
| AC-04 | A 2-minute, single-call PCAP file with known codec (G.711) produces a CDR with MOS in the range [3.5, 4.5] and packet loss within ±0.1% of the ground-truth value computed by Wireshark. |
| AC-05 | The tool exits with status code 1 and a human-readable error message when given a non-existent PCAP path. |
| AC-06 | No memory leaks reported by Valgrind (or AddressSanitizer) when processing any of the test PCAP files. |

---

## 8. Open Questions

| OQ | Question | Owner |
|----|----------|-------|
| OQ-01 | Should PCAP-NG format be supported in v1.0, or deferred to v1.1? PcapPlusPlus supports both, but the decision affects test asset selection. | Project Manager |
| OQ-02 | For dialogs with multiple codecs negotiated (e.g., G.711 + G.729 in SDP offer), should the CDR record only the first codec listed in the `m=` line, or all codecs? | Project Manager |
| OQ-03 | Should the `--output` flag support `-` (dash) as a synonym for stdout, or is stdout the only non-file output target needed? | Project Manager |
| OQ-04 | Is there a target maximum latency for producing the first CDR record after PCAP read begins, or is total-file throughput the only performance constraint? | Project Manager |
| OQ-05 | Should the tool handle multi-party conference calls (3+ participants sharing a Call-ID via Replaces header), or is two-party calls the only supported topology? | Project Manager |
| OQ-06 | Are the Wireshark SampleCaptures SIP PCAP files confirmed to carry actual RTP media (not just SIP signalling), so that MOS/jitter acceptance criteria in AC-04 are testable? | Project Manager |
| OQ-07 | Is there a preference for how incomplete dialogs (PCAP cut mid-call, no BYE observed) should be handled — silently dropped, or emitted as a partial CDR with a `"status": "incomplete"` flag? | Project Manager |
