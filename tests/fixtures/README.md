# Test Fixtures

Place Wireshark SampleCaptures SIP PCAP files here for integration testing.

Expected files:
- `sip_rtp_pcmu.pcap`  — A SIP/RTP capture containing at least one complete G.711
                          call (INVITE → 200 OK with SDP → RTP media → BYE).
                          Download from: https://wiki.wireshark.org/SampleCaptures#SIP_and_RTP

- `rtp_only.pcap`      — A capture containing RTP packets but no SIP messages.
                          Used to verify that zero CDRs are emitted without signalling.

If these files are absent, the integration tests that reference them will be skipped
automatically (using GTEST_SKIP()).

Licence note: Wireshark SampleCaptures are provided under various open licences.
Verify the licence of each file before redistributing this repository (CA-06).
