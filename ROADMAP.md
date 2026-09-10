# RouterShark feature roadmap

The repository already implements the capture/storage/live-analysis core. A literal 1:1 implementation of every Wireshark desktop dialog is a large product, so the remaining UI features should reuse TShark/Wireshark analysis primitives instead of reimplementing dissectors.

## Implemented in this build

- TZSP live ingest from RouterOS
- Persistent raw packet database
- Live packet list
- Common L2/L3/L4 columns
- Full TShark protocol tree per packet
- Hex bytes
- Wireshark display-filter engine over stored ranges
- Follow-stream backend
- PCAP export
- Protocol statistics
- Multi-router source separation
- API authentication and RouterOS source allowlist
- Retention cleanup

## Next UI modules

1. Conversations and endpoints (Ethernet / IPv4 / IPv6 / TCP / UDP)
2. I/O graphs and throughput/PPS graphs
3. Expert Information and malformed/retransmission summaries
4. Coloring rules compatible with display filters
5. Follow TCP / UDP / TLS / HTTP / HTTP2 / QUIC dialog
6. DNS resolution and optional local name database
7. Packet comments, bookmarks, tags and saved investigations
8. HTTP object extraction and file/object export
9. TLS key-log upload for authorized decryption workflows
10. VoIP calls / SIP / RTP analysis and RTP stream playback
11. TCP stream graphs, RTT, sequence and window scaling views
12. Capture profiles per RouterOS and saved server-side filters
13. PCAP/PCAPNG import into the same database
14. Scheduled retention/storage policies and per-router quotas
15. User accounts, RBAC, audit log and organization/tenant support
16. ClickHouse/object-storage tier for very high sustained packet rates
