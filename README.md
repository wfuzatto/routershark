# RouterShark

Web packet analyzer for RouterOS TZSP streams. It receives packets directly from MikroTik RouterOS over UDP/TZSP, stores every raw Ethernet frame in PostgreSQL, broadcasts summaries live through WebSocket, and uses TShark as a server-side protocol-dissection engine. No WinPcap/Npcap is required.

## Current feature set

- RouterOS TZSP receiver on UDP/37008
- Multiple routers distinguished by source IP
- Router source-IP allowlist
- Raw full-frame persistence in PostgreSQL (`bytea`)
- Batched database ingestion
- Ethernet / ARP / IPv4 / IPv6 / TCP / UDP / ICMP summary parsing
- Live packet table over WebSocket
- Wireshark/TShark full packet decode to JSON
- Packet bytes / hex view
- Wireshark display-filter validation and execution on a selected time window
- Follow TCP/UDP/TLS/HTTP/HTTP2/QUIC through TShark API
- Protocol statistics
- Search by IP / packet info plus native protocol/port filters in the API
- PCAP export for arbitrary time windows
- Token-protected API
- Docker deployment

## Architecture

```text
RouterOS packet sniffer
        |
        | TZSP / UDP 37008
        v
+---------------------+
| RouterShark backend |
|  TZSP collector     |
|  gopacket summary   |
|  WebSocket live     |
|  REST API           |
|  TShark dissector   |
+---------+-----------+
          |
          v
 +-------------------+
 | PostgreSQL        |
 | raw frame + index |
 +-------------------+
          ^
          |
      React UI
```

## Production note

TZSP itself does not authenticate the sender. For an Internet-hosted collector, use at least `ROUTER_IP_ALLOWLIST` plus a host firewall allowing UDP/37008 only from trusted addresses. Prefer transporting the stream over a WireGuard tunnel and binding the allowlist to the routers' tunnel addresses.

## Start

```bash
cp .env.example .env
# Edit passwords, API token and RouterOS public/tunnel IPs.
docker compose up -d --build
```

Open `http://SERVER_IP:8088`.

If `API_TOKEN` is configured, set it in the browser console once:

```js
localStorage.setItem('routershark_token','YOUR_TOKEN'); location.reload();
```

## RouterOS

Basic RouterOS 7 configuration:

```routeros
/tool sniffer set streaming-enabled=yes streaming-server=SERVER_IP streaming-port=37008 filter-stream=yes only-headers=no
/tool sniffer start
```

You can restrict traffic before it crosses the WAN, for example:

```routeros
/tool sniffer set filter-interface=ether1 filter-direction=any filter-stream=yes
```

Stop:

```routeros
/tool sniffer stop
/tool sniffer set streaming-enabled=no
```

## REST examples

Recent packets:

```bash
curl -H 'Authorization: Bearer TOKEN' 'http://SERVER:8088/api/packets?limit=100&protocol=TCP&port=443'
```

Full protocol tree:

```bash
curl -H 'Authorization: Bearer TOKEN' 'http://SERVER:8088/api/packets/PACKET_UUID/decode'
```

Wireshark display filter across five minutes:

```bash
curl -G -H 'Authorization: Bearer TOKEN' \
  --data-urlencode 'filter=tcp.port == 443 && ip.addr == 10.0.0.1' \
  'http://SERVER:8088/api/display-filter'
```

Follow TCP stream 0:

```bash
curl -G -H 'Authorization: Bearer TOKEN' \
  --data-urlencode 'proto=tcp' --data-urlencode 'mode=utf-8' --data-urlencode 'stream=0' \
  'http://SERVER:8088/api/follow'
```

Export last five minutes:

```bash
curl -H 'Authorization: Bearer TOKEN' -o capture.pcap \
  'http://SERVER:8088/api/export.pcap?limit=20000'
```

## Scaling path

For tens of thousands of packets per second continuously, keep PostgreSQL for metadata/control and move long-term packet bodies to object storage or a compressed packet store, or replace the analytical index with ClickHouse. The current PostgreSQL design intentionally satisfies the requirement that every packet be persisted in a database and is appropriate for a first production deployment with sane RouterOS capture filters and retention.

## Wireshark compatibility

RouterShark relies on TShark for deep protocol dissection and display-filter semantics. That gives access to the Wireshark dissector ecosystem without using WinPcap/Npcap. When distributing a combined product, review Wireshark/TShark GPL licensing obligations.
