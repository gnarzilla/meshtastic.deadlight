# Deadlight Meshtastic Proxy

**Internet-over-LoRa: A practical bridge between Meshtastic mesh networks and the Internet**

[Why This Exists](#why-this-exists) · [Getting Started](#getting-started) · [Hardware](#hardware) · [Usage](#usage) · [Configuration](#configuration) · [How It Works](#how-it-works) · [Real-World Use Cases](#real-world-use-cases) · [Performance](#performance) · [Roadmap](#roadmap)

![Deadlight Meshtastic Proxy (no lora)](assets/output.gif)

## Overview

Deadlight Meshtastic Proxy transforms LoRa mesh networks into practical Internet gateways. Built on the [Deadlight Proxy](https://github.com/gnarzilla/proxy.deadlight) foundation, it adds transparent mesh networking capabilities that let any device on a Meshtastic mesh access standard Internet protocols—HTTP/HTTPS, email, DNS, and more—as if they had normal connectivity.

**What makes this different from other mesh solutions:**
- Standard protocols work unchanged (browse websites, send email, use apps)
- Transparent to applications (no special client software needed)
- Automatic fragmentation and reassembly for mesh transport
- Full MITM proxy capabilities for traffic inspection/modification
- Works with existing Meshtastic hardware and networks
- Truly off-grid: solar-powered nodes can provide connectivity across kilometers

Think of it as giving your Meshtastic network the capabilities of a satellite terminal, but running on $30 hardware and zero monthly fees.

## Why This Exists

Meshtastic networks are incredible for messaging and telemetry, but they weren't designed for general Internet access. Each protocol (HTTP, SMTP, DNS) would need custom mesh-aware implementations. This creates a chicken-and-egg problem: applications won't add mesh support without users, users won't adopt mesh without applications.

Deadlight solves this by sitting in the middle:
1. Mesh side: Speaks fluent Meshtastic (protobuf over LoRa serial)
2. Internet side: Speaks every protocol your applications already use
3. Bridges transparently: Fragments outgoing requests, reassembles incoming responses

**Result**: Your mesh network suddenly works with everything, email clients, web browsers, update tools, API services, all without modifying a single line of application code.

### Critical Scenarios This Enables

- **Disaster Response**: Coordinate rescue operations when cell towers are down
- **Rural Connectivity**: Share one satellite uplink across dozens of kilometers
- **Censorship Resistance**: Maintain communication during Internet blackouts
- **Off-Grid Networks**: Festival/protest/research networks that disappear when powered off
- **Development Projects**: Bring Internet services to areas with zero infrastructure

## Features

- **Universal Protocol Support**: HTTP/HTTPS, SMTP/IMAP, SOCKS5, WebSocket, FTP, DNS—if it runs over TCP/IP, it works
- **Transparent TLS Interception**: Inspect and cache HTTPS traffic to minimize mesh bandwidth
- **Intelligent Fragmentation**: Automatically chunks large requests/responses into ~220-byte Meshtastic packets
- **Store-and-Forward**: Delay-tolerant networking handles intermittent mesh connectivity
- **Connection Pooling**: Reuses upstream connections to reduce mesh overhead
- **Plugin Extensibility**: Add custom filters, caching, compression, or protocol handlers
- **Hardware Flexibility**: Works with USB serial, Bluetooth, or TCP-connected radios
- **Zero-Config Detection**: Auto-discovers Meshtastic devices on serial ports

## Getting Started

### Prerequisites

**Software**:
- Linux system (Raspberry Pi, x86 server, or ESP32-S3 with adequate RAM)
- GLib 2.0+, OpenSSL 1.1+
- GCC or Clang

**Hardware** (see [Hardware](#hardware) section for details):
- Meshtastic-compatible LoRa radio (ESP32-based recommended)
- Gateway node: Raspberry Pi or similar with Internet connection
- Client nodes: Any Meshtastic device (phone, handheld, custom)

### Quick Install

1. **Clone and build**:
   ```bash
   git clone https://github.com/gnarzilla/meshtastic.deadlight.git
   cd meshtastic.deadlight
   make clean && make UI=1
   ```

2. **Install CA certificate** (for HTTPS interception):
   ```bash
   # The proxy generates these on first run:
   # /etc/deadlight/ca.crt (install on clients)
   # /etc/deadlight/ca.key (keep secret)
   
   # Debian/Ubuntu
   sudo cp /etc/deadlight/ca/ca.crt /usr/local/share/ca-certificates/deadlight-mesh.crt
   sudo update-ca-certificates
   ```

3. **Connect your Meshtastic radio**:
   ```bash
   # Most devices appear as /dev/ttyACM0 or /dev/ttyUSB0
   ls -l /dev/tty*
   
   # Give yourself permission (or run as root)
   sudo usermod -a -G dialout $USER
   ```

4. **Run the proxy**:
   ```bash
   sudo ./bin/deadlight -c meshtastic.conf
   ```

5. **Configure mesh clients** to use the gateway's mesh address as their proxy (see [Usage](#usage)).

## Hardware

### Recommended Gateway Setup

**Option 1: Raspberry Pi Gateway** (most versatile)
- Raspberry Pi 4/5 (2GB+ RAM)
- RAK WisBlock Meshtastic Starter Kit or Heltec LoRa 32 V3
- Connection: USB serial or GPIO UART
- Power: 5V/3A supply or 12V solar panel + battery

**Option 2: ESP32-S3 All-in-One** (compact)
- Lilygo T-Deck or T-Watch S3
- 8MB+ PSRAM required for Deadlight
- Built-in LoRa radio and display
- Power: LiPo battery + solar panel

**Option 3: Industrial/Outdoor**
- Heltec Wireless Tracker or Mesh Node T114
- Weatherproof enclosure
- High-gain directional antenna (5-8 dBi)
- Solar panel + LiFePO4 battery for 24/7 operation

### Client Devices

Any Meshtastic-compatible device works:
- **Android/iOS**: Meshtastic app on phone (Bluetooth to radio)
- **Handheld**: RAK WisBlock, Lilygo T-Echo, Heltec LoRa 32
- **Custom**: ESP32 + LoRa module + Deadlight client build

### Radio Configuration

For best Internet gateway performance:
```
# In Meshtastic app or CLI
meshtastic --set lora.region US --set lora.modem_preset LONG_FAST
meshtastic --set lora.tx_power 30  # Maximum (check local regulations)
meshtastic --set lora.hop_limit 3  # Adjust for network size
```

## Usage

### Basic Configuration

Edit `meshtastic.conf`:

```ini
[core]
port = 8080
max_connections = 50
log_level = info

[meshtastic]
enabled = true
serial_port = /dev/ttyACM0
baud_rate = 115200
mesh_node_id = 0x12345678  # Your gateway's Meshtastic ID
fragment_size = 220        # Max payload per packet
ack_timeout = 30000        # 30 seconds for mesh ACKs
max_retries = 3

[ssl]
enable_interception = true
ca_cert = /etc/deadlight/ca/ca.crt
ca_key = /etc/deadlight/ca/ca.key

[network]
pool_max_per_host = 5      # Reuse connections aggressively
pool_idle_timeout = 600    # Keep idle connections longer
upstream_timeout = 120000  # Allow slow mesh responses
```

### Client Setup

**On mesh client devices**, configure proxy settings:

```bash
# Linux/Mac
export http_proxy=mesh://gateway-node-id:8080
export https_proxy=mesh://gateway-node-id:8080

# Or in applications:
# HTTP Proxy: gateway-node-id port 8080
# SOCKS5: gateway-node-id port 8080
```

**On Android** (using Meshtastic app + ProxyDroid):
1. Install ProxyDroid
2. Set proxy to gateway node's mesh ID
3. Connect Meshtastic app via Bluetooth

### Testing

```bash
# From mesh client node
curl -x mesh://gateway:8080 http://example.com

# Send email via mesh
curl -x mesh://gateway:8080 \
  --mail-from sender@example.com \
  --mail-rcpt recipient@example.com \
  --upload-file message.txt \
  smtp://smtp.gmail.com:587

# SOCKS5 for SSH over mesh
ssh -o ProxyCommand="nc -X 5 -x gateway:8080 %h %p" user@remote-server
```

## Configuration

### Optimizing for Mesh Performance

**Bandwidth Conservation**:
```ini
[plugins]
# Enable aggressive compression
compressor.enabled = true
compressor.min_size = 512
compressor.algorithms = gzip,brotli

# Cache aggressively to reduce mesh traffic
cache.enabled = true
cache.max_size_mb = 500
cache.ttl_hours = 24
```

**Latency Tolerance**:
```ini
[meshtastic]
# Longer timeouts for multi-hop paths
ack_timeout = 60000
max_retries = 5

[network]
# Don't timeout on slow mesh responses
upstream_timeout = 300000  # 5 minutes
connection_timeout = 180000  # 3 minutes
```

**Priority Shaping**:
```ini
[plugins]
ratelimiter.enabled = true
# Reserve bandwidth for critical services
ratelimiter.priority_high = smtp,imap,dns
ratelimiter.priority_low = http_video,http_images
```

### Advanced: Multi-Gateway Setup

For redundancy, run multiple gateways:

```ini
[meshtastic]
gateway_mode = true
announce_interval = 300  # Announce availability every 5 min
prefer_local = true      # Route via nearest gateway
load_balance = true      # Distribute across gateways
```

## How It Works

### Architecture Overview

```
┌─────────────┐                  ┌──────────────┐                ┌──────────┐
│ Mesh Client │                  │   Deadlight  │                │ Internet │
│   (Phone)   │  LoRa Packets    │   Gateway    │   TCP/IP       │ Services │
│             ├─────────────────>│              ├───────────────>│          │
│ Meshtastic  │  (868/915 MHz)   │ - Fragment   │                │  HTTP    │
│     App     │                  │ - Reassemble │                │  SMTP    │
│             │<─────────────────┤ - TLS Proxy  │<───────────────┤  IMAP    │
└─────────────┘                  └──────────────┘                └──────────┘
                                         │
                                         │ Also bridges:
                                         ├─> Other mesh nodes
                                         ├─> Offline message store
                                         └─> Satellite uplink (if available)
```

### Packet Flow

1. **Request Fragmentation**:
   ```
   HTTP GET request (1500 bytes)
   └─> Split into 7 Meshtastic packets (~220 bytes each)
   └─> Each tagged with sequence number + session ID
   └─> Sent hop-by-hop through mesh to gateway
   ```

2. **Gateway Reassembly**:
   ```
   Gateway receives packets out-of-order
   └─> Buffers and sorts by sequence number
   └─> Detects missing packets, requests retransmit
   └─> Reassembles into original HTTP request
   └─> Proxies to Internet normally
   ```

3. **Response Fragmentation**:
   ```
   HTTP response (50KB HTML)
   └─> Gateway fragments into ~230 packets
   └─> Sends with flow control (wait for ACKs)
   └─> Client reassembles and delivers to application
   ```

### Protocol Detection

Deadlight auto-detects protocols by inspecting initial bytes:
- `GET / HTTP/1.1` → HTTP handler → Fragment and forward
- `CONNECT example.com:443` → HTTPS tunnel → TLS interception optional
- `EHLO` → SMTP handler → Email relay
- `\x05` → SOCKS5 handler → Transparent tunneling

### Security Model

**Encryption layers**:
1. **LoRa PHY**: AES-256 encryption at Meshtastic layer
2. **TLS**: End-to-end between client and final destination
3. **Proxy MITM** (optional): Deadlight can terminate TLS for caching/inspection

**Trust model**:
- Gateway has root CA (can inspect HTTPS if enabled)
- Mesh uses Meshtastic's channel encryption (PSK)
- Clients trust gateway CA (install certificate)

**Privacy**: Mesh node IDs are pseudonymous. For operational security in sensitive deployments, use throwaway node IDs and rotate channel keys.

## Real-World Use Cases

### Disaster Response Network

**Scenario**: Earthquake destroys cell infrastructure

**Setup**:
- Solar-powered Deadlight gateway at field hospital (has satellite uplink)
- Rescue teams carry Meshtastic handhelds (10km range)
- Coordinate via email, share maps, update databases

**Result**: Teams stay connected across 50+ square km with zero functioning infrastructure.

### Rural Community Internet

**Scenario**: Village 30km from nearest fiber connection

**Setup**:
- One gateway node at village center (WiMAX or satellite backhaul)
- Residents install Meshtastic radios on roofs
- Multi-hop mesh covers entire valley

**Result**: 100+ households share single Internet connection. Cost: ~$50 per household for radio, no monthly fees.

### Protest/Festival Network

**Scenario**: Large gathering needs coordination without relying on government-controlled networks

**Setup**:
- Organizers carry Deadlight gateways with LTE failover
- Attendees use Meshtastic app on phones (Bluetooth to radios)
- Network disappears when powered down (no logs, no traces)

**Result**: Thousands communicate freely. Network evaporates forensically when disassembled.

### Journalist in Blackout Zone

**Scenario**: Government shuts down Internet during protests

**Setup**:
- Journalist has Meshtastic radio + Deadlight on laptop
- Connects to mesh gateway run by colleague 15km away (who has working connection)
- Files stories via mesh SMTP relay

**Result**: Censorship bypassed. Reports reach editors despite blackout.

## Performance

### Throughput Expectations

**LoRa Physical Layer** (LONG_FAST preset):
- Raw bitrate: ~5.5 kbps
- Effective throughput: ~3-4 kbps (after protocol overhead)
- Latency: 500ms - 5s per hop

**Real-World Application Performance**:
- **Email**: 10-20 emails/minute (text-heavy)
- **Web browsing**: 30-60 seconds per page (with caching)
- **DNS**: ~2 seconds per lookup (cache aggressively!)
- **API calls**: 5-10 seconds per request
- **File transfer**: ~400 bytes/sec (~1.4 MB/hour)

**Optimization tips**:
- Enable compression (3-10x improvement for text)
- Use image proxies (reduce image sizes before meshing)
- Cache everything possible (DNS, API responses, static assets)
- Batch requests (avoid chatty protocols)

### Scaling Considerations

**Single Gateway**:
- Handles 10-20 concurrent mesh clients comfortably
- Limited by LoRa airtime regulations (1% duty cycle in EU)

**Multi-Gateway Mesh**:
- Horizontally scalable (add more gateways = more capacity)
- Load balances automatically across available gateways

**Bottlenecks**:
1. LoRa duty cycle (legal limit on transmission time)
2. Mesh hop count (>4 hops = diminishing returns)
3. Gateway uplink bandwidth (satellite is typically the constraint)

## Roadmap

### v1.1 (Q1 2026)
- Adaptive fragmentation (adjust packet size based on mesh conditions)
- Intelligent retry with exponential backoff
- Pre-fetching for common resources
- Android client app (native Deadlight on-device)

### v1.2 (Q2 2026)
- Multi-gateway coordination protocol
- Offline message queue (store-and-forward when gateway unreachable)
- Bandwidth shaping per client/protocol
- WebRTC signaling over mesh (for peer-to-peer voice/video)

### v2.0 (Future)
- Full IPv6 support
- Meshtastic firmware integration (run Deadlight directly on ESP32)
- Satellite backhaul optimization (Starlink, Iridium)
- Machine learning for mesh route prediction

## Contributing

This is a specialized fork of [Deadlight Proxy](https://github.com/gnarzilla/proxy.deadlight). Contributions welcome:

- **Protocol optimizations**: Improve mesh efficiency
- **Hardware testing**: Validate on different radio platforms
- **Real-world deployments**: Share your use cases and lessons learned
- **Documentation**: Especially non-English guides for global use

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## Support & Community

- **Issues**: [GitHub Issues](https://github.com/gnarzilla/deadlight-meshtastic/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gnarzilla/deadlight-meshtastic/discussions)
- **Matrix**: `#deadlight-mesh:matrix.org`
- **Development**: [ko-fi/gnarzilla](https://ko-fi.com/gnarzilla)

## Legal & Safety

**Radio Regulations**: LoRa operates in license-free ISM bands, but transmission power and duty cycle are regulated. Ensure compliance with your local regulations (FCC Part 15 in US, ETSI EN 300-220 in EU).

**Encryption Export**: This software includes strong cryptography. Check export restrictions if deploying internationally.

**Responsible Use**: This tool can bypass censorship and provide communication in emergencies. It can also be misused. Use ethically and legally. The authors are not responsible for misuse.

**Privacy Notice**: Meshtastic mesh networks are pseudonymous, not anonymous. For operational security in high-risk environments, use proper opsec practices (rotate node IDs, use ephemeral keys, avoid PII in mesh metadata).

## License

MIT License – see [LICENSE](docs/LICENSE)

Includes:
- [Meshtastic Protobufs](https://github.com/meshtastic/protobufs) (GPL v3)
- [nanopb](https://jpa.kapsi.fi/nanopb/) (zlib license)

---

**Status**: testing-ready v1.0.0 | **Maintained by**: [@gnarzilla](https://github.com/gnarzilla)
