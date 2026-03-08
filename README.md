# WireTap

WireTap is a lightweight network packet sniffer written in Go similar to `tcpdump`. It utilizes Linux `AF_PACKET` and implements an asynchronous DNS resolver to ensure that hostname lookups never block the real-time packet stream.

## Supported Packet Types

WireTap provides deep visibility into several layers of the OSI model. Here is what you can see:

### Network & Infrastructure

- `Ethernet`: Captures raw frames, specifically reporting MAC addresses and EtherTypes.
- `ARP`: Monitors Address Resolution Protocol requests and replies, showing you exactly "who has" an IP and who is claiming it.
- `DHCP`: Tracks `DHCPv4` transactions, revealing device hostnames, requested IPs, and message types (Discover, Request, etc.).
- `IGMP`: Observes multicast group management traffic.

### Transport Layer

- `TCP`: Reports source/destination ports, IP versions (v4/v6), and payload lengths.
- `UDP`: Monitors connectionless traffic. (Note: DNS-related UDP traffic is automatically handed off to the specialized DNS parser).

### Diagnostic & Control

- `ICMPv4` / `ICMPv6`: Visualizes "pings," destination unreachable messages, and other network control signals.

### Application Layer

- `DNS`: It breaks down queries and responses. It tracks: queries for specific domains and record types (A, AAAA, etc.), replies, including resolved `IP`s and `CNAME`aliases and esponse codes (e.g., `NXDOMAIN`) to help troubleshoot failing lookups.

## Usage

Ensure you have libpcap headers installed on your system, then build the binary and run it:

```bash
go build -o wiretap .
sudo ./wiretap
```

Note: running `WireTap` requires elevated privileges (`CAP_NET_RAW`) to access the network interface.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
