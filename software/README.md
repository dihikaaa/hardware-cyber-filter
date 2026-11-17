# Software: Python IDS and golden model

A small intrusion detection system (IDS) written in Python with Scapy. It
applies the same 7 rules as the hardware packet filter, to both IPv4 and IPv6
packets, prints an alert for every dropped packet, and ends with a summary.

It is also the **golden reference model** for the Verilog design: it builds
test packets, decides ALLOW or DROP for each one, and exports those decisions
as test vectors that a Verilog testbench can check the hardware against.

## Setup

```bash
cd software
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

None of these scripts need `sudo`: they read and write `.pcap` files and never
send packets on the network.

## Run in this order

| Step | Command | Output |
|---|---|---|
| 1. Build the test packets and check the rules | `python make_tests.py` | `data/test_packets.pcap`, prints 45/45 PASS |
| 2. Run the IDS (alerts + summary) | `python golden_filter.py` | `data/decisions.csv` |
| 3. Export Verilog test vectors | `python export_vectors.py` | `data/packets.hex`, `data/expected.txt`, `data/vectors.txt` |
| 4. Protocol breakdown of a capture | `python traffic_stats.py your_capture.pcap` | printed table |

Run the IDS on your own capture:

```bash
python golden_filter.py capture.pcap capture_decisions.csv --no-alerts
```

Alert boxes print automatically for captures of 100 packets or fewer;
`--alerts` forces them on and `--no-alerts` turns them off.

## Filter rules

Defined at the top of `golden_filter.py`. They are checked in order and the
first match wins. Keep them in sync with the Verilog parameters.

| # | Rule | Checked on | Action |
|---|---|---|---|
| 1 | Blocked source address | IPv4 192.168.1.100, 10.0.0.50; IPv6 2001:db8::bad:1, 2001:db8::bad:2 | DROP |
| 2 | Blocked destination address | IPv4 192.168.1.200; IPv6 2001:db8::200 | DROP |
| 3 | Blocked port | destination port 23 (Telnet) | DROP |
| 4 | Blocked protocol | UDP (17), a demo policy | DROP |
| 5 | SYN flood | 4th TCP SYN in an 8-packet window | DROP |
| 6 | ICMP flood | 4th ICMP (IPv4 protocol 1) or ICMPv6 (IPv6 next header 58) in an 8-packet window | DROP |
| 7 | Everything else | | ALLOW |

How the flood counters work, the same way as the hardware:

- The window is 8 IP packets, IPv4 and IPv6 counted together. Non-IP packets
  (ARP and others) are skipped and not counted.
- A counter holds the packets seen **before** the current one, so the check is
  `count >= THRESHOLD - 1`, which drops the 4th packet.
- When the window wraps, the counters restart and the packet that arrives on
  the wrap is counted in the new window.
- IPv6 extension headers are followed to find the real upper-layer protocol.

## Test-vector format

One line per IP packet in `packets.hex`, 288 bits = 72 hex characters:

| Bits | Field | Width |
|---|---|---|
| `[287:160]` | source address (IPv4 in the low 32 bits) | 128 |
| `[159:32]` | destination address (IPv4 in the low 32 bits) | 128 |
| `[31:24]` | protocol / IPv6 next header | 8 |
| `[23:16]` | flags: bit 16 = `tcp_syn`, bit 17 = `is_ipv6` | 8 |
| `[15:0]` | destination port (0 if not TCP/UDP) | 16 |

`expected.txt` has one line per vector: `1` = DROP, `0` = ALLOW. Feed the
vectors to the testbench **in order**, because the flood counters carry over
from packet to packet.

```verilog
reg [287:0] packets  [0:N-1];  $readmemh("packets.hex", packets);
reg         expected [0:N-1];  $readmemb("expected.txt", expected);
```

## Results

- `make_tests.py`: **45/45** test packets pass (static rules, SYN and ICMP
  floods, window reset, IPv6 rules, ICMPv6 flood, IPv6 SYN flood, and cases
  that check IPv4 and IPv6 rules never mix).
- Cross-check: all **44/44** IP vectors give the same decision in Python and in
  the dual-stack Verilog design (simulated with Icarus Verilog).
- On a 2000-packet home Wi-Fi capture, the IDS inspected 1996 packets (4 were
  ARP). The demo "block all UDP" rule dropped 1394 of them, because browsers
  use QUIC over UDP, and one burst of normal connections tripped the SYN flood
  rule. Lab rules need tuning on real traffic.

## Note on the RTL version

This model matches the **dual-stack (IPv4 + IPv6)** packet filter with the
`>= THRESHOLD - 1` comparison (4th packet dropped). The `rtl/` folder in this
repository currently holds the IPv4-only version with `>= THRESHOLD`
(5th packet dropped), so the two will disagree on flood packets until the RTL
is updated.

## Files

| File | Purpose |
|---|---|
| `golden_filter.py` | The IDS and golden model: rules, flood counters, alerts, summary |
| `make_tests.py` | Builds 45 test packets and checks each against the expected result |
| `export_vectors.py` | Turns a pcap into Verilog test vectors |
| `traffic_stats.py` | Protocol breakdown of a capture (IPv4/IPv6, TCP/UDP/ICMP, apps by port) |
| `data/` | Generated test packets, decisions and vectors |
| `requirements.txt` | Python dependency (Scapy) |
