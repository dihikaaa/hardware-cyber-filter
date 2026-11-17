"""
Software IDS and golden reference model for the hardware packet filter (v2,
dual-stack: IPv4 and IPv6).

It applies the same 7 rules as the v2 Verilog module, in the same order,
including the SYN and ICMP/ICMPv6 flood counters. For every dropped packet it
raises an alert, and at the end it prints a summary of alerts by type.

The output has two uses:
  1. A software IDS demo: run it on a capture and read the alerts.
  2. A golden model: export_vectors.py turns its decisions into the
     expected results for the Verilog testbench.

Usage:
	python golden_filter.py [input.pcap] [output.csv] [--alerts | --no-alerts]
	(defaults: data/test_packets.pcap, data/decisions.csv)

	Alert boxes are printed automatically for small captures (<= 100 packets).
	--alerts forces them on, --no-alerts turns them off.
"""
import csv
import ipaddress
import sys
from collections import Counter
from pathlib import Path

from scapy.all import IP, TCP, UDP, IPv6, rdpcap

DATA_DIR = Path(__file__).parent / "data"

# ---- Rules: keep these in sync with the Verilog parameters -----------------
# Addresses are stored as ipaddress objects, so "2001:db8::bad:1" and its
# long form compare equal. IPv4 and IPv6 objects never compare equal.
BLOCKED_SRC_IPS = {ipaddress.ip_address(a) for a in (
	"192.168.1.100", "10.0.0.50",          # IPv4
	"2001:db8::bad:1", "2001:db8::bad:2",  # IPv6 (documentation range)
)}
BLOCKED_DST_IPS = {ipaddress.ip_address(a) for a in (
	"192.168.1.200",                       # IPv4
	"2001:db8::200",                       # IPv6
)}
BLOCKED_PORTS   = {23}                    # Telnet
SYN_THRESHOLD   = 4                       # the 4th SYN in a window is dropped
ICMP_THRESHOLD  = 4                       # the 4th ICMP in a window is dropped
WINDOW_SIZE     = 8                       # counters clear every 8 IP packets (v4 + v6)

PROTO_ICMP   = 1
PROTO_TCP    = 6
PROTO_UDP    = 17
PROTO_ICMPV6 = 58
TCP_SYN_BIT = 0x02

FIELDS = ["ip_version", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_syn"]
ALERT_BOX_LIMIT = 100


def upper_protocol(ip6):
	"""Final Next Header of an IPv6 packet, after any extension headers."""
	if TCP in ip6:
		return PROTO_TCP
	if UDP in ip6:
		return PROTO_UDP
	layer = ip6.payload
	while layer is not None and layer.name != "NoPayload":
		if type(layer).__name__.startswith("ICMPv6"):
			return PROTO_ICMPV6
		layer = layer.payload
	nh = ip6.nh
	while True:                       # walk extension headers Scapy decoded
		nxt = ip6.payload
		if not hasattr(nxt, "nh") or nxt.name == "NoPayload":
			return nh
		nh, ip6 = nxt.nh, nxt


def extract_fields(pkt):
	"""Header fields the filter looks at, or None if the packet isn't IP."""
	if IP in pkt:
		ip, version, proto = pkt[IP], 4, pkt[IP].proto
	elif IPv6 in pkt:
		ip, version = pkt[IPv6], 6
		proto = upper_protocol(ip)
	else:
		return None
	src_port = dst_port = 0          # ports only exist for TCP/UDP
	tcp_syn = 0
	if proto == PROTO_TCP and TCP in ip:
		src_port, dst_port = ip[TCP].sport, ip[TCP].dport
		tcp_syn = 1 if int(ip[TCP].flags) & TCP_SYN_BIT else 0
	elif proto == PROTO_UDP and UDP in ip:
		src_port, dst_port = ip[UDP].sport, ip[UDP].dport
	return {
		"ip_version": version,
		"src_ip":   ip.src,
		"dst_ip":   ip.dst,
		"protocol": proto,
		"src_port": src_port,
		"dst_port": dst_port,
		"tcp_syn":  tcp_syn,
	}


def is_icmp(fields):
	"""ICMP is protocol 1 in IPv4 and Next Header 58 (ICMPv6) in IPv6."""
	want = PROTO_ICMPV6 if fields["ip_version"] == 6 else PROTO_ICMP
	return fields["protocol"] == want


class FloodMonitor:
	"""Software copy of the hardware's packet-count window.

	The hardware decides with the counter values from BEFORE the current
	packet, then updates the counters at the clock edge. This class does
	the same: call is_*_flood() first, then update().
	"""

	def __init__(self):
		self.window = 0
		self.syn = 0
		self.icmp = 0

	def is_syn_flood(self, fields):
		return self._is_syn(fields) and self.syn >= SYN_THRESHOLD - 1

	def is_icmp_flood(self, fields):
		return is_icmp(fields) and self.icmp >= ICMP_THRESHOLD - 1

	def update(self, fields):
		if self.window == WINDOW_SIZE - 1:      # last packet of the window
			# Like the v2 RTL: the counters restart, and the packet that
			# arrives on the wrap is counted in the NEW window.
			self.window = 0
			self.syn  = int(self._is_syn(fields))
			self.icmp = int(is_icmp(fields))
		else:
			self.window += 1
			self.syn  += self._is_syn(fields)
			self.icmp += is_icmp(fields)

	@staticmethod
	def _is_syn(fields):
		return fields["protocol"] == PROTO_TCP and fields["tcp_syn"] == 1


def decide(fields, monitor):
	"""Rules are checked top to bottom; the first match wins."""
	if ipaddress.ip_address(fields["src_ip"]) in BLOCKED_SRC_IPS:
		return "DROP", "blocked source IP"
	if ipaddress.ip_address(fields["dst_ip"]) in BLOCKED_DST_IPS:
		return "DROP", "blocked destination IP"
	if fields["dst_port"] in BLOCKED_PORTS:
		return "DROP", "blocked port"
	if fields["protocol"] == PROTO_UDP:
		return "DROP", "UDP blocked"
	if monitor.is_syn_flood(fields):
		return "DROP", "SYN flood"
	if monitor.is_icmp_flood(fields):
		return "DROP", "ICMP flood"
	return "ALLOW", ""


class PacketFilter:
	"""Holds the flood counters so they carry over from packet to packet."""

	def __init__(self):
		self.monitor = FloodMonitor()

	def classify(self, pkt):
		"""Returns (fields, action, reason). action is ALLOW, DROP or SKIP."""
		fields = extract_fields(pkt)
		if fields is None:
			return None, "SKIP", "not IP"
		action, reason = decide(fields, self.monitor)
		self.monitor.update(fields)          # every IP packet counts, like packet_valid
		return fields, action, reason


def proto_name(n, version=4):
	if n == PROTO_ICMPV6 and version == 6:
		return "ICMPv6"
	return {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(n, str(n))


def print_alert(i, fields, reason):
	syn = " (SYN)" if fields["tcp_syn"] else ""
	print("  +---------------------------------------------+")
	print(f"  | ALERT  packet {i:<5} {reason.upper():<24}|")
	print(f"  |   source      {fields['src_ip']}:{fields['src_port']:<{29 - len(fields['src_ip'])}}|")
	print(f"  |   destination {fields['dst_ip']}:{fields['dst_port']:<{29 - len(fields['dst_ip'])}}|")
	print(f"  |   protocol    {proto_name(fields['protocol'], fields['ip_version']) + syn:<30}|")
	print("  |   action      PACKET DROPPED                |")
	print("  +---------------------------------------------+")


def main():
	args = [a for a in sys.argv[1:] if not a.startswith("--")]
	flags = {a for a in sys.argv[1:] if a.startswith("--")}
	in_file  = Path(args[0]) if len(args) > 0 else DATA_DIR / "test_packets.pcap"
	out_file = Path(args[1]) if len(args) > 1 else DATA_DIR / "decisions.csv"

	pkts = rdpcap(str(in_file))
	if "--alerts" in flags:
		show_boxes = True
	elif "--no-alerts" in flags:
		show_boxes = False
	else:
		show_boxes = len(pkts) <= ALERT_BOX_LIMIT

	pf = PacketFilter()
	counts = Counter()
	alerts = Counter()
	rows = []
	for i, pkt in enumerate(pkts):
		fields, action, reason = pf.classify(pkt)
		counts[action] += 1
		if fields is None:
			print(f"{i:4}  {pkt.summary()}  SKIP ({reason})")
			fields = dict.fromkeys(FIELDS, "")
		else:
			syn = " SYN" if fields["tcp_syn"] else ""
			print(f"{i:4}  {fields['src_ip']}:{fields['src_port']} --> "
				  f"{fields['dst_ip']}:{fields['dst_port']}  "
				  f"{proto_name(fields['protocol'], fields['ip_version'])}{syn}  {action} {reason}".rstrip())
			if action == "DROP":
				alerts[reason] += 1
				if show_boxes:
					print_alert(i, fields, reason)
		rows.append({"index": i, **fields, "action": action, "reason": reason})

	out_file.parent.mkdir(exist_ok=True)
	with open(out_file, "w", newline="") as f:
		writer = csv.DictWriter(f, fieldnames=["index", *FIELDS, "action", "reason"])
		writer.writeheader()
		writer.writerows(rows)

	print("\n================ IDS SUMMARY ================")
	print(f"  Packets read : {len(pkts)}")
	print(f"  Allowed      : {counts['ALLOW']}")
	print(f"  Dropped      : {counts['DROP']}")
	print(f"  Skipped      : {counts['SKIP']}  (not IP: ARP and others)")
	if alerts:
		print("\n  Alerts by type:")
		for reason, n in alerts.most_common():
			print(f"    {reason:<24} {n:6}")
	print("=============================================")
	print(f"Decisions saved to {out_file}")


if __name__ == "__main__":
	main()
