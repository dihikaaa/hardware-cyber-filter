"""
Breaks down a capture by protocol, to see how much traffic the filter covers.

Usage:
	python traffic_stats.py [input.pcap]   (default: data/normal.pcap)
"""
import sys
from collections import Counter
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6, rdpcap

from golden_filter import DATA_DIR


def uses_port(layer, port):
	return layer.sport == port or layer.dport == port


def count_traffic(pkts):
	"""Returns (network, transport, apps, coverage) Counters for a list of packets."""
	network, transport, apps, coverage = Counter(), Counter(), Counter(), Counter()
	for pkt in pkts:
		if IP in pkt:
			network["IPv4"] += 1
		elif IPv6 in pkt:
			network["IPv6"] += 1
		elif ARP in pkt:
			network["ARP"] += 1
		else:
			network["other"] += 1

		if TCP in pkt:
			transport["TCP"] += 1
			tcp = pkt[TCP]
			if uses_port(tcp, 443):
				apps["HTTPS (TCP 443)"] += 1
			elif uses_port(tcp, 80):
				apps["HTTP (TCP 80)"] += 1
			elif uses_port(tcp, 53):
				apps["DNS (TCP 53)"] += 1
			else:
				apps["other TCP"] += 1
		elif UDP in pkt:
			transport["UDP"] += 1
			udp = pkt[UDP]
			if uses_port(udp, 443):
				apps["QUIC / HTTP3 (UDP 443)"] += 1
			elif uses_port(udp, 53):
				apps["DNS (UDP 53)"] += 1
			elif uses_port(udp, 5353):
				apps["mDNS (UDP 5353)"] += 1
			else:
				apps["other UDP"] += 1
		elif ICMP in pkt:
			transport["ICMP"] += 1
		else:
			transport["other / none"] += 1

		if IP in pkt:
			coverage["golden_filter.py (all IPv4)"] += 1
			if TCP in pkt:
				coverage["filter.py (IPv4 + TCP only)"] += 1

	return network, transport, apps, coverage


def main():
	in_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR / "normal.pcap"
	pkts = rdpcap(str(in_file))
	total = len(pkts)
	network, transport, apps, coverage = count_traffic(pkts)

	print(f"Traffic breakdown: {in_file} ({total} packets)")
	for title, counter in [("Network layer", network), ("Transport layer", transport),
						   ("Applications (by port)", apps), ("Filter coverage", coverage)]:
		print(f"\n{title}")
		for name, n in counter.most_common():
			print(f"  {name:<30} {n:6}  {100 * n / total:5.1f}%")


if __name__ == "__main__":
	main()
