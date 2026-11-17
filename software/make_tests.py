"""
Builds the test packets for the filter (v2 rules, IPv4 and IPv6) and saves
them to a pcap.

Packets are only written to a file, never sent on the network.
After saving, the packets are run IN ORDER through golden_filter and each
result is checked against the expected one. Order matters because the SYN
and ICMP flood counters carry over between packets, and they clear every
8 IP packets (the window), IPv4 and IPv6 counted together.

Usage:
	python make_tests.py [output.pcap]   (default: data/test_packets.pcap)
"""
import sys
from pathlib import Path

from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Ether, ICMPv6EchoRequest, Raw, wrpcap

from golden_filter import DATA_DIR, PacketFilter

# Fixed MACs so Scapy never tries to look them up on the network
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

CLIENT = "10.0.0.5"
SERVER = "203.0.113.10"          # documentation-only address range (TEST-NET-3)

_sport = 50000


def eth():
	return Ether(src=SRC_MAC, dst=DST_MAC)


def tcp(dport, src=CLIENT, dst=SERVER, flags="PA"):
	"""TCP packet. flags="PA" is normal data; Scapy's default would be a SYN."""
	global _sport
	_sport += 1
	return eth()/IP(src=src, dst=dst)/TCP(sport=_sport, dport=dport, flags=flags)


def syn(src=CLIENT, dport=80):
	return tcp(dport, src=src, flags="S")


def ping(src=CLIENT):
	return eth()/IP(src=src, dst=SERVER)/ICMP()


# IPv6 addresses from the 2001:db8::/32 documentation range
V6_CLIENT = "2001:db8::5"
V6_SERVER = "2001:db8::10"


def tcp6(dport, src=V6_CLIENT, dst=V6_SERVER, flags="PA"):
	global _sport
	_sport += 1
	return eth()/IPv6(src=src, dst=dst)/TCP(sport=_sport, dport=dport, flags=flags)


def syn6():
	return tcp6(80, flags="S")


def ping6():
	return eth()/IPv6(src=V6_CLIENT, dst=V6_SERVER)/ICMPv6EchoRequest()


# (description, packet, expected action)
# Comments show the window position (0-7) of each IPv4 packet.
TESTS = [
	# Window 1: static rules
	("normal HTTPS",                             tcp(443),                          "ALLOW"),  # 0
	("Telnet (blocked port 23)",                 tcp(23),                           "DROP"),   # 1
	("blocked source IP 192.168.1.100",          tcp(80, src="192.168.1.100"),      "DROP"),   # 2
	("blocked source IP 10.0.0.50",              tcp(80, src="10.0.0.50"),          "DROP"),   # 3
	("blocked destination IP 192.168.1.200",     tcp(80, dst="192.168.1.200"),      "DROP"),   # 4
	("UDP DNS query (all UDP blocked)",
		eth()/IP(src=CLIENT, dst="8.8.8.8")/UDP(sport=53000, dport=53),               "DROP"),   # 5
	("blocked IP and blocked port together",     tcp(23, src="192.168.1.100"),      "DROP"),   # 6
	("normal HTTP",                              tcp(80),                           "ALLOW"),  # 7, window clears

	# Window 2: SYN flood (threshold 4)
	("SYN 1",                                    syn(),                             "ALLOW"),  # 0
	("SYN 2",                                    syn(),                             "ALLOW"),  # 1
	("SYN 3",                                    syn(),                             "ALLOW"),  # 2
	("SYN 4 (threshold reached)",                syn(),                             "DROP"),   # 3
	("SYN 5",                                    syn(),                             "DROP"),   # 4
	("normal HTTPS during SYN flood",            tcp(443),                          "ALLOW"),  # 5
	("SYN from blocked IP (IP rule wins)",       syn(src="10.0.0.50"),              "DROP"),   # 6
	("SYN 7",                                    syn(),                             "DROP"),   # 7, window clears

	# Window 3: ICMP flood (threshold 4)
	("ping 1",                                   ping(),                            "ALLOW"),  # 0
	("ping 2",                                   ping(),                            "ALLOW"),  # 1
	("ping 3",                                   ping(),                            "ALLOW"),  # 2
	("ping 4 (threshold reached)",               ping(),                            "DROP"),   # 3
	("ping 5",                                   ping(),                            "DROP"),   # 4
	("normal HTTPS during ICMP flood",           tcp(443),                          "ALLOW"),  # 5
	("ping 6",                                   ping(),                            "DROP"),   # 6
	("SYN after the SYN window cleared",         syn(),                             "ALLOW"),  # 7, window clears

	# Window 4: counters have cleared; IPv6 static rules
	("ping in a new window",                     ping(),                            "ALLOW"),  # 0
	("server reply (443 back to client)",        tcp(50000, src=SERVER, dst=CLIENT), "ALLOW"), # 1
	("IPv6 normal HTTPS",                        tcp6(443),                         "ALLOW"),  # 2
	("IPv6 Telnet (blocked port 23)",            tcp6(23),                          "DROP"),   # 3
	("IPv6 blocked source 2001:db8::bad:1",      tcp6(80, src="2001:db8::bad:1"),   "DROP"),   # 4
	("IPv6 blocked source 2001:db8::bad:2",      tcp6(80, src="2001:db8::bad:2"),   "DROP"),   # 5
	("IPv6 blocked destination 2001:db8::200",   tcp6(80, dst="2001:db8::200"),     "DROP"),   # 6
	("IPv6 UDP DNS (all UDP blocked)",
		eth()/IPv6(src=V6_CLIENT, dst="2001:db8::53")/UDP(sport=53001, dport=53),     "DROP"),   # 7

	# Window 5: IPv6 SYN flood, and no IPv4/IPv6 mix-ups
	("IPv6 ending in blocked 192.168.1.100",     tcp6(80, src="2001:db8::c0a8:164"), "ALLOW"), # 0
	("IPv6 SYN 1",                               syn6(),                            "ALLOW"),  # 1
	("IPv6 SYN 2",                               syn6(),                            "ALLOW"),  # 2
	("IPv6 SYN 3",                               syn6(),                            "ALLOW"),  # 3
	("IPv6 SYN 4 (threshold reached)",           syn6(),                            "DROP"),   # 4
	("ICMPv6 ping a",                            ping6(),                           "ALLOW"),  # 5
	("ICMPv6 ping b",                            ping6(),                           "ALLOW"),  # 6
	("IPv4 protocol 58 is not ICMP",
		eth()/IP(src=CLIENT, dst=SERVER, proto=58)/Raw(b"x"),                        "ALLOW"),  # 7

	# Window 6: ICMPv6 flood
	("ICMPv6 ping 1",                            ping6(),                           "ALLOW"),  # 0
	("ICMPv6 ping 2",                            ping6(),                           "ALLOW"),  # 1
	("ICMPv6 ping 3",                            ping6(),                           "ALLOW"),  # 2
	("ICMPv6 ping 4 (threshold reached)",        ping6(),                           "DROP"),   # 3

	# Not IP: not inspected, and not counted in the window
	("ARP (not IP)",
		eth()/ARP(hwsrc=SRC_MAC, psrc=CLIENT, pdst="10.0.0.1"),                      "SKIP"),
]


def main():
	out_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR / "test_packets.pcap"
	out_file.parent.mkdir(exist_ok=True)

	wrpcap(str(out_file), [pkt for _, pkt, _ in TESTS])
	print(f"Saved {len(TESTS)} test packets to {out_file}\n")

	pf = PacketFilter()
	failures = 0
	for i, (desc, pkt, expected) in enumerate(TESTS):
		_, action, reason = pf.classify(pkt)
		ok = action == expected
		failures += not ok
		result = "PASS" if ok else "FAIL"
		got = f"{action} {reason}".strip()
		print(f"{result} {i:2}  {desc:<40} expected {expected:<5}  got {got}")

	print(f"\n{len(TESTS) - failures}/{len(TESTS)} tests passed")
	sys.exit(1 if failures else 0)


if __name__ == "__main__":
	main()
