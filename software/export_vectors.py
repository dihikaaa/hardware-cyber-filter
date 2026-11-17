"""
Turns a pcap into test vectors for the dual-stack Verilog testbench.

Every IP packet becomes one 288-bit line (72 hex characters) in packets.hex:

	bits [287:160]  source address  (128; IPv4 in the low 32 bits)
	     [159:32]   dest address    (128; IPv4 in the low 32 bits)
	     [31:24]    protocol / IPv6 next header  (8)
	     [23:16]    flags  (8: bit 16 = tcp_syn, bit 17 = is_ipv6)
	     [15:0]     dst_port  (16)

and one line in expected.txt: 1 = DROP, 0 = ALLOW (from golden_filter).
The packets must be fed to the testbench in this order, because the SYN
and ICMP flood counters carry over between packets.

	reg [287:0] packets  [0:N-1];  $readmemh("packets.hex", packets);
	reg         expected [0:N-1];  $readmemb("expected.txt", expected);

Packets the filter skips (not IP) are not exported.
vectors.txt lists the same vectors in readable form for debugging.

Usage:
	python export_vectors.py [input.pcap] [output_dir]
	(defaults: data/test_packets.pcap, data/)
"""
import ipaddress
import sys
from pathlib import Path

from scapy.all import rdpcap

from golden_filter import DATA_DIR, PacketFilter


def to_hex(fields):
	src = int(ipaddress.ip_address(fields["src_ip"]))
	dst = int(ipaddress.ip_address(fields["dst_ip"]))
	flags = fields["tcp_syn"] | (2 if fields["ip_version"] == 6 else 0)
	return (f"{src:032x}{dst:032x}{fields['protocol']:02x}"
			f"{flags:02x}{fields['dst_port']:04x}")


def main():
	in_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR / "test_packets.pcap"
	out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DATA_DIR
	out_dir.mkdir(exist_ok=True)

	hex_lines, expected_lines, readable_lines = [], [], []
	skipped = 0
	pf = PacketFilter()
	for pkt in rdpcap(str(in_file)):
		fields, action, reason = pf.classify(pkt)
		if fields is None:
			skipped += 1
			continue
		n = len(hex_lines)
		hex_lines.append(to_hex(fields))
		expected_lines.append("1" if action == "DROP" else "0")
		readable_lines.append(
			f"{n:4}  IPv{fields['ip_version']}  {fields['src_ip']:>18} -> {fields['dst_ip']:<18} "
			f"proto={fields['protocol']:<3} syn={fields['tcp_syn']} dport={fields['dst_port']:<5} "
			f"{action} {reason}".rstrip())

	(out_dir / "packets.hex").write_text("\n".join(hex_lines) + "\n")
	(out_dir / "expected.txt").write_text("\n".join(expected_lines) + "\n")
	(out_dir / "vectors.txt").write_text(
		"   #  version  src -> dst  (see packets.hex for the 72-hex-digit vectors)\n" + "\n".join(readable_lines) + "\n")

	print(f"Exported {len(hex_lines)} vectors ({skipped} non-IP packets skipped) to {out_dir}/")
	print("  packets.hex   - 288-bit vectors for $readmemh")
	print("  expected.txt  - 1 = DROP, 0 = ALLOW")
	print("  vectors.txt   - readable listing\n")
	print("\n".join(readable_lines))


if __name__ == "__main__":
	main()
