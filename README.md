# Hardware-Level Cybersecurity Filtering for Edge Networks

## Objective

Design a hardware-based cybersecurity filtering module for edge networks.

The module will inspect relevant packet header information and make an
ALLOW or DROP decision based on predefined security rules.

## Project Structure

- `software/` - Python IDS and reference security model (golden model); see [software/README.md](software/README.md)
- `rtl/` - Verilog/SystemVerilog hardware implementation
- `simulation/` - Simulation files and test results
- `data/` - Network traffic and test data
- `docs/` - Project documentation

## Software (Python IDS)

The Python IDS applies the same 7 rules as the hardware to IPv4 and IPv6
packets, raises an alert for every drop, and exports test vectors with the
expected result for each packet, so the Verilog design can be checked against
it.

```bash
cd software
pip install -r requirements.txt
python make_tests.py        # 45/45 test packets pass
python golden_filter.py     # IDS run with alerts and a summary
python export_vectors.py    # Verilog test vectors
```

## Planned Flow

Network Traffic
        ↓
Packet Header Extraction
        ↓
Security Rule Matching
        ↓
ALLOW / DROP Decision
        ↓
Hardware Implementation
        ↓
RTL Simulation → Synthesis → ASIC Flow
