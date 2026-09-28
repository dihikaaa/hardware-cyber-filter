# Hardware-Level Cybersecurity Filtering for Edge Networks

## Objective

Design a hardware-based cybersecurity filtering module for edge networks.

The module will inspect relevant packet header information and make an
ALLOW or DROP decision based on predefined security rules.

## Project Structure

- `software/` - Python-based reference security model
- `rtl/` - Verilog/SystemVerilog hardware implementation
- `simulation/` - Simulation files and test results
- `data/` - Network traffic and test data
- `docs/` - Project documentation

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
