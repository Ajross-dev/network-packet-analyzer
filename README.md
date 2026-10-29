# Network Packet Analyzer

A lightweight command-line network packet analyzer built with Python, PyShark, and TShark. Captures live network traffic, displays packet information, filters by protocol, and optionally exports results to CSV.

This project was built to explore network traffic analysis, packet inspection, and Python application development.

## Features

- **Live Packet Capture:** Capture network traffic from a specified interface.
- **Protocol Filtering:** Filter displayed packets by protocol (TCP, UDP, TLS, DNS, etc.).
- **Packet Inspection:** Display protocol, packet length, and source/destination IPv4 addresses when available.
- **Protocol Statistics:** Track captured packets and protocol frequencies.
- **CSV Export:** Save matching packet information to a CSV file.
- **Command-Line Interface:** Configure capture settings through CLI arguments.
- **Error Handling:** Validate user input and handle interrupted captures.

## Technologies

- Python 3
- PyShark
- TShark / Wireshark
- argparse
- csv

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/Ajross-dev/network-packet-analyzer.git
cd network-packet-analyzer
```

**2. Install TShark (Ubuntu/WSL)**

```bash
sudo apt update
sudo apt install tshark
```

**3. Create a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**4. Install dependencies**

```bash
pip install pyshark
```

## Usage

Run the analyzer with elevated permissions if required for live packet capture.

**Capture 5 packets (default)**

```bash
sudo .venv/bin/python analyzer.py
```

**Capture 20 packets**

```bash
sudo .venv/bin/python analyzer.py --count 20
```

**Filter by protocol**

```bash
sudo .venv/bin/python analyzer.py --protocol TCP --count 30
```

**Specify a network interface**

```bash
sudo .venv/bin/python analyzer.py --interface eth0 --count 10
```

**Export results to CSV**

```bash
sudo .venv/bin/python analyzer.py --count 20 --output packets.csv
```

**Combine filtering and exporting**

```bash
sudo .venv/bin/python analyzer.py --protocol TLS --count 50 --output tls_packets.csv
```

## Example Output

```text
Packet 1
Protocol: TCP
Length: 74
Source IP: 172.20.10.5
Destination IP: 142.250.190.14
----------------------------------
Packet 2
Protocol: DNS
Length: 85
Source IP: 172.20.10.5
Destination IP: 8.8.8.8
----------------------------------
--- Protocol Statistics ---
TCP: 1
DNS: 1
Total captured packets: 2
```

_Example output is illustrative; actual results depend on network traffic._

## How It Works

The analyzer uses PyShark as a Python interface to TShark, Wireshark's command-line packet analysis tool.

1. Parses and validates command-line arguments.
2. Initializes live packet capture on the selected network interface.
3. Processes incoming packets and identifies their highest-level protocols.
4. Applies optional protocol filtering.
5. Extracts packet information and displays matching packets.
6. Optionally writes matching packets to CSV.
7. Displays capture statistics and releases resources.

**Note:** The `--count` argument controls the total number of packets captured, not the number matching a protocol filter. Protocol statistics count only matching packets. The analyzer currently extracts IPv4 addresses; packets without an IPv4 layer display a corresponding message.

## Testing

The project includes automated unit tests using Python's built-in `unittest` framework.

Run the tests with:

```bash
.venv/bin/python -m unittest -v test_analyzer.py
```

Tests cover IPv4 address extraction, handling packets without IPv4, default CLI arguments, protocol normalization, CSV filename validation, and invalid packet counts.

Tests use mock objects and do not require live network capture or elevated permissions.

## Limitations

- Requires TShark and appropriate packet-capture permissions.
- Protocol filtering occurs after packets are captured.
- Does not currently extract IPv6 addresses.
- CSV export supports simple `.csv` filenames in the current directory.
- In WSL, the default `eth0` interface represents a virtual network interface rather than necessarily capturing all Windows host traffic.

## Future Improvements

- IPv6 support
- Additional packet metadata
- Automated unit tests
- Advanced packet filtering

## License

No license has been specified yet.
