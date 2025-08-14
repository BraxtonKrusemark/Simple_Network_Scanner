Python Network & Port Scanner

A fast and flexible network and port scanner written in Python using Scapy.Supports scanning multiple hosts, custom port ranges, common ports, and skips inactive hosts. Results are saved in a CSV file.

Features

Scan multiple IP addresses or a subnet (e.g., 192.168.1.1-50)

Scan a custom range of ports and/or common ports like 22, 80, 443, 8080

Skips hosts that do not respond at Layer 2 (no MAC address detected)

Threaded scanning:

Limit concurrent IP scans (default: 5)

Per-port threading for faster scanning

Results exported to CSV, including skipped hosts

Command-line interface for easy usage

Installation

Clone the repository:

git clone https://github.com/yourusername/python-network-scanner.git
cd python-network-scanner

Install dependencies:

pip install scapy

Note: On Windows, you may need to install Npcap to allow raw socket operations with Scapy. Run Python as administrator if scanning TCP ports.

Usage

python scanner.py --targets 192.168.1.10 192.168.1.15 --ports 1-100 --common --max-ip-threads 5 --output scan_results.csv

Command-line arguments

--targets: Space-separated list of IP addresses or hostnames to scan (required)

--ports: Port range to scan (format: start-end, default: 1-100)

--common: Include common ports (22, 80, 443, 8080, etc.)

--max-ip-threads: Maximum concurrent IP threads (default: 5)

--output: CSV file name to save results (default: _scan_results.csv)

Example

Scan two hosts, ports 1–50, including common ports, with 5 IP threads:

python scanner.py --targets 192.168.1.10 192.168.1.15 --ports 1-50 --common --max-ip-threads 5 --output myscan.csv

Output

CSV file with columns: Host, Port, Status

Skipped hosts (no MAC detected) are included with Port as - and Status as NO MAC

Example:

Host,Port,Status
192.168.1.5,-,NO MAC
192.168.1.10,22,OPEN
192.168.1.10,23,CLOSED
192.168.1.10,80,OPEN

Notes

Scanning large networks may take time. Use threading and port limits to avoid overwhelming your system

Administrator privileges may be required on Windows for raw socket operations

Only scan networks you own or have permission to test

License

This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgements

Scapy – Python library for packet manipulation and network scanning

