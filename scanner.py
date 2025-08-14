from scapy.all import IP, TCP, sr1, Ether, srp, ARP
import csv
import threading
from concurrent.futures import ThreadPoolExecutor

scan_results = []
lock = threading.Lock()
MAX_IP_THREADS = 5  # Limit concurrent IPs


import argparse

parser = argparse.ArgumentParser(description="Python Network/Port Scanner")
parser.add_argument("--targets", nargs="+", required=True,
                    help="Target IP addresses or hostnames")
parser.add_argument("--ports", default="1-100",
                    help="Port range to scan (format: start-end)")
parser.add_argument("--common", action="store_true",
                    help="Include common ports (22,80,443,8080, etc.)")
parser.add_argument("--max-ip-threads", type=int, default=5,
                    help="Maximum number of concurrent IP threads")
parser.add_argument("--output", default="scan_results.csv",
                    help="CSV file to save results")

args = parser.parse_args()

# Convert port range string to list of integers
start_port, end_port = map(int, args.ports.split("-"))
port_list = list(range(start_port, end_port + 1))

# Add common ports if requested
if args.common:
    common_ports = [21,22,23,25,53,80,110,143,443,3306,8080]
    port_list = sorted(set(port_list).union(common_ports))

targets = args.targets
max_ip_threads = args.max_ip_threads
output_file = args.output

print(f"Scanning targets: {targets}")
print(f"Ports: {port_list}")
print(f"Max IP threads: {max_ip_threads}")
print(f"Results will be saved to: {output_file}")


# Function to scan a single port
def scan_port(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="S")  # SYN
    response = sr1(packet, timeout=1, verbose=False)

    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            status = "OPEN"
            sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=False)
            print(f"[+] {target}:{port} OPEN")
        elif response[TCP].flags == 0x14:
            status = "CLOSED"
            print(f"[-] {target}:{port} CLOSED")
    else:
        status = "FILTERED"
        print(f"[?] {target}:{port} FILTERED or no response")

    with lock:
        scan_results.append([target, port, status])

# Function to scan all ports for a single host
def scan_host(target):
    # --- Check for MAC address ---
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    answered, _ = srp(arp_packet, timeout=1, verbose=False)
    if not answered:
        print(f"Skipping {target}: no MAC address detected")

        with lock:
            scan_results.append([target, "-", "NO MAC"])
        return

    print(f"Scanning host {target}...")
    threads = []
    for port in port_list:
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# --- Scan IPs with limited concurrency ---
with ThreadPoolExecutor(max_workers=MAX_IP_THREADS) as executor:
    executor.map(scan_host, targets)

# --- Write results to CSV ---
with open(f"{output_file}", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Host", "Port", "Status"])
    for row in scan_results:
        writer.writerow(row)
