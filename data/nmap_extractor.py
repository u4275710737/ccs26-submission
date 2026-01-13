import re
from collections import Counter
from pathlib import Path

from tqdm import tqdm


class NmapPortInfo:
    def __init__(self, port: str, state: str, service: str, reason: str):
        self.port = port
        self.state = state
        self.service = service
        self.reason = reason

    def __repr__(self):
        return f"NmapPortInfo(port='{self.port}', state='{self.state}', service='{self.service}', reason='{self.reason}')"

class NmapHostResult:
    def __init__(self, ip_address: str, ports: list[NmapPortInfo], device_type: str, os_guesses: str):
        self.ip_address = ip_address
        self.ports = ports  # List of NmapPortInfo
        self.device_type = device_type # String with device type, optional (not always present)
        self.os_guesses = os_guesses  # String with OS details or guesses

    def __repr__(self):
        return (f"NmapHostResult(ip_address='{self.ip_address}', "
                f"ports={self.ports}, device_type='{self.device_type}, os_guesses='{self.os_guesses}')")


nmap_lines = []

# Read in TCP nmap data
folder_path = Path('./daily_scans/tcp')

for txt_file in folder_path.glob('nmap_output_*'):
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.readlines()
        nmap_lines.extend(content)

# Read in UDP nmap data
folder_path = Path('./daily_scans/udp')

for txt_file in folder_path.glob('nmap_output_*'):
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.readlines()
        nmap_lines.extend(content)

num_reports = 0
down_hosts = []

processing_results = False
processing_ip = None
processing_ports = []
processing_device_type = ""
processing_os = ""
port_section = False

hosts_up = 0
seconds = 0

up_hosts_results = []
for line in tqdm(nmap_lines):
    if "Nmap scan report for" in line:
        num_reports += 1
        if processing_ip is not None:
            if processing_os == "":
                print(f"Processing likely failed. Take a look at {processing_ip}!")
        processing_results = False
        processing_ip = None
        processing_ports = []
        processing_device_type = ""
        processing_os = ""
        port_section = False
        ip_match = re.search(r'Nmap scan report for (?:[\w\-.*]+)?\s*\(?(\d{1,3}(?:\.\d{1,3}){3})\)?', line)
        if ip_match:
            ip_address = ip_match.group(1)
        else:
            print("Failed to extract IP!")
            print(line)

        if "host down" in line:
            down_hosts.append(ip_address)
            continue
        else:
            processing_ip = ip_address
            processing_results = True
            continue

    if processing_results:
        if re.match(r'^PORT\s+STATE\s+SERVICE\s+REASON', line):
            port_section = True
            continue
        elif port_section:
            port_res_match = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+(.*)$', line)
            if port_res_match:
                port, state, service, reason = port_res_match.groups()
                if "/" not in port or line.strip() == "" or line.startswith(("Warning:", "OS :", "No exact", "Too many", "Device type:")):
                    port_section = False
                else:
                    processing_ports.append(NmapPortInfo(port, state, service, reason))
            else:
                port_section = False
        if not port_section:
            if line.startswith("Device type:"):
                device_match = re.search(r'^Device type:\s*(.+)$', line)
                if device_match:
                    processing_device_type = device_match.group(1)
                continue
            if line.startswith("Aggressive OS guesses:"):
                os_match = re.search(r'^Aggressive OS guesses:\s*(.+)$', line)
                if os_match:
                    processing_os = os_match.group(1)
                continue
            if line.startswith("OS details:"):
                os_match = re.search(r'^OS details:\s*(.+)$', line)
                if os_match:
                    processing_os = os_match.group(1)
                continue
            if line.startswith("Too many fingerprints"):
                processing_os = "Too many fingerprints match this host to give specific OS details"
                continue
            if line.startswith("TCP/IP fingerprint:"):
                if processing_os == "":
                    processing_os = "No guesses made"
                up_hosts_results.append(NmapHostResult(processing_ip, processing_ports, processing_device_type, processing_os))
                processing_results = False
                continue

    if line.startswith('# Nmap done'):
        match = re.search(r'(\d+) IP addresses \((\d+) hosts up\) scanned in ([\d.]+) seconds', line)
        if match:
            hosts_up += int(match.group(2))
            seconds += float(match.group(3))
        else:
            print("Failed to match!")
            print(line)

device_counter_full = Counter()
device_counter_partial = Counter()
general_purpose_counter = Counter()
device_types_found = 0
device_types_lengths = []
gp_count = 0
router_count = 0
for host in up_hosts_results:
    if host.device_type:
        device_types_found += 1
        device_counter_full[host.device_type] += 1
        if host.device_type == "general purpose":
            general_purpose_counter[host.os_guesses] += 1
            gp_count += 1
        if host.device_type == "router":
            router_count += 1
        types = host.device_type.split('|')
        device_types_lengths.append(len(types))
        device_counter_partial.update(types)
device_types_length_multiple = sum(1 for x in device_types_lengths if x > 1)

line_width = 110
print()
print("Extraction Results".center(line_width, "="))
print()
print(f"Total scanned hosts: {num_reports} with {hosts_up} of them being up at the time in {seconds} seconds.")
print(f"Number of extracted reports from file: {num_reports}")
print()
print("Statistics".center(line_width, "="))
print()
print(f"Number of extracted hosts that are down: {len(down_hosts)}")
print(f"Number of extracted hosts that are up: {len(up_hosts_results)}")
print(f"Number of found device types: {device_types_found}")
print(f"Number of device types with more than two partials: {device_types_length_multiple} ({round(device_types_length_multiple/device_types_found * 100,2)}%)")
print(f"Average number of device types: {sum(device_types_lengths) / len(device_types_lengths)}")
print(f"Maximum number of device types: {max(device_types_lengths)}")
print(f"Single general purpose found: {gp_count}")
print(f"Single routers found: {router_count}")
print()
print("Partial Devices".center(line_width, "="))
print()
for device, count in device_counter_partial.most_common():
    if device:
        print(f"{device}: {count} ({round(count/device_types_found * 100, 2)}%)")
print()
print("Full Devices".center(line_width, "="))
print()
for device, count in device_counter_full.most_common():
    if device:
        print(f"{device}: {count}")
print()
print("General Purpose OSes".center(line_width, "="))
print()
for os, count in general_purpose_counter.most_common():
    if os:
        print(f"{os}: {count}")
print()

# Make sure parsing worked
assert num_reports == len(down_hosts) + len(up_hosts_results)
assert hosts_up == len(up_hosts_results)
assert sum(1 for host in up_hosts_results if host.os_guesses != "") == len(up_hosts_results)
assert sum(1 for host in up_hosts_results if host.ip_address != "") == len(up_hosts_results)
