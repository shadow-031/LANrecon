import ipaddress
import subprocess
import threading
import socket
import re
import urllib.parse

# Define the network to scan
network = ipaddress.IPv4Network("192.168.3.0/24", strict=False)

# Store live IPs and open ports
live_ips = []
scan_results = {}
service_versions = {}

# Check if a host is online (ping)
def is_ip_up(ip):
    try:
        subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stderr=subprocess.DEVNULL
        )
        print(f"[+] {ip} is UP")
        live_ips.append(str(ip))
    except subprocess.CalledProcessError:
        pass  # Host is down or unreachable

# Scan ports on a live IP
def scan_ports(ip, port_range=(1, 1000), timeout=0.5):
    print(f"[>] Scanning ports on {ip}")
    open_ports = []

    for port in range(port_range[0], port_range[1] + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()

            if result == 0:
                print(f"    [OPEN] Port {port}")
                open_ports.append(port)
        except:
            pass

    if open_ports:
        scan_results[ip] = open_ports
    else:
        print(f"    [!] No open ports found on {ip}")

# Use Nmap to detect service and version and print possible CVEs
def detect_services():
    print("\n[>] Detecting service/version using Nmap...")
    for ip, ports in scan_results.items():
        print(f"\n{ip}:")
        port_str = ",".join(str(p) for p in ports)

        try:
            result = subprocess.check_output(
                ["nmap", "-sV", "-p", port_str, ip],
                stderr=subprocess.DEVNULL
            ).decode()

            # Match lines like "80/tcp open  http  Apache httpd 2.4.41"
            matches = re.findall(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", result)

            if not matches:
                print("  [!] No service/version info found")

            for port, service, version in matches:
                clean_version = version.strip()
                print(f"  Port {port}: {service} - {clean_version}")
                
                # Save service-version map
                service_versions[(ip, port)] = (service, clean_version)

                # Create CVE search link
                query = urllib.parse.quote_plus(service + " " + clean_version)
                cve_url = f"https://vulners.com/search?query={query}"
                print(f"    ↪ CVE Search: {cve_url}")

        except subprocess.CalledProcessError:
            print(f"[>] Nmap scan failed for {ip}")

# Step 1: Ping all hosts using threads
ping_threads = []
for ip in network.hosts():
    t = threading.Thread(target=is_ip_up, args=(ip,))
    t.start()
    ping_threads.append(t)

for t in ping_threads:
    t.join()

# Step 2: Scan open ports for each live IP
for ip in live_ips:
    scan_ports(ip, port_range=(1, 1000))  # Change to (1, 65535) for full scan

# Step 3: Detect services and print CVE links
detect_services()

# Summary
print("\n[>] Scan complete.")
print("\nOpen Ports Summary:")
for ip, ports in scan_results.items():
    print(f"{ip}: {ports}")
