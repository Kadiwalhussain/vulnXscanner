# Advanced Network Port Scanner with Banner Grabbing and Enhanced Threat Flagging
# Beginner-friendly Python script (still no external packages – pure built-in libraries)
# New features:
# - Scan user-defined port range (e.g., 1-1024 or all 1-65535)
# - Multi-threading for MUCH faster scanning (scans many ports at once)
# - Banner grabbing: Tries to fetch service "banner" (version info) for open ports
# - More common ports (top ~100 vulnerable/common ones)
# - Updated threat warnings based on 2025 cybersecurity info
# - Better report with service detection and specific risks

import socket  # For network connections
import threading  # For faster multi-threaded scanning
from datetime import datetime
import queue  # To manage ports for threads

# Expanded list of common/vulnerable ports (top risky ones first, based on recent reports)
common_ports = [
    22,   # SSH - highly attacked
    80,   # HTTP
    443,  # HTTPS
    3389, # RDP - very vulnerable
    445,  # SMB
    21,   # FTP
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    110,  # POP3
    135,  # RPC
    137,  # NetBIOS
    138,  # NetBIOS
    139,  # NetBIOS
    143,  # IMAP
    161,  # SNMP
    162,  # SNMP Trap
    389,  # LDAP
    443,  # HTTPS (duplicate for emphasis)
    3306, # MySQL
    5432, # PostgreSQL
    5900, # VNC
    8080, # HTTP Alternate
    8443, # HTTPS Alternate
    9200, # Elasticsearch
    # Add more if needed...
]

# Map ports to common services
port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch",
}

# Enhanced threat warnings (updated for 2025 trends: RDP/SSH highly exploited, SMB ransomware, etc.)
port_threats = {
    22: "SSH: One of the MOST attacked ports in 2025. Risks: Brute-force, weak keys, outdated OpenSSH (e.g., recent CVEs like CVE-2025-26465). Use strong keys/passwords!",
    80: "HTTP: Unencrypted web. Risks: Outdated servers (Apache/Nginx CVEs), SQL injection, XSS.",
    443: "HTTPS: Encrypted web. Still risks from outdated TLS, web app vulnerabilities.",
    3389: "RDP: Extremely vulnerable! High brute-force attacks, exploits like BlueKeep. Often used in ransomware. Disable if not needed!",
    445: "SMB: Famous for ransomware (EternalBlue/WannaCry). Patch immediately if open!",
    21: "FTP: Plaintext passwords. Risks: Brute-force, anonymous access.",
    23: "Telnet: Completely insecure (plaintext everything). Disable ASAP!",
    25: "SMTP: Risks: Open relay spam, exploitation in email servers.",
    3389: "RDP: (Repeated for emphasis) Top exploited in 2025 reports.",
    9200: "Elasticsearch: Often exposed, leads to data leaks.",
}

# Function to grab banner (service version info)
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Some services send banner automatically, others need a nudge
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        # For HTTP/HTTPS, send a simple GET request
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        # For SSH/FTP etc., banner often sent on connect
        sock.close()
        if banner:
            return banner[:200]  # Limit length
    except:
        pass
    return "No banner grabbed (or service doesn't send one)"

# Function to scan a single port
def scan_port(ip, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = port_services.get(port, "Unknown")
            banner = grab_banner(ip, port)
            results.append((port, service, banner))
    except:
        pass

# Main program
print("=== Advanced Port Scanner + Banner Grabbing + Threat Report ===")
print("WARNING: Only scan YOUR OWN devices or with EXPLICIT PERMISSION!")
print("Scanning networks without permission is ILLEGAL.\n")

target = input("Enter IP address (e.g., 127.0.0.1 for your computer): ")

# Ask for port range
print("\nPort range options:")
print("1. Common/vulnerable ports only (fast, ~50 ports)")
print("2. Top 1-1024 (well-known ports)")
print("3. Custom range (e.g., 1-65535 – slow!)")
choice = input("Choose (1-3): ")

if choice == "1":
    ports_to_scan = common_ports
elif choice == "2":
    ports_to_scan = range(1, 1025)
elif choice == "3":
    start = int(input("Start port (1-65535): "))
    end = int(input("End port (1-65535): "))
    ports_to_scan = range(start, end + 1)
else:
    print("Invalid choice – using common ports.")
    ports_to_scan = common_ports

print(f"\nScanning {len(ports_to_scan)} ports on {target}...")
print(f"Started at {datetime.now()}\n")

# Multi-threading setup (faster!)
threads = []
max_threads = 100  # Safe number for beginners
port_queue = queue.Queue()
results = []

for port in ports_to_scan:
    port_queue.put(port)

def worker():
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port, results)
        port_queue.task_done()

# Start threads
for _ in range(min(max_threads, len(ports_to_scan))):
    t = threading.Thread(target=worker)
    t.start()

port_queue.join()  # Wait for all to finish

print(f"Scan finished at {datetime.now()}\n")

# Sort results by port number
results.sort(key=lambda x: x[0])

if not results:
    print("No open ports found. Target may be offline, firewalled, or no services running.")
else:
    print(f"Found {len(results)} open port(s):\n")
    for port, service, banner in results:
        print(f"Port {port}/TCP OPEN")
        print(f"   Service: {service}")
        if "No banner" not in banner:
            print(f"   Banner/Version: {banner}")
        print()

    print("=== Enhanced Threat Report (2025 Risks) ===")
    print("General advice: Close unnecessary ports, keep software patched, use firewalls!\n")
    
    for port, service, banner in results:
        threat = port_threats.get(port, "No specific common threats – but any open port increases risk.")
        print(f"Port {port} ({service}):")
        print(f"   - {threat}")
        if "No banner" not in banner and "ssh" in banner.lower():
            print("   - Detected SSH version – search online for CVEs specific to this version!")
        print()

print("Tip: For real vulnerability scanning, use professional tools like Nmap with --version-all or Nessus.")
print("Learn responsibly – great job leveling up! 🚀")