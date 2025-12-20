# Web-Based Advanced Port Scanner
# Uses Flask (simple Python web framework)
# Run this file, then open http://127.0.0.1:5000 in your browser

from flask import Flask, render_template_string, request
import socket
import threading
from datetime import datetime
import queue

app = Flask(__name__)

# === All the scanning code from before (ports, services, threats) ===
common_ports = [22, 80, 443, 3389, 445, 21, 23, 25, 53, 110, 135, 137, 138, 139, 143, 161, 162, 389, 3306, 5432, 5900, 8080, 8443, 9200]

port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch",
}

port_threats = {
    22: "SSH: One of the MOST attacked ports. Risks: Brute-force, outdated versions.",
    80: "HTTP: Unencrypted. Risks: Web vulnerabilities if outdated.",
    443: "HTTPS: Still risks from old TLS or web app flaws.",
    3389: "RDP: Extremely vulnerable! Often targeted by ransomware.",
    445: "SMB: Famous for EternalBlue/WannaCry exploits.",
    21: "FTP: Plaintext passwords – very risky.",
    23: "Telnet: Completely insecure. Disable immediately!",
}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        if banner:
            return banner[:200]
    except:
        pass
    return "No banner grabbed"

def scan_target(ip, port_range):
    ports_to_scan = {
        "common": common_ports,
        "1-1024": list(range(1, 1025)),
        "1-10000": list(range(1, 10001))
    }[port_range]

    results = []
    q = queue.Queue()
    for port in ports_to_scan:
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(ip, port)
                    results.append((port, service, banner))
                sock.close()
            except:
                pass
            q.task_done()

    for _ in range(50):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
    q.join()

    results.sort(key=lambda x: x[0])
    return results

# === Web Pages ===

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Port Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #f4f4f9; }
        h1 { color: #333; text-align: center; }
        .warning { background: #ffcccc; padding: 15px; border-radius: 8px; margin: 20px 0; font-weight: bold; }
        form { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        label { display: block; margin: 15px 0 5px; font-weight: bold; }
        input, select, button { padding: 10px; font-size: 16px; width: 100%; margin-top: 5px; }
        button { background: #007bff; color: white; border: none; cursor: pointer; margin-top: 20px; }
        button:hover { background: #0056b3; }
        .result { margin-top: 30px; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .open { color: green; font-weight: bold; }
        .threat { background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🛡️ Advanced Web Port Scanner</h1>
    <div class="warning">
        ⚠️ ONLY scan devices you own or have explicit permission to scan!<br>
        Unauthorized scanning is illegal.
    </div>

    <form method="post">
        <label>Target IP Address:</label>
        <input type="text" name="ip" placeholder="e.g., 127.0.0.1" required value="{{ ip }}">

        <label>Port Range:</label>
        <select name="range">
            <option value="common">Common/Vulnerable Ports (Fast)</option>
            <option value="1-1024">Ports 1-1024 (Standard)</option>
            <option value="1-10000">Ports 1-10000 (Deeper Scan)</option>
        </select>

        <button type="submit">🚀 Start Scan</button>
    </form>

    {% if results is not none %}
    <div class="result">
        <h2>Scan Results for {{ ip }} ({{ scan_time }})</h2>
        {% if results %}
            <p>Found <strong>{{ results|length }}</strong> open port(s):</p>
            {% for port, service, banner in results %}
                <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px;">
                    <p><span class="open">Port {{ port }}/TCP OPEN</span> - Service: <strong>{{ service }}</strong></p>
                    {% if "No banner" not in banner %}
                        <p><strong>Banner/Version:</strong> <code>{{ banner }}</code></p>
                    {% endif %}
                    <div class="threat">
                        <strong>⚠️ Threat Alert:</strong> {{ port_threats.get(port, "General risk: Open port increases attack surface.") }}
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <p>No open ports found. Target may be offline or heavily firewalled.</p>
        {% endif %}
    </div>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    ip = ""
    scan_time = ""

    if request.method == 'POST':
        ip = request.form['ip'].strip()
        port_range = request.form['range']

        # Basic input validation
        try:
            socket.inet_aton(ip)  # Validates IP format
            start_time = datetime.now()
            results = scan_target(ip, port_range)
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except:
            results = []
            scan_time = "Invalid IP address!"

    return render_template_string(HTML_TEMPLATE, results=results, ip=ip, scan_time=scan_time, port_threats=port_threats)

if __name__ == '__main__':
    print("🚀 Web Port Scanner starting...")
    print("Open your browser and go to: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)