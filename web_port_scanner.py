from flask import Flask, render_template_string, request
import socket
import threading
import queue
from datetime import datetime
import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


app = Flask(__name__)

# --- Logic (Same as before) ---
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 161, 389, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9200]
port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch"
}
port_threats = {
    22: "SSH: Brute-force risk. Use key-auth and Fail2Ban.",
    80: "HTTP: Unencrypted. Use HSTS and redirect to 443.",
    443: "HTTPS: Check for weak TLS 1.0/1.1 protocols.",
    3389: "RDP: High Ransomware risk. Use VPN/Gateway.",
    445: "SMB: EternalBlue target. Firewall port 445.",
    21: "FTP: Cleartext creds. Use SFTP (Port 22).",
    23: "Telnet: Highly insecure. Replace with SSH.",
}
severity_map = {23: "Critical", 21: "High", 445: "High", 3389: "High", 22: "Medium", 80: "Medium", 443: "Low", 3306:"Critical"}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = ""
        try:
            data = sock.recv(1024)
            if data: banner += data.decode('utf-8', errors='ignore').strip()
        except: pass
        if port in [80, 443, 8080, 8443]:
            try:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = sock.recv(1024)
                if response:
                    decoded = response.decode('utf-8', errors='ignore').split('\r\n')[0]
                    banner += f" ({decoded})"
            except: pass
        sock.close()
        return banner[:100] if banner else "No banner response"
    except: return "No banner response"

def scan_target(target_ip, deep_scan):
    ports = list(range(1, 1025)) if deep_scan else common_ports
    results = []
    q = queue.Queue()
    for port in ports: q.put(port)
    def worker():
        while not q.empty():
            port = q.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(target_ip, port)
                    severity = severity_map.get(port, "Low")
                    threat = port_threats.get(port, "General exposure risk detected.")
                    results.append((port, service, banner, severity, threat))
                sock.close()
            except: pass
            q.task_done()
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    q.join()
    return sorted(results, key=lambda x: x[0])

def resolve_target(target):
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except: return None, target

# --- Professional & Mobile-Responsive UI Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnX | Security Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        /* (All your CSS exactly as before - copy-paste it here unchanged) */
        :root {
            --bg-main: #0a0c10;
            --bg-card: #12151c;
            --border: #232833;
            --accent: #10b981;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .hamburger {
            display: none;
            cursor: pointer;
            padding: 15px;
            position: fixed;
            top: 10px;
            left: 10px;
            z-index: 1001;
            background: var(--bg-card);
            border-radius: 8px;
        }
        .hamburger div {
            width: 30px;
            height: 3px;
            background: var(--text-primary);
            margin: 6px 0;
            transition: 0.4s;
        }
        .sidebar {
            width: 240px;
            background: #010409;
            border-right: 1px solid var(--border);
            padding: 24px;
            position: fixed;
            height: 100vh;
            top: 0;
            left: 0;
            z-index: 1000;
            transition: transform 0.3s ease;
            overflow-y: auto;
        }
        .logo {
            font-weight: 800;
            font-size: 1.5rem;
            color: var(--accent);
            letter-spacing: -1px;
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nav-item {
            padding: 12px;
            border-radius: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            margin-bottom: 8px;
            display: block;
            transition: 0.2s;
        }
        .nav-item:hover, .nav-item.active {
            background: var(--bg-card);
            color: var(--text-primary);
        }
        .content {
            flex: 1;
            padding: 20px;
            margin-left: 240px;
            transition: margin-left 0.3s ease;
        }
        .header { margin-bottom: 40px; text-align: center; }
        .header h1 { font-size: 2rem; }
        .header p { color: var(--text-secondary); }
        .search-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 40px;
        }
        .input-group {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            background: #0d1117;
            border: 1px solid var(--border);
            padding: 14px 18px;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
        }
        .btn-primary {
            background: var(--accent);
            color: #000;
            font-weight: 600;
            padding: 14px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
        }
        .btn-clear {
            background: transparent;
            border: 2px solid var(--critical);
            color: var(--critical);
            padding: 14px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            width: 100%;
            font-size: 1rem;
            transition: all 0.2s;
        }
        .btn-clear:hover {
            background: rgba(239, 68, 68, 0.1);
        }
        .options-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        .terminal {
            background: #010409;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #8b949e;
            margin-bottom: 30px;
            max-height: 200px;
            overflow-y: auto;
        }
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            position: relative;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: scale(1.03);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.2);
        }
        .severity-badge {
            position: absolute;
            top: 24px;
            right: 24px;
            font-size: 0.7rem;
            text-transform: uppercase;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 20px;
        }
        .Critical { background: rgba(239, 68, 68, 0.1); color: var(--critical); }
        .High { background: rgba(249, 115, 22, 0.1); color: var(--high); }
        .Medium { background: rgba(245, 158, 11, 0.1); color: var(--medium); }
        .Low { background: rgba(16, 185, 129, 0.1); color: var(--low); }
        .port-info { font-size: 1.1rem; font-weight: 700; margin-bottom: 4px; }
        .service-name { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px; }
        .banner-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            background: #0d1117;
            padding: 8px;
            border-radius: 6px;
            margin-bottom: 16px;
            word-break: break-all;
        }
        .remediation { border-top: 1px solid var(--border); padding-top: 16px; font-size: 0.85rem; }
        .remediation-label { font-weight: 600; color: var(--text-primary); display: block; margin-bottom: 4px; }
        .ai-hint {
            margin-top: 12px;
            font-size: 0.85rem;
            color: var(--accent);
            text-align: center;
        }
        footer { margin-top: 60px; padding: 20px; font-size: 0.8rem; color: #4b5563; text-align: center; }
        @media (max-width: 768px) {
            .hamburger { display: block; }
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
            .content { margin-left: 0; padding-top: 60px; }
            .input-group { flex-direction: column; }
            .btn-primary, .btn-clear { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="hamburger" onclick="this.parentElement.querySelector('.sidebar').classList.toggle('open')">
        <div></div><div></div><div></div>
    </div>
    <div class="sidebar">
        <div class="logo"><span>◈</span> VulnX</div>
        <a href="/" class="nav-item active">Dashboard</a>
        <a href="#" class="nav-item">Scan History</a>
        <a href="#" class="nav-item">Vulnerability Database</a>
        <a href="/subdomain" class="nav-item">Subdomain Finder</a>
        <a href="#" class="nav-item" style="margin-top:auto">Settings</a>
    </div>
    <div class="content">
        <div class="header">
            <h1>Security Scanner</h1>
            <p>Perform real-time port analysis and service finger-printing.</p>
        </div>
        <div class="search-container">
            <form method="post">
                <div class="input-group">
                    <input type="text" name="target" placeholder="Enter IP or Hostname (e.g. scanme.nmap.org)" required value="{{ original_target }}">
                    <button type="submit" class="btn-primary">Analyze Target</button>
                </div>
                <div class="options-bar">
                    <label><input type="checkbox" name="deep" {{ 'checked' if deep_scan else '' }}> Deep Scan (1-1024)</label>
                    <label><input type="checkbox" checked> OS Detection</label>
                    <label><input type="checkbox" checked> Aggressive Mode</label>
                </div>
            </form>

            {% if results is not none or log_lines %}
            <form method="post" action="/clear">
                <button type="submit" class="btn-clear">
                    🗑️ Clear Results
                </button>
            </form>
            {% endif %}
        </div>

        {% if log_lines %}
            <div class="terminal">
                {% for line in log_lines %}
                    <div>> {{ line }}</div>
                {% endfor %}
            </div>
        {% endif %}

        {% if results is not none %}
            <div class="results-grid">
                {% for port, service, banner, severity, threat in results %}
                    <div class="card"
                         onclick="fetchGeminiDetails({{ port }}, '{{ service|replace(\"'\", \"\\'\") }}', '{{ banner|replace(\"'\", \"\\'\") }}', '{{ severity }}')">
                        <span class="severity-badge {{ severity }}">{{ severity }}</span>
                        <div class="port-info">Port {{ port }}</div>
                        <div class="service-name">{{ service }} Service Detected</div>
                        <div class="banner-text">{{ banner }}</div>
                        <div class="remediation">
                            <span class="remediation-label">Remediation Guide</span>
                            {{ threat }}
                        </div>
                        <div class="ai-hint">
                            🔍 Click card for AI-powered deep analysis (Gemini)
                        </div>
                    </div>
                {% endfor %}
            </div>

            {% if not results %}
                <div style="text-align: center; padding: 40px; background: var(--bg-card); border-radius: 12px;">
                    <p style="color: var(--accent); font-weight: 600;">No open ports found.</p>
                </div>
            {% endif %}
        {% endif %}

        <footer>
            VulnX Security Engine • Enterprise Version 2.0 • 2025
        </footer>
    </div>

    <script>
    function fetchGeminiDetails(port, service, banner, severity) {
        fetch('/gemini-details', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port, service, banner, severity })
        })
        .then(res => {
            if (!res.ok) throw new Error('Network error');
            return res.text();
        })
        .then(text => {
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.85); display: flex; align-items: center;
                justify-content: center; z-index: 9999;
            `;
            modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

            const content = document.createElement('div');
            content.style.cssText = `
                background: var(--bg-card); padding: 30px; border-radius: 12px;
                max-width: 700px; max-height: 80vh; overflow-y: auto;
                border: 1px solid var(--border);
            `;
            content.innerHTML = `
                <h3 style="color: var(--accent); margin-bottom: 15px;">
                    🔍 Gemini AI Analysis — Port ${port} (${service})
                </h3>
                <pre style="white-space: pre-wrap; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; line-height: 1.5;">${text}</pre>
                <button onclick="this.closest('div').parentElement.remove()"
                        style="margin-top: 20px; padding: 10px 20px; background: var(--accent); color: black; border: none; border-radius: 8px; cursor: pointer; font-weight: 600;">
                    Close
                </button>
            `;

            modal.appendChild(content);
            document.body.appendChild(modal);
        })
        .catch(err => {
            alert('Failed to get AI analysis: ' + err.message);
        });
    }
    </script>
</body>
</html>
"""

SUBDOMAIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Finder - VulnX</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { background: #0a0c10; font-family: Inter; color: white; }
        .container { max-width: 750px; margin: 50px auto; background:#12151c; padding:30px; border-radius:12px; }
        input[type=text]{width:100%;padding:13px;border-radius:8px;border:1px solid #232833;background:#0d1117;color:white;}
        button{margin-top:20px;width:100%;background:#10b981;color:black;padding:14px;border-radius:8px;border:none;font-weight:600;cursor:pointer;}
        .result-box{background:#010409;padding:15px;border-radius:8px;border:1px solid #232833;margin-top:20px;font-family:monospace;}
        a{color:#10b981;text-decoration:none;}
    </style>
</head>
<body>
    <div style="padding:20px">
        <a href="/">← Back to Dashboard</a>
    </div>

    <div class="container">
        <h2>🔍 Subdomain Finder</h2>
        <p>Find valid subdomains associated with any hostname</p>

        <form method="post">
            <input type="text" name="domain" placeholder="example.com" required>
            <button type="submit">Find Subdomains</button>
        </form>

        {% if subdomains %}
        <div class="result-box">
            {% for sub in subdomains %}
                <div>✔ {{ sub }}</div>
            {% endfor %}
        </div>
        {% endif %}

        {% if message %}
        <div class="result-box">{{ message }}</div>
        {% endif %}
    </div>

</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    # Default empty state
    results = None
    original_target = ""
    resolved_ip = None
    deep_scan = False
    log_lines = []

    if request.method == 'POST':
        # Only process and keep data when form is submitted
        original_target = request.form['target'].strip()
        deep_scan = 'deep' in request.form

        resolved_ip, _ = resolve_target(original_target)
       
        log_lines = [
            f"Initializing scan for {original_target}...",
            f"Target resolved to {resolved_ip}" if resolved_ip else "DNS resolution failed."
        ]
       
        if resolved_ip:
            log_lines.append(f"Scanning {'1024 ports' if deep_scan else 'top common ports'}...")
            results = scan_target(resolved_ip, deep_scan)
            log_lines.append(f"Scan complete. {len(results)} open ports identified.")
        else:
            results = []
            log_lines.append("Scan aborted due to resolution failure.")

    # On GET (refresh or first load), everything is reset above — no old data kept

    return render_template_string(
        HTML_TEMPLATE,
        results=results,
        original_target=original_target if request.method == 'POST' else "",  # Clear input on refresh
        resolved_ip=resolved_ip,
        deep_scan=deep_scan,
        log_lines=log_lines
    )

def check_subdomain(domain, sub):
    try:
        socket.gethostbyname(f"{sub}.{domain}")
        return True
    except:
        return False

@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_page():
    subdomains = []
    message = ""
    
    default_list = [
        "www", "mail", "ftp", "dev", "test", "cpanel", 
        "api", "blog", "shop", "admin", "beta", "stage"
    ]

    if request.method == "POST":
        domain = request.form.get("domain").strip()

        if domain:
            for sub in default_list:
                full = f"{sub}.{domain}"
                if check_subdomain(domain, sub):
                    subdomains.append(full)

            if not subdomains:
                message = "❌ No subdomains detected"

    return render_template_string(
        SUBDOMAIN_TEMPLATE,
        subdomains=subdomains,
        message=message
    )



load_dotenv()

# Configure once
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
    print("Gemini API key loaded successfully.")
else:
    print("ERROR: GEMINI_API_KEY not found in .env file!")


@app.route('/gemini-details', methods=['POST'])
def gemini_details():
    try:
        data = request.get_json(force=True)
    except:
        return "Invalid JSON data sent.", 400

    port = data.get("port", "Unknown")
    service = data.get("service", "Unknown")
    banner = data.get("banner", "Unknown")
    severity = data.get("severity", "Low")

    prompt = f"""
You are a world-class cybersecurity expert. Analyze the following target port:

Port: {port}
Service: {service}
Banner: {banner}
Severity: {severity}

Provide a deep analysis including:
1️⃣ Real security risks  
2️⃣ Possible exploits  
3️⃣ Vulnerability explanations  
4️⃣ CVE notes (if applicable)  
5️⃣ MITRE tags  
6️⃣ Remediation plan  
7️⃣ Risk score  

Keep the answer technical, professional, and to the point.
    """

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content([prompt])

        if hasattr(response, "text") and response.text:
            return response.text, 200
        else:
            return "Gemini returned no usable text output.", 200

    except Exception as e:
        return f"[Gemini ERROR] {str(e)}", 500




if __name__ == '__main__':
    print("VulnX is starting...")
    print("Open your browser: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)