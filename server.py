from flask import Flask, request, render_template_string
import socket
import time
import threading
import logging
from datetime import datetime

app = Flask(__name__)

# Konfiguracja
PASSWORD = "CHANGE_YOUR_PASSWORD"
TARGET_MAC = "244BFE070CE2"
TARGET_IPS = ["192.168.1.25", "192.168.1.255"]
WOL_PORTS = [7, 9]
SERVER_PORT = 5000

# Zmienne globalne
server_running = False
connection_status = "UNKNOWN"
last_wol_time = None
wol_count = 0

# Logowanie
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_internet():
    """Sprawdź połączenie internetowe"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except:
        return False

def monitor_connection():
    """Monitor połączenia w tle"""
    global server_running, connection_status
    
    while True:
        if check_internet():
            if connection_status != "OK":
                logger.info("Internet connection restored")
                connection_status = "OK"
            
            if not server_running:
                logger.info("Restarting server...")
                try:
                    server_running = True
                    app.run(host='0.0.0.0', port=SERVER_PORT, debug=False, use_reloader=False)
                except Exception as e:
                    logger.error(f"Server restart failed: {e}")
                    server_running = False
        else:
            if connection_status != "DISCONNECTED":
                logger.warning("Internet connection lost")
                connection_status = "DISCONNECTED"
                server_running = False
            time.sleep(10)
        
        time.sleep(30)

def send_wol_packet():
    """Wyślij pakiet Wake-on-LAN"""
    global last_wol_time, wol_count
    
    try:
        mac_bytes = bytes.fromhex(TARGET_MAC)
        magic_packet = b'\xFF' * 6 + mac_bytes * 16
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        packets_sent = 0
        for ip in TARGET_IPS:
            for port in WOL_PORTS:
                try:
                    sock.sendto(magic_packet, (ip, port))
                    packets_sent += 1
                    logger.info(f"WOL packet sent to {ip}:{port}")
                except Exception as e:
                    logger.error(f"Failed to send to {ip}:{port} - {e}")
        
        sock.close()
        
        last_wol_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        wol_count += 1
        
        return True, packets_sent
    except Exception as e:
        logger.error(f"WOL sending failed: {e}")
        return False, 0

# Template HTML
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WOL Controller</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial; 
            text-align: center; 
            margin: 20px;
            background: #f0f0f0;
        }
        .container {
            max-width: 400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .btn { 
            padding: 15px 30px; 
            font-size: 18px; 
            margin: 10px;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            display: inline-block;
            cursor: pointer;
        }
        .btn-wake { background: #4CAF50; color: white; }
        .btn-status { background: #2196F3; color: white; }
        .btn-admin { background: #ff9800; color: white; }
        .btn:hover { opacity: 0.8; }
        .status-box {
            background: #f9f9f9;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
        }
        .error { border-left-color: #f44336; }
        .info { font-size: 12px; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ WOL Controller</h1>
        <p><strong>DESKTOP-N947VL2</strong></p>
        
        <a href="/wake?pass={{ password }}" class="btn btn-wake">WAKE COMPUTER</a><br>
        <a href="/status" class="btn btn-status">STATUS</a><br>
        <a href="/admin?pass={{ password }}" class="btn btn-admin">ADMIN</a>
        
        <div class="info">
            <p>MAC: 24-4B-FE-07-0C-E2</p>
            <p>IP: 192.168.1.25</p>
            {% if last_wol %}
            <p>Last WOL: {{ last_wol }}</p>
            <p>Total WOL sent: {{ wol_count }}</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, 
                                password=PASSWORD, 
                                last_wol=last_wol_time, 
                                wol_count=wol_count)

@app.route('/wake')
def wake():
    if request.args.get('pass') != PASSWORD:
        return '<h1>❌ Unauthorized</h1><p>Invalid password</p>', 401
    
    success, packets = send_wol_packet()
    
    if success:
        return f'''
        <div class="container">
            <h1>✅ WOL Sent Successfully</h1>
            <p>Packets sent: {packets}</p>
            <p>Target: DESKTOP-N947VL2 (192.168.1.25)</p>
            <p>Time: {last_wol_time}</p>
            <br>
            <a href="/" class="btn btn-status">← Back</a>
        </div>
        <style>{HTML_TEMPLATE.split('<style>')[1].split('</style>')[0]}</style>
        '''
    else:
        return f'''
        <div class="container">
            <h1>❌ WOL Failed</h1>
            <p>Could not send magic packet</p>
            <br>
            <a href="/" class="btn btn-status">← Back</a>
        </div>
        <style>{HTML_TEMPLATE.split('<style>')[1].split('</style>')[0]}</style>
        '''

@app.route('/status')
def status():
    internet = "🟢 Connected" if check_internet() else "🔴 Disconnected"
    server_status = "🟢 Running" if server_running else "🔴 Stopped"
    
    return f'''
    <div class="container">
        <h1>📊 System Status</h1>
        <div class="status-box">
            <strong>Internet:</strong> {internet}<br>
            <strong>Server:</strong> {server_status}<br>
            <strong>Connection Status:</strong> {connection_status}<br>
            <strong>WOL Count:</strong> {wol_count}<br>
            <strong>Last WOL:</strong> {last_wol_time or "Never"}
        </div>
        <a href="/" class="btn btn-status">← Back</a>
    </div>
    <style>{HTML_TEMPLATE.split('<style>')[1].split('</style>')[0]}</style>
    '''

@app.route('/admin')
def admin():
    if request.args.get('pass') != PASSWORD:
        return '<h1>❌ Unauthorized</h1>', 401
    
    return f'''
    <div class="container">
        <h1>⚙️ Admin Panel</h1>
        <div class="status-box">
            <strong>Server Config:</strong><br>
            Port: {SERVER_PORT}<br>
            MAC: {TARGET_MAC}<br>
            Target IPs: {", ".join(TARGET_IPS)}<br>
            WOL Ports: {", ".join(map(str, WOL_PORTS))}
        </div>
        
        <a href="/wake?pass={PASSWORD}" class="btn btn-wake">Test WOL</a><br>
        <a href="/status" class="btn btn-status">Status</a><br>
        <a href="/" class="btn btn-admin">← Back</a>
    </div>
    <style>{HTML_TEMPLATE.split('<style>')[1].split('</style>')[0]}</style>
    '''

@app.route('/logs')
def logs():
    return '<h1>Logs would be here</h1><a href="/">← Back</a>'

if __name__ == '__main__':
    logger.info("Starting WOL Controller...")
    logger.info(f"Password protection enabled")
    logger.info(f"Target: {TARGET_MAC} -> {TARGET_IPS}")
    
    # Uruchom monitor połączenia w tle
    monitor_thread = threading.Thread(target=monitor_connection, daemon=True)
    monitor_thread.start()
    
    server_running = True
    connection_status = "OK" if check_internet() else "DISCONNECTED"
    
    try:
        app.run(host='0.0.0.0', port=SERVER_PORT, debug=False)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
