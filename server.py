from flask import Flask, request, render_template_string, session, redirect, url_for
import socket
import time
import threading
import logging
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate random secret key for sessions

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

def is_authenticated():
    """Check if user is authenticated"""
    return session.get('authenticated', False)

def require_auth():
    """Decorator to require authentication"""
    if not is_authenticated():
        return redirect(url_for('login'))
    return None

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
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WOL Controller - Login</title>
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
        .form-group {
            margin: 15px 0;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .btn { 
            padding: 15px 30px; 
            font-size: 18px; 
            margin: 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
        }
        .btn-login { background: #4CAF50; color: white; }
        .btn-status { background: #2196F3; color: white; text-decoration: none; display: inline-block; }
        .btn:hover { opacity: 0.8; }
        .error {
            color: #f44336;
            background: #ffebee;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .info { font-size: 12px; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WOL Controller Login</h1>
        <p><strong>Your PC</strong></p>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-login">LOGIN</button>
        </form>
        
        <br>
        <a href="/status" class="btn btn-status">VIEW STATUS (PUBLIC)</a>
        
        <div class="info">
            <p>Enter password to access Wake and Admin functions</p>
        </div>
    </div>
</body>
</html>
"""

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
        .btn-logout { background: #f44336; color: white; }
        .btn:hover { opacity: 0.8; }
        .status-box {
            background: #f9f9f9;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
        }
        .error { border-left-color: #f44336; }
        .success { 
            background: #e8f5e8;
            color: #2e7d32;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        .info { font-size: 12px; color: #666; margin-top: 20px; }
        .nav-links {
            margin: 20px 0;
        }
        .nav-links a {
            margin: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ WOL Controller</h1>
        <p><strong>Your PC</strong></p>
        
        {% if message %}
        <div class="success">{{ message }}</div>
        {% endif %}
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <div class="nav-links">
            <a href="/wake" class="btn btn-wake">WAKE COMPUTER</a><br>
            <a href="/admin" class="btn btn-admin">ADMIN PANEL</a><br>
            <a href="/status" class="btn btn-status">STATUS</a><br>
            <a href="/logout" class="btn btn-logout">LOGOUT</a>
        </div>
        
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
    auth_check = require_auth()
    if auth_check:
        return auth_check
        
    return render_template_string(HTML_TEMPLATE, 
                                last_wol=last_wol_time, 
                                wol_count=wol_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('home'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid password")
    
    # If already authenticated, redirect to home
    if is_authenticated():
        return redirect(url_for('home'))
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))

@app.route('/wake')
def wake():
    auth_check = require_auth()
    if auth_check:
        return auth_check
    
    success, packets = send_wol_packet()
    
    if success:
        message = f"✅ WOL Sent Successfully! Packets sent: {packets} at {last_wol_time}"
        return render_template_string(HTML_TEMPLATE, 
                                    message=message,
                                    last_wol=last_wol_time, 
                                    wol_count=wol_count)
    else:
        error = "❌ WOL Failed - Could not send magic packet"
        return render_template_string(HTML_TEMPLATE, 
                                    error=error,
                                    last_wol=last_wol_time, 
                                    wol_count=wol_count)

@app.route('/status')
def status():
    internet = "🟢 Connected" if check_internet() else "🔴 Disconnected"
    server_status = "🟢 Running" if server_running else "🔴 Stopped"
    
    return f'''
    <div class="container">
        <h1>📊 System Status (Public)</h1>
        <div class="status-box">
            <strong>Internet:</strong> {internet}<br>
            <strong>Server:</strong> {server_status}<br>
            <strong>Connection Status:</strong> {connection_status}<br>
            <strong>WOL Count:</strong> {wol_count}<br>
            <strong>Last WOL:</strong> {last_wol_time or "Never"}
        </div>
        <div class="nav-links">
            <a href="/login" class="btn btn-status">← Login</a>
            {'<a href="/" class="btn btn-admin">← Dashboard</a>' if is_authenticated() else ''}
        </div>
    </div>
    <style>
        body {{ font-family: Arial; text-align: center; margin: 20px; background: #f0f0f0; }}
        .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .btn {{ padding: 15px 30px; font-size: 18px; margin: 10px; border: none; border-radius: 5px; text-decoration: none; display: inline-block; cursor: pointer; }}
        .btn-status {{ background: #2196F3; color: white; }}
        .btn-admin {{ background: #ff9800; color: white; }}
        .btn:hover {{ opacity: 0.8; }}
        .status-box {{ background: #f9f9f9; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }}
        .nav-links {{ margin: 20px 0; }}
        .nav-links a {{ margin: 5px; }}
    </style>
    '''

@app.route('/admin')
def admin():
    auth_check = require_auth()
    if auth_check:
        return auth_check
    
    return f'''
    <div class="container">
        <h1>⚙️ Admin Panel</h1>
        <div class="status-box">
            <strong>Server Configuration:</strong><br>
            Port: {SERVER_PORT}<br>
            MAC: {TARGET_MAC}<br>
            Target IPs: {", ".join(TARGET_IPS)}<br>
            WOL Ports: {", ".join(map(str, WOL_PORTS))}<br>
            Session Active: ✅
        </div>
        
        <div class="nav-links">
            <a href="/wake" class="btn btn-wake">Send WOL</a><br>
            <a href="/status" class="btn btn-status">View Status</a><br>
            <a href="/" class="btn btn-admin">← Dashboard</a><br>
            <a href="/logout" class="btn btn-logout">Logout</a>
        </div>
    </div>
    <style>
        body {{ font-family: Arial; text-align: center; margin: 20px; background: #f0f0f0; }}
        .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .btn {{ padding: 15px 30px; font-size: 18px; margin: 10px; border: none; border-radius: 5px; text-decoration: none; display: inline-block; cursor: pointer; }}
        .btn-wake {{ background: #4CAF50; color: white; }}
        .btn-status {{ background: #2196F3; color: white; }}
        .btn-admin {{ background: #ff9800; color: white; }}
        .btn-logout {{ background: #f44336; color: white; }}
        .btn:hover {{ opacity: 0.8; }}
        .status-box {{ background: #f9f9f9; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }}
        .nav-links {{ margin: 20px 0; }}
        .nav-links a {{ margin: 5px; }}
    </style>
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
