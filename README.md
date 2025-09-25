# WOL Controller

Advanced Wake-on-LAN controller with secure session-based authentication and auto-reconnect functionality.

## Features

- 🖥️ **Wake-on-LAN**: Remote computer wake-up with magic packets
- 🔐 **Secure Authentication**: Session-based login system (no passwords in URLs)
- 📱 **Mobile-Friendly**: Responsive web interface optimized for all devices
- 🔄 **Auto-Reconnect**: Automatic server restart after internet connection loss
- 📊 **Public Status Monitor**: Real-time connection and system status (publicly accessible)
- ⚙️ **Admin Panel**: Configuration management and system information
- 🚀 **Clean Navigation**: No automatic redirects, user-controlled navigation
- ✅ **Success Feedback**: Clear success/error messages for all actions

## Target Configuration

- **Computer**: My PC
- **MAC Address**: 24-4B-FE-07-0C-E2
- **IP Addresses**: 192.168.1.25, 192.168.1.255 (broadcast)
- **WOL Ports**: 7, 9
- **Server Port**: 5000
- **Default Password**: CHANGE_YOUR_PASSWORD ⚠️

## Security Features

- ✅ **Session Management**: Secure login with Flask sessions
- ✅ **No URL Passwords**: Credentials never exposed in URLs
- ✅ **Protected Routes**: Wake and Admin functions require authentication
- ✅ **Public Status**: System status remains publicly accessible
- ✅ **Auto-Logout**: Clean session termination
- ✅ **Random Secret Key**: Cryptographically secure session encryption

## Installation

### Requirements
- Python 3.6+
- Flask library

### Setup Steps

1. **Install Flask**:
   ```bash
   pip install flask
   ```

2. **Configure the script**:
   - Edit `PASSWORD` in the script (line 14)
   - Update `TARGET_MAC` with your computer's MAC address
   - Adjust `TARGET_IPS` and `WOL_PORTS` if needed

3. **Run the server**:
   ```bash
   python server.py
   ```

### For Android (Pydroid 3)
1. Install **Pydroid 3** from Google Play Store
2. In Pydroid 3 terminal: `pip install flask`
3. Copy `server.py` to your device
4. Run: `python server.py`

## Usage

### Access Points
- **Local**: `http://localhost:5000`
- **Network**: `http://your-ip:5000`

### Authentication Flow
1. **Visit homepage** → Redirected to login if not authenticated
2. **Enter password** → Creates secure session
3. **Access dashboard** → Full functionality available
4. **Use features** → Wake, Admin, Status all accessible
5. **Logout** → Clears session securely

### Available Pages

| Page | Access | Description |
|------|--------|-------------|
| `/` | Protected | Main dashboard with all controls |
| `/login` | Public | Login form for authentication |
| `/wake` | Protected | Send WOL packets to target computer |
| `/admin` | Protected | Server configuration and management |
| `/status` | Public | System status (internet, server, WOL stats) |
| `/logout` | Protected | Terminate session and logout |

## Configuration

### Network Settings
```python
TARGET_MAC = "244BFE070CE2"           # Your computer's MAC address
TARGET_IPS = ["192.168.1.25", "192.168.1.255"]  # Direct + broadcast IPs
WOL_PORTS = [7, 9]                    # Wake-on-LAN ports
SERVER_PORT = 5000                    # Web server port
```

### Security Settings
```python
PASSWORD = "YOUR_SECURE_PASSWORD"     # Change this immediately!
```

## How It Works

1. **Connection Monitoring**: Background thread monitors internet connectivity
2. **Auto-Recovery**: Server automatically restarts after connection loss
3. **Magic Packets**: WOL packets sent to multiple IP/port combinations
4. **Session Security**: Flask sessions with cryptographic signing
5. **Multi-Target**: Supports direct IP and broadcast addresses

## Troubleshooting

### Common Issues

**Authentication Problems**:
- Ensure you've changed the default password
- Clear browser cookies/cache
- Check for typos in password

**WOL Not Working**:
- Verify target computer's MAC address
- Enable WOL in BIOS/UEFI settings
- Check network configuration (same subnet)
- Ensure target computer supports WOL

**Connection Issues**:
- Verify server is running on correct port
- Check firewall settings
- Ensure devices are on same network

### Logs
Check console output for detailed logging:
- Connection status changes
- WOL packet transmission results
- Server restart notifications
- Error details

## Development

### File Structure
```
server.py           # Main application
README.md          # This documentation
```

### Key Components
- **Flask Web Server**: HTTP interface
- **Session Management**: Secure authentication
- **WOL Implementation**: Magic packet generation
- **Connection Monitor**: Background connectivity check
- **HTML Templates**: Embedded responsive UI

## License

This project is open source. Modify and distribute freely.

## Security Notice

⚠️ **Important**: Change the default password before deployment!

⚠️ **Network Security**: This tool sends network packets - ensure you have permission to wake target devices.

---

**Version**: 2.0 (Session-Based Authentication)  
**Compatibility**: Python 3.6+, Flask 1.0+
