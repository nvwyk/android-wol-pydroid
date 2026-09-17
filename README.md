# WOL Controller

Advanced Wake-on-LAN controller with secure session-based authentication and auto-reconnect functionality.

## Features

- 🖥️ **Wake-on-LAN**: Remote computer wake-up with magic packets
- 🔐 **Secure Authentication**: Session-based login system (no passwords in URLs)
- 📱 **Mobile-Friendly**: Responsive web interface optimized for all devices
- 🔄 **Self-Updating**: `launcher.py` pulls new `server.py` versions from GitHub, health-checks them and rolls back broken ones
- 🐕 **Watchdog**: Crashed server is restarted automatically with backoff
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

2. **Run it once** so `config.json` is created next to `server.py`, then edit `config.json` (see [Configuration](#configuration)).

3. **Run the server** with automatic updates:
   ```bash
   python launcher.py
   ```
   or without the updater: `python server.py`

### For Android (Pydroid 3)
1. Install **Pydroid 3** from Google Play Store
2. In Pydroid 3 terminal: `pip install flask`
3. Copy `launcher.py` and `server.py` into the same folder on your device
4. Run `python launcher.py --selftest` once. Every check should say PASS.
5. Open `launcher.py` in Pydroid and press Run. Keep it running; it starts `server.py` itself.

**Upgrading from the old single-file setup:** copy `launcher.py` next to your existing, edited
`server.py` and run the launcher. Before anything is replaced, it copies `PASSWORD`, `TARGET_MAC`,
`TARGET_IPS`, `WOL_PORTS` and `SERVER_PORT` from the old file into `config.json`. The old file is kept
as `server.py.bak`. If you replace `server.py` by hand instead, write `config.json` yourself first.

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
| `/status` | Public | System status (internet, version, WOL stats) |
| `/health` | Public | JSON liveness check used by the launcher |
| `/logout` | Protected | Terminate session and logout |

## Configuration

Settings live in `config.json` next to `server.py`. It is never committed and never touched by updates.
Restart the launcher after editing it.

```json
{
  "password": "YOUR_SECURE_PASSWORD",
  "target_mac": "244BFE070CE2",
  "target_ips": ["192.168.1.25", "192.168.1.255"],
  "wol_ports": [7, 9],
  "server_port": 5000,
  "secret_key": "generated automatically"
}
```

`secret_key` is generated on first start and keeps you logged in across restarts and updates.

## How It Works

1. **Magic Packets**: WOL packets sent to multiple IP/port combinations
2. **Session Security**: Flask sessions with cryptographic signing
3. **Connection Monitoring**: Background thread shows internet state on `/status`. The web server keeps serving the LAN when the internet is down.

### Automatic updates (`launcher.py`)

Every 5 minutes the launcher asks GitHub for the latest commit on `main` (a response of about 40 bytes;
60 unauthenticated requests per hour are allowed, this uses 12). Only when that commit changes
`server.py` does it:

1. Download `server.py` pinned to that commit and verify it against GitHub's git hash
2. Check the Python syntax; on failure the running version is left alone
3. Save the current file as `server.py.bak`, stop the server, swap in the new file atomically
4. Start the new server and wait up to 90 s for `/health` to answer from that exact process
5. On failure restore `server.py.bak`, restart it, and remember the bad version so it is not retried until a new `server.py` is pushed

Commits that only touch other files (README etc.) cause no restart. Local edits to `server.py` are
overwritten by the next update; put device-specific changes in `config.json`.
`launcher.py` never updates itself. Copy new versions of it to the phone by hand.

Updater state is kept in `state.json`. Output goes to the Pydroid console only, nothing is logged to disk.

### Limits

- Updates only happen while Pydroid is running. If you stop Pydroid, Android kills it, or the phone
  reboots, nothing runs until you press Run on `launcher.py` again. A Pydroid-relaunch automation app
  would be needed for that; it is not part of this project.
- If the launcher is killed, `server.py` notices within 5 seconds and exits, so a new Run does not hit
  "address already in use".
- Without internet, update checks fail quietly and are retried every 5 minutes; WOL on the LAN keeps working.

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
launcher.py        # Supervisor: watchdog + GitHub updater (run this)
server.py          # Flask WOL application (updated from GitHub)
config.json        # Local settings (created on first run, git-ignored)
state.json         # Local updater state (git-ignored)
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
