# Android WOL Controller

Advanced Wake-on-LAN controller for Android devices with auto-reconnect and password protection.

## Features

- 🖥️ **Wake-on-LAN**: Remote computer wake-up
- 🔐 **Password Protection**: Secure access with password
- 📱 **Mobile-Friendly**: Responsive web interface  
- 🔄 **Auto-Reconnect**: Automatic server restart after WiFi loss
- 📊 **Status Monitor**: Real-time connection and system status
- ⚙️ **Admin Panel**: Configuration and management

## Target Configuration

- **Computer**: DESKTOP-N947VL2
- **MAC Address**: 24-4B-FE-07-0C-E2
- **IP Address**: 192.168.1.25
- **Password**: Password

## Installation (Pydroid 3)

1. Install **Pydroid 3** from Google Play Store
2. In Pydroid 3, install Flask: `pip install flask`
3. Copy `server.py` to your Pydroid 3 files
4. Run the script: `python server.py`

## Usage

Access the controller at:
- **Local**: `http://localhost:5000`
- **Network**: `http://your-domain:5000`

### Endpoints

- `/` - Main interface
- `/wake?pass=Password` - Wake computer
- `/status` - System status  
- `/admin?pass=Password` - Admin panel

## Requirements

- Python 3.6+
- Flask
- Android 8.0+ (for Pydroid 3)
