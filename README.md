# Parental Control & Monitoring Dashboard

A powerful, cross-platform Parental Control utility featuring an intuitive Electron-based dashboard and a robust Python backend. It provides comprehensive system multi-level monitoring and restriction capabilities.

## Features
- **Interactive Dashboard**: Modern UI to view logs, analytics, and manage settings.
- **Website Blocking**: Manage a custom list of blocked domains with automatic subdomain expansion (`www.`, `m.`, etc.).
- **DoH Bypass Prevention** (Windows): Disables Chrome Secure DNS and blocks known DoH servers via firewall.
- **App Blocker**: Terminate specific applications during "Focus Time".
- **Keylogger**: Stealthily monitor keystrokes.
- **History Analysis**: Extract and view top visited domains natively from Chrome.
- **Screenshots**: Automatically capture screen activity at defined intervals.
- **Encrypted Storage**: Local data is stored securely via AES encryption.

## Prerequisites
- **Node.js**: Required to run the Electron frontend.
- **Python 3.8+**: Required for the backend server.

## Setup & Installation

### 1. Install Dependencies
Install Python packages required by the backend:
```bash
pip install -r requirements.txt
```
Install Node.js packages for the frontend dashboard:
```bash
npm install
```

### 2. Running the Application
The capabilities of the application require **Administrator/Root privileges** to modify system files (like the hosts file) and inject firewall rules.

Launch the application (this handles the privilege elevation prompt automatically):
```powershell
npm start
```
Or run the dashboard in dev mode:
```powershell
npm run dev
```

### 3. Building the Executable
To package a standalone executable installer (e.g. for Windows):
```powershell
npm run build:nsis
```
This requires `electron-builder` and generates the installer in the `dist` folder.

## Support & Troubleshooting
- **Permission Denied**: Ensure you are running the application with elevated privileges.
- **Chrome History Error**: Close Chrome before running history analysis to unlock the SQLite database.
- **Missing Features**: Check that optional dependencies in `requirements.txt` are perfectly installed.
- **Sites Still Accessible**: Disable DNS-over-HTTPS in target browsers (Settings → Privacy → Secure DNS → Off).
