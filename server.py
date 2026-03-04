# server.py - Flask Backend for Parental Control Dashboard
import os
import sys

# Ensure local modules (like database.py) can be imported
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# REDIRECT OUTPUT FOR DEBUGGING (Development only)
# sys.stdout = open(os.path.join(BASE_DIR, "runtime_server_log.txt"), "a", buffering=1)
# sys.stderr = sys.stdout

import json
import re
import shutil
import sqlite3
import subprocess
import threading
import time as _time
import hashlib
import secrets
import functools
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import Counter
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_cors import CORS
from database import EncryptedDB

# ==============================================================================
# APP CONFIGURATION
# ==============================================================================

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -- File paths --
BLOCKED_SITES_FILE = os.path.join(BASE_DIR, "blocked_sites.txt")
LOG_FILE = os.path.join(BASE_DIR, "key_log.txt")
SCREENSHOT_FOLDER = os.path.join(BASE_DIR, "screenshots")

# -- App Blocker settings --
BLOCKED_APPS_FILE = os.path.join(BASE_DIR, "blocked_apps.json")
DEFAULT_BLOCKED_APPS = ["brave", "firefox", "mspaint"]

# -- Focus time settings --
FOCUS_START_HOUR = 21  # 9 PM
FOCUS_END_HOUR = 23    # 11 PM

# -- Hosts file --
def get_hosts_path():
    if sys.platform == "win32":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"

HOSTS_PATH = get_hosts_path()
REDIRECT_IP = "127.0.0.1"
SUBDOMAIN_PREFIXES = ["", "www.", "m.", "api.", "mobile.", "accounts."]

# -- State tracking --
blocker_thread = None
blocker_active = False
keylogger_thread = None
keylogger_active = False
risk_scanner_thread = None
risk_scanner_active = False
time_tracker_thread = None
time_tracker_active = False
alert_checker_thread = None
alert_checker_active = False

# -- Database --
db = EncryptedDB()

# -- Risk scanner state --
_last_keylog_scan_pos = 0

# -- Authentication --
DASH_PASSWORD = os.environ.get('PARENTAL_DASH_PASS', 'admin123')
_password_hash = hashlib.pbkdf2_hmac('sha256', DASH_PASSWORD.encode(), b'parental_salt_2026', 200000).hex()
_active_sessions = {}  # token -> {created, expires}
SESSION_LIFETIME = 3600 * 8  # 8 hours

def verify_password(password):
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), b'parental_salt_2026', 200000).hex()
    return h == _password_hash

def create_session():
    token = secrets.token_hex(32)
    _active_sessions[token] = {
        'created': datetime.now().isoformat(),
        'expires': (_time.time() + SESSION_LIFETIME)
    }
    return token

def validate_session(token):
    if not token:
        return False
    session = _active_sessions.get(token)
    if not session:
        return False
    if _time.time() > session['expires']:
        del _active_sessions[token]
        return False
    return True

def require_auth(f):
    """Decorator to require authentication on API endpoints."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Auth-Token') or request.cookies.get('auth_token')
        if not validate_session(token):
            return jsonify({'error': 'Authentication required', 'auth_required': True}), 401
        return f(*args, **kwargs)
    return decorated


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# -- File paths --
BLOCKED_SITES_FILE = os.path.join(BASE_DIR, "blocked_sites.json")

def load_blocked_sites():
    if not os.path.exists(BLOCKED_SITES_FILE):
        return []
    try:
        with open(BLOCKED_SITES_FILE, 'r') as f:
            data = json.load(f)
            # Migration from old txt file or old format list of strings
            if data and isinstance(data[0], str):
                return [{"site": s, "active": True} for s in data]
            return data
    except (PermissionError, json.JSONDecodeError):
        return []

def save_blocked_sites(sites):
    try:
        with open(BLOCKED_SITES_FILE, 'w') as f:
            json.dump(sites, f, indent=2)
    except PermissionError:
        try:
            os.remove(BLOCKED_SITES_FILE)
        except (PermissionError, OSError):
            pass
        with open(BLOCKED_SITES_FILE, 'w') as f:
            json.dump(sites, f, indent=2)

def load_blocked_apps():
    if not os.path.exists(BLOCKED_APPS_FILE):
        return DEFAULT_BLOCKED_APPS[:]
    with open(BLOCKED_APPS_FILE, 'r') as f:
        return json.load(f)

def save_blocked_apps(apps):
    with open(BLOCKED_APPS_FILE, 'w') as f:
        json.dump(apps, f)

def get_keylog_content():
    if not os.path.exists(LOG_FILE):
        return ""
    with open(LOG_FILE, 'r') as f:
        return f.read()

def extract_domain(url):
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def get_chrome_history_path():
    if sys.platform == "win32":
        return os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\History")
    elif sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History")
    elif sys.platform == "linux":
        return os.path.expanduser("~/.config/google-chrome/default/History")
    return None

def is_focus_time():
    current_hour = datetime.now().hour
    return FOCUS_START_HOUR <= current_hour < FOCUS_END_HOUR


# ==============================================================================
# WEBSITE BLOCKING CORE LOGIC
# ==============================================================================

def apply_blocks_to_hosts(sites):
    expanded = []
    for site in sites:
        if site.startswith("http://") or site.startswith("https://"):
            continue
        for prefix in SUBDOMAIN_PREFIXES:
            variant = f"{prefix}{site}"
            if variant not in expanded:
                expanded.append(variant)
    try:
        with open(HOSTS_PATH, 'r+') as f:
            content = f.read()
            if content and not content.endswith('\n'):
                f.write('\n')
            
            lines = content.splitlines()
            existing_sites = set()
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and not line.strip().startswith('#'):
                    existing_sites.add(parts[1])

            added = 0
            for site in expanded:
                if site not in existing_sites:
                    f.write(f"{REDIRECT_IP} {site}\n")
                    f.write(f"::1 {site}\n")
                    added += 1
                    
        # Flush DNS cache (Windows only)
        if sys.platform == "win32":
            os.system('ipconfig /flushdns > NUL 2>&1')
            
        return True, f"Blocked {added} entries"
    except PermissionError:
        return False, "Permission denied. Run with sudo."
    except Exception as e:
        return False, str(e)

def remove_blocks_from_hosts(sites):
    try:
        with open(HOSTS_PATH, 'r+') as f:
            lines = f.readlines()
            f.seek(0)
            for line in lines:
                is_blocked = False
                parts = line.split()
                if len(parts) >= 2 and not line.strip().startswith('#'):
                    domain = parts[1]
                    for site in sites:
                        if domain == site or domain.endswith('.' + site):
                            is_blocked = True
                            break
                if not is_blocked:
                    f.write(line)
            f.truncate()
            
        # Flush DNS cache (Windows only)
        if sys.platform == "win32":
            os.system('ipconfig /flushdns > NUL 2>&1')
            
        return True, "Sites unblocked"
    except PermissionError:
        return False, "Permission denied. Run with sudo."
    except Exception as e:
        return False, str(e)


# ==============================================================================
# DNS-OVER-HTTPS (DoH) BYPASS PREVENTION
# ==============================================================================

DOH_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]

def disable_chrome_secure_dns():
    """Disables Chrome's Secure DNS via Windows Registry (Windows only)."""
    if sys.platform != "win32":
        return False, "Only supported on Windows"
    try:
        import winreg
        key_path = r"SOFTWARE\Policies\Google\Chrome"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
        winreg.CloseKey(key)
        return True, "Chrome Secure DNS disabled via registry"
    except Exception as e:
        return False, f"Could not disable Chrome Secure DNS: {e}"

def enable_chrome_secure_dns():
    """Re-enables Chrome's Secure DNS via Windows Registry (Windows only)."""
    if sys.platform != "win32":
        return False, "Only supported on Windows"
    try:
        import winreg
        key_path = r"SOFTWARE\Policies\Google\Chrome"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "DnsOverHttpsMode")
        winreg.CloseKey(key)
        return True, "Chrome Secure DNS re-enabled"
    except Exception:
        return False, "Could not re-enable Chrome Secure DNS"

def block_doh_firewall():
    """Adds Windows Firewall rule to block known DoH servers (Windows only)."""
    if sys.platform != "win32":
        return False, "Only supported on Windows"
    try:
        ips = ",".join(DOH_SERVERS)
        os.system(f'netsh advfirewall firewall add rule name="BlockDoH_ParentalCtrl" dir=out action=block remoteip={ips} > NUL 2>&1')
        return True, "Firewall rule added to block DoH servers"
    except Exception as e:
        return False, f"Could not add firewall rule: {e}"

def unblock_doh_firewall():
    """Removes the DoH blocking firewall rule (Windows only)."""
    if sys.platform != "win32":
        return False, "Only supported on Windows"
    try:
        os.system('netsh advfirewall firewall delete rule name="BlockDoH_ParentalCtrl" > NUL 2>&1')
        return True, "Firewall DoH rule removed"
    except Exception:
        return False, "Could not remove firewall rule"


# ==============================================================================
# REAL-TIME BLOCKED SITE MONITORING (via Chrome history)
# ==============================================================================

_monitor_checked_urls = set()

def monitor_blocked_sites_in_history():
    """Scans recent Chrome history for visits to blocked sites, generates alerts."""
    global _monitor_checked_urls
    history_db = get_chrome_history_path()
    if not history_db or not os.path.exists(history_db):
        return
    tmp_db = os.path.join(BASE_DIR, "tmp_monitor")
    try:
        shutil.copy2(history_db, tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 20")
        rows = cursor.fetchall()
        blocked_sites = load_blocked_sites()
        active_blocked_domains = [s["site"] for s in blocked_sites if s.get("active", True)]
        for row in rows:
            url = row[0]
            domain = extract_domain(url)
            if domain in active_blocked_domains and url not in _monitor_checked_urls:
                db.add_alert("site_block", "high", f"Blocked site VISITED: {domain} ({url[:80]})")
                _monitor_checked_urls.add(url)
        conn.close()
        os.remove(tmp_db)
    except Exception:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)


# ==============================================================================
# APP BLOCKER CORE LOGIC
# ==============================================================================

def get_running_processes():
    """Get list of running process names (Linux)."""
    try:
        result = subprocess.run(['ps', '-eo', 'comm'], capture_output=True, text=True, timeout=5)
        return [line.strip().lower() for line in result.stdout.strip().split('\n')[1:] if line.strip()]
    except Exception:
        return []

def terminate_blocked_apps():
    apps = load_blocked_apps()
    running = get_running_processes()
    violated = []
    for app_name in apps:
        name = app_name.replace(".exe", "").lower()
        if any(name in proc for proc in running):
            violated.append(app_name)
            if sys.platform == "win32":
                os.system(f"taskkill /F /IM {app_name} > NUL 2>&1")
            else:
                os.system(f"pkill -f {name} > /dev/null 2>&1")
    return violated

def app_blocker_loop():
    global blocker_active
    while blocker_active:
        violated = terminate_blocked_apps()
        for app_name in violated:
            db.add_alert(
                "focus_violation",
                "high",
                f"Blocked app '{app_name}' was detected and terminated"
            )
        _time.sleep(15)


# ==============================================================================
# KEYLOGGER CORE LOGIC
# ==============================================================================

if sys.platform == "win32":
    try:
        from pynput import keyboard as pynput_keyboard
    except ImportError:
        pynput_keyboard = None
    evdev = None
    ecodes = None
else:
    try:
        import evdev
        from evdev import InputDevice, categorize, ecodes
    except ImportError:
        evdev = None
        ecodes = None
    try:
        from pynput import keyboard as pynput_keyboard
    except ImportError:
        pynput_keyboard = None


def find_keyboard_device():
    if evdev is None:
        return None
    devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
    for device in devices:
        capabilities = device.capabilities()
        if ecodes.EV_KEY in capabilities:
            keys = capabilities[ecodes.EV_KEY]
            if ecodes.KEY_A in keys and ecodes.KEY_ENTER in keys:
                return device
    return None


def evdev_keylogger_thread():
    global keylogger_active
    keyboard_device = find_keyboard_device()
    if keyboard_device is None:
        keylogger_active = False
        return

    KEY_MAP = {}
    if ecodes:
        KEY_MAP = {
            ecodes.KEY_A: 'a', ecodes.KEY_B: 'b', ecodes.KEY_C: 'c', ecodes.KEY_D: 'd',
            ecodes.KEY_E: 'e', ecodes.KEY_F: 'f', ecodes.KEY_G: 'g', ecodes.KEY_H: 'h',
            ecodes.KEY_I: 'i', ecodes.KEY_J: 'j', ecodes.KEY_K: 'k', ecodes.KEY_L: 'l',
            ecodes.KEY_M: 'm', ecodes.KEY_N: 'n', ecodes.KEY_O: 'o', ecodes.KEY_P: 'p',
            ecodes.KEY_Q: 'q', ecodes.KEY_R: 'r', ecodes.KEY_S: 's', ecodes.KEY_T: 't',
            ecodes.KEY_U: 'u', ecodes.KEY_V: 'v', ecodes.KEY_W: 'w', ecodes.KEY_X: 'x',
            ecodes.KEY_Y: 'y', ecodes.KEY_Z: 'z',
            ecodes.KEY_1: '1', ecodes.KEY_2: '2', ecodes.KEY_3: '3', ecodes.KEY_4: '4',
            ecodes.KEY_5: '5', ecodes.KEY_6: '6', ecodes.KEY_7: '7', ecodes.KEY_8: '8',
            ecodes.KEY_9: '9', ecodes.KEY_0: '0',
            ecodes.KEY_SPACE: ' ', ecodes.KEY_ENTER: '\n', ecodes.KEY_TAB: '\t',
            ecodes.KEY_MINUS: '-', ecodes.KEY_EQUAL: '=',
            ecodes.KEY_LEFTBRACE: '[', ecodes.KEY_RIGHTBRACE: ']',
            ecodes.KEY_SEMICOLON: ';', ecodes.KEY_APOSTROPHE: "'",
            ecodes.KEY_GRAVE: '`', ecodes.KEY_BACKSLASH: '\\',
            ecodes.KEY_COMMA: ',', ecodes.KEY_DOT: '.', ecodes.KEY_SLASH: '/',
        }

    shift_active = False
    try:
        for event in keyboard_device.read_loop():
            if not keylogger_active:
                break
            if event.type == ecodes.EV_KEY:
                key_event = categorize(event)
                if key_event.scancode in (ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT):
                    shift_active = (key_event.keystate == key_event.key_down)
                    continue
                if key_event.keystate == key_event.key_down:
                    if key_event.scancode == ecodes.KEY_BACKSPACE:
                        with open(LOG_FILE, "a") as f:
                            f.write("[BS]")
                        continue
                    char = KEY_MAP.get(key_event.scancode, '')
                    if char:
                        if shift_active and char.isalpha():
                            char = char.upper()
                        with open(LOG_FILE, "a") as f:
                            f.write(char)
    except Exception:
        pass
    keylogger_active = False


def pynput_keylogger_thread():
    global keylogger_active

    def on_press(key):
        if not keylogger_active:
            return False
        try:
            with open(LOG_FILE, "a") as f:
                f.write(key.char)
        except AttributeError:
            with open(LOG_FILE, "a") as f:
                if key == pynput_keyboard.Key.space:
                    f.write(" ")
                elif key == pynput_keyboard.Key.enter:
                    f.write("\n")
                elif key == pynput_keyboard.Key.backspace:
                    f.write("[BS]")

    with pynput_keyboard.Listener(on_press=on_press) as listener:
        listener.join()
    keylogger_active = False


# ==============================================================================
# RISK DETECTION ENGINE
# ==============================================================================

def scan_keylog_for_risks():
    """Scan keylog for risk keywords. Returns list of detections."""
    global _last_keylog_scan_pos
    if not os.path.exists(LOG_FILE):
        return []

    detections = []
    try:
        with open(LOG_FILE, 'r') as f:
            f.seek(_last_keylog_scan_pos)
            new_content = f.read()
            _last_keylog_scan_pos = f.tell()

        if not new_content.strip():
            return []

        # Clean up keylog content (remove [BS] markers)
        clean = re.sub(r'\[BS\]', '', new_content).lower()

        keywords = db.get_risk_keywords()
        for kw_row in keywords:
            keyword = kw_row['keyword'].lower()
            if keyword in clean:
                # Extract context (30 chars around the match)
                idx = clean.find(keyword)
                start = max(0, idx - 15)
                end = min(len(clean), idx + len(keyword) + 15)
                context = clean[start:end].strip()

                db.add_risk_event(keyword, context, kw_row['severity'])
                db.add_alert(
                    "risk_keyword",
                    kw_row['severity'],
                    f"Risk keyword '{keyword}' detected in keylog"
                )
                detections.append({"keyword": keyword, "severity": kw_row['severity']})
    except Exception as e:
        print(f"[RISK] Scan error: {e}")

    return detections


def risk_scanner_loop():
    """Background thread that scans keylogs every 10 seconds."""
    global risk_scanner_active
    while risk_scanner_active:
        if keylogger_active:
            scan_keylog_for_risks()
        _time.sleep(10)


# ==============================================================================
# ALERT CHECKER (focus violations, blocked site attempts)
# ==============================================================================

def alert_checker_loop():
    """Background thread that checks for violations."""
    global alert_checker_active
    while alert_checker_active:
        # Check focus time violations
        if is_focus_time():
            running = get_running_processes()
            blocked_apps = load_blocked_apps()
            for app_name in blocked_apps:
                name = app_name.replace(".exe", "").lower()
                if any(name in proc for proc in running):
                    db.add_alert(
                        "focus_violation",
                        "high",
                        f"App '{app_name}' detected running during focus time ({FOCUS_START_HOUR}:00-{FOCUS_END_HOUR}:00)"
                    )

        # Monitor Chrome history for blocked site visits
        try:
            monitor_blocked_sites_in_history()
        except Exception:
            pass

        _time.sleep(30)


# ==============================================================================
# TIME TRACKING ENGINE
# ==============================================================================

def get_active_window_info():
    """Get the currently active window name and process (Linux)."""
    try:
        # Try xdotool first (X11)
        wid = subprocess.run(
            ['xdotool', 'getactivewindow'], capture_output=True, text=True, timeout=2
        )
        if wid.returncode == 0:
            wname = subprocess.run(
                ['xdotool', 'getactivewindow', 'getwindowname'],
                capture_output=True, text=True, timeout=2
            )
            wpid = subprocess.run(
                ['xdotool', 'getactivewindow', 'getwindowpid'],
                capture_output=True, text=True, timeout=2
            )
            name = wname.stdout.strip() if wname.returncode == 0 else "Unknown"
            pid = wpid.stdout.strip() if wpid.returncode == 0 else ""

            # Get process name from PID
            proc_name = "unknown"
            if pid:
                try:
                    comm_path = f"/proc/{pid}/comm"
                    if os.path.exists(comm_path):
                        with open(comm_path, 'r') as f:
                            proc_name = f.read().strip()
                except Exception:
                    pass

            return {"window_title": name, "process": proc_name, "pid": pid}
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return None


def time_tracker_loop():
    """Background thread that tracks active window/app usage."""
    global time_tracker_active
    last_window = None
    last_switch_time = datetime.now()

    while time_tracker_active:
        info = get_active_window_info()
        if info:
            current = info['process']
            now = datetime.now()

            if current != last_window:
                # Record time for previous window
                if last_window:
                    duration = (now - last_switch_time).total_seconds()
                    if duration > 1:
                        db.add_app_usage(last_window, last_switch_time.isoformat(), duration)
                        db.update_time_tracking(last_window, "app", duration)

                        # Check if window title suggests a website
                        title = info.get('window_title', '')
                        for browser in ['firefox', 'chrome', 'chromium', 'brave']:
                            if browser in (last_window or '').lower():
                                # Extract domain-like info from title
                                parts = title.split(' - ')
                                if len(parts) > 1:
                                    domain_hint = parts[-2].strip() if len(parts) > 2 else parts[0].strip()
                                    db.update_time_tracking(domain_hint, "site", duration)

                last_window = current
                last_switch_time = now

        _time.sleep(5)


# ==============================================================================
# BROWSER HISTORY ANALYSIS (Enhanced with durations)
# ==============================================================================

def analyze_browser_history(top_n=10):
    history_db = get_chrome_history_path()
    if not history_db or not os.path.exists(history_db):
        return None, "Chrome history database not found"

    tmp_db = os.path.join(BASE_DIR, "tmp_chrome_history")
    try:
        shutil.copy2(history_db, tmp_db)
    except Exception as e:
        return None, f"Could not copy history DB: {e}"

    conn = None
    try:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        webkit_timestamp = int((seven_days_ago - datetime(1601, 1, 1)).total_seconds() * 1_000_000)

        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()

        # Enhanced query: get visit duration too
        query = """
            SELECT u.url, u.title, v.visit_time, v.visit_duration
            FROM urls u JOIN visits v ON u.id = v.url
            WHERE v.visit_time > ?
            ORDER BY v.visit_time DESC
        """
        cursor.execute(query, (webkit_timestamp,))
        rows = cursor.fetchall()

        domain_data = {}
        recent_visits = []

        for url, title, visit_time, visit_duration in rows:
            domain = extract_domain(url)
            if not domain:
                continue

            # visit_duration is in microseconds
            duration_sec = (visit_duration or 0) / 1_000_000

            if domain not in domain_data:
                domain_data[domain] = {"visits": 0, "total_time": 0}
            domain_data[domain]["visits"] += 1
            domain_data[domain]["total_time"] += duration_sec

            # Convert webkit timestamp to readable
            epoch_start = datetime(1601, 1, 1)
            visit_dt = epoch_start + timedelta(microseconds=visit_time)
            visit_str = visit_dt.strftime("%Y-%m-%d %H:%M")

            if len(recent_visits) < 30:
                recent_visits.append({
                    "domain": domain, "title": title or domain,
                    "visit_time": visit_str, "duration": round(duration_sec, 1)
                })

            # Store in encrypted DB
            db.add_site_visit(domain, visit_str, duration_sec, title or "")

        results = sorted(
            [{"domain": d, "visits": v["visits"], "total_time": round(v["total_time"], 1)}
             for d, v in domain_data.items()],
            key=lambda x: x["visits"], reverse=True
        )[:top_n]

        db.flush()
        return {"top_sites": results, "recent": recent_visits}, None

    except sqlite3.Error as e:
        return None, f"Database error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"
    finally:
        if conn:
            conn.close()
        if os.path.exists(tmp_db):
            os.remove(tmp_db)


# ==============================================================================
# SCREENSHOT LOGIC
# ==============================================================================

def take_screenshot():
    import pyscreeze
    from PIL import ImageGrab
    import os
    from datetime import datetime

    os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"screenshot_{timestamp}.png"
    filepath = os.path.join(SCREENSHOT_FOLDER, filename)
    try:
        # Use pyscreeze for consistent cross-platform behavior
        img = pyscreeze.screenshot()
        img.save(filepath)
        return filename, None
    except Exception as e:
        import traceback
        err = f"{str(e)}\n{traceback.format_exc()}"
        return None, err


def list_screenshots():
    if not os.path.exists(SCREENSHOT_FOLDER):
        return []
    files = sorted(os.listdir(SCREENSHOT_FOLDER), reverse=True)
    return [f for f in files if f.endswith('.png')]


# ==============================================================================
# FLASK ROUTES — FRONTEND SERVING
# ==============================================================================

@app.route('/')
def serve_index():
    return send_from_directory('frontend', 'dashboard.html')

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    return send_from_directory('frontend', filename)


# ==============================================================================
# FLASK ROUTES — AUTHENTICATION
# ==============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password', '')
    if verify_password(password):
        token = create_session()
        resp = jsonify({'success': True, 'token': token})
        resp.set_cookie('auth_token', token, max_age=SESSION_LIFETIME, httponly=True, samesite='Strict')
        return resp
    return jsonify({'success': False, 'error': 'Invalid password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.headers.get('X-Auth-Token') or request.cookies.get('auth_token')
    if token and token in _active_sessions:
        del _active_sessions[token]
    resp = jsonify({'success': True})
    resp.delete_cookie('auth_token')
    return resp

@app.route('/api/auth/check')
def auth_check():
    token = request.headers.get('X-Auth-Token') or request.cookies.get('auth_token')
    return jsonify({'authenticated': validate_session(token)})


# ==============================================================================
# FLASK ROUTES — API ENDPOINTS (all require auth)
# ==============================================================================

# --- Status ---
@app.route('/api/status')
@require_auth
def get_status():
    sites = load_blocked_sites()
    return jsonify({
        "blocked_sites_count": len(sites),
        "keylogger_active": keylogger_active,
        "app_blocker_active": blocker_active,
        "risk_scanner_active": risk_scanner_active,
        "time_tracker_active": time_tracker_active,
        "screenshot_count": len(list_screenshots()),
        "keylog_size": os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0,
        "unread_alerts": db.get_unread_alert_count(),
        "focus_time_active": is_focus_time(),
        "focus_hours": f"{FOCUS_START_HOUR}:00 - {FOCUS_END_HOUR}:00",
    })


# --- Blocked Sites ---
@app.route('/api/blocked-sites', methods=['GET'])
@require_auth
def get_blocked_sites():
    return jsonify({"sites": load_blocked_sites()})

@app.route('/api/blocked-sites', methods=['POST'])
@require_auth
def add_blocked_site():
    data = request.get_json()
    site = data.get('site', '').strip()
    if not site:
        return jsonify({"error": "No site provided"}), 400
    sites = load_blocked_sites()
    if any(s["site"] == site for s in sites):
        return jsonify({"error": "Site already blocked"}), 409
    sites.append({"site": site, "active": True})
    save_blocked_sites(sites)
    
    # Apply to hosts immediately
    apply_blocks_to_hosts([site])
    
    return jsonify({"message": f"Added and blocked {site}", "sites": sites})

@app.route('/api/blocked-sites/toggle', methods=['POST'])
@require_auth
def toggle_blocked_site():
    data = request.get_json()
    site = data.get('site', '').strip()
    if not site:
        return jsonify({"error": "No site provided"}), 400
    sites = load_blocked_sites()
    
    found = False
    new_state = False
    for s in sites:
        if s["site"] == site:
            s["active"] = not s.get("active", True)
            new_state = s["active"]
            found = True
            break
            
    if not found:
        return jsonify({"error": "Site not in list"}), 404
        
    save_blocked_sites(sites)
    
    if new_state:
        apply_blocks_to_hosts([site])
        msg = f"Locked and blocked {site}"
    else:
        remove_blocks_from_hosts([site])
        msg = f"Unlocked and unblocked {site}"
        
    return jsonify({"message": msg, "sites": sites})

@app.route('/api/blocked-sites', methods=['DELETE'])
@require_auth
def remove_blocked_site():
    data = request.get_json()
    site = data.get('site', '').strip()
    if not site:
        return jsonify({"error": "No site provided"}), 400
    sites = load_blocked_sites()
    
    found = False
    for i, s in enumerate(sites):
        if s["site"] == site:
            sites.pop(i)
            found = True
            break
            
    if not found:
        return jsonify({"error": "Site not in list"}), 404
        
    save_blocked_sites(sites)
    
    # Remove from hosts immediately
    remove_blocks_from_hosts([site])
    
    return jsonify({"message": f"Removed and unblocked {site}", "sites": sites})

@app.route('/api/blocked-sites/apply', methods=['POST'])
@require_auth
def apply_site_blocks():
    sites = load_blocked_sites()
    if not sites:
        return jsonify({"error": "No sites to block"}), 400
    
    active_sites = [s["site"] for s in sites if s.get("active", True)]
    if not active_sites:
        return jsonify({"message": "No active sites to block"}), 200

    success, msg = apply_blocks_to_hosts(active_sites)
    if success:
        db.add_alert("site_block", "low", f"Applied blocks for {len(active_sites)} sites")
    return jsonify({"success": success, "message": msg})

# Removed /api/blocked-sites/remove endpoint as per instructions.
# The DELETE /api/blocked-sites endpoint handles removal of individual sites.


# --- DoH Bypass Prevention (Windows) ---
@app.route('/api/doh/disable', methods=['POST'])
@require_auth
def disable_doh():
    s1, m1 = disable_chrome_secure_dns()
    s2, m2 = block_doh_firewall()
    return jsonify({"chrome_dns": {"success": s1, "message": m1}, "firewall": {"success": s2, "message": m2}})

@app.route('/api/doh/enable', methods=['POST'])
@require_auth
def enable_doh():
    s1, m1 = enable_chrome_secure_dns()
    s2, m2 = unblock_doh_firewall()
    return jsonify({"chrome_dns": {"success": s1, "message": m1}, "firewall": {"success": s2, "message": m2}})


# --- Keylogger ---
@app.route('/api/keylogger/start', methods=['POST'])
@require_auth
def start_keylogger_api():
    global keylogger_active, keylogger_thread, risk_scanner_active, risk_scanner_thread, _last_keylog_scan_pos
    if keylogger_active:
        return jsonify({"error": "Keylogger already running"}), 409

    open(LOG_FILE, "w").close()
    _last_keylog_scan_pos = 0
    keylogger_active = True

    if sys.platform == "win32":
        if pynput_keyboard is None:
            keylogger_active = False
            return jsonify({"error": "pynput not installed"}), 500
        keylogger_thread = threading.Thread(target=pynput_keylogger_thread, daemon=True)
    else:
        if evdev is not None:
            keylogger_thread = threading.Thread(target=evdev_keylogger_thread, daemon=True)
        elif pynput_keyboard is not None:
            keylogger_thread = threading.Thread(target=pynput_keylogger_thread, daemon=True)
        else:
            keylogger_active = False
            return jsonify({"error": "No keylogger backend available"}), 500

    keylogger_thread.start()

    # Auto-start risk scanner with keylogger
    if not risk_scanner_active:
        risk_scanner_active = True
        risk_scanner_thread = threading.Thread(target=risk_scanner_loop, daemon=True)
        risk_scanner_thread.start()

    db.add_alert("system", "low", "Keylogger started")
    return jsonify({"message": "Keylogger started (risk scanner enabled)"})

@app.route('/api/keylogger/stop', methods=['POST'])
@require_auth
def stop_keylogger_api():
    global keylogger_active, risk_scanner_active
    if not keylogger_active:
        return jsonify({"error": "Keylogger not running"}), 409
    keylogger_active = False
    risk_scanner_active = False
    # Final scan
    scan_keylog_for_risks()
    db.add_alert("system", "low", "Keylogger stopped")
    return jsonify({"message": "Keylogger stopped"})

@app.route('/api/keylogger/logs')
@require_auth
def get_keylogger_logs():
    content = get_keylog_content()
    return jsonify({"logs": content, "active": keylogger_active})


# --- App Blocker ---
@app.route('/api/app-blocker/start', methods=['POST'])
@require_auth
def start_app_blocker():
    global blocker_active, blocker_thread
    if blocker_active:
        return jsonify({"error": "App blocker already running"}), 409
    blocker_active = True
    blocker_thread = threading.Thread(target=app_blocker_loop, daemon=True)
    blocker_thread.start()
    db.add_alert("system", "low", "App blocker started")
    return jsonify({"message": "App blocker started"})

@app.route('/api/app-blocker/stop', methods=['POST'])
@require_auth
def stop_app_blocker():
    global blocker_active
    if not blocker_active:
        return jsonify({"error": "App blocker not running"}), 409
    blocker_active = False
    db.add_alert("system", "low", "App blocker stopped")
    return jsonify({"message": "App blocker stopped"})

@app.route('/api/app-blocker/apps', methods=['GET'])
@require_auth
def get_blocked_apps():
    return jsonify({"apps": load_blocked_apps()})

@app.route('/api/app-blocker/apps', methods=['POST'])
@require_auth
def add_blocked_app():
    data = request.get_json()
    app_name = data.get('app', '').strip()
    if not app_name:
        return jsonify({"error": "No app name provided"}), 400
    apps = load_blocked_apps()
    if app_name in apps:
        return jsonify({"error": "App already in list"}), 409
    apps.append(app_name)
    save_blocked_apps(apps)
    return jsonify({"message": f"Added {app_name}", "apps": apps})

@app.route('/api/app-blocker/apps', methods=['DELETE'])
@require_auth
def remove_blocked_app():
    data = request.get_json()
    app_name = data.get('app', '').strip()
    if not app_name:
        return jsonify({"error": "No app name provided"}), 400
    apps = load_blocked_apps()
    if app_name not in apps:
        return jsonify({"error": "App not in list"}), 404
    apps.remove(app_name)
    save_blocked_apps(apps)
    return jsonify({"message": f"Removed {app_name}", "apps": apps})


# --- Alerts ---
@app.route('/api/alerts')
@require_auth
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    alert_type = request.args.get('type', None)
    alerts = db.get_alerts(limit=limit, alert_type=alert_type)
    return jsonify({"alerts": alerts, "unread": db.get_unread_alert_count()})

@app.route('/api/alerts/read', methods=['POST'])
@require_auth
def mark_alerts_read():
    db.mark_alerts_read()
    return jsonify({"message": "All alerts marked as read"})

@app.route('/api/alerts', methods=['DELETE'])
@require_auth
def clear_alerts():
    db.clear_alerts()
    return jsonify({"message": "All alerts cleared"})


# --- Risk Keywords & Detection ---
@app.route('/api/risk-keywords', methods=['GET'])
@require_auth
def get_risk_keywords():
    return jsonify({"keywords": db.get_risk_keywords()})

@app.route('/api/risk-keywords', methods=['POST'])
@require_auth
def add_risk_keyword():
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    severity = data.get('severity', 'medium')
    category = data.get('category', 'general')
    if not keyword:
        return jsonify({"error": "No keyword provided"}), 400
    success = db.add_risk_keyword(keyword, severity, category)
    if not success:
        return jsonify({"error": "Keyword already exists"}), 409
    return jsonify({"message": f"Added keyword '{keyword}'"})

@app.route('/api/risk-keywords', methods=['DELETE'])
@require_auth
def remove_risk_keyword():
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    if not keyword:
        return jsonify({"error": "No keyword provided"}), 400
    db.remove_risk_keyword(keyword)
    return jsonify({"message": f"Removed keyword '{keyword}'"})

@app.route('/api/risk-detections')
@require_auth
def get_risk_detections():
    limit = request.args.get('limit', 50, type=int)
    return jsonify({"detections": db.get_risk_events(limit=limit)})


# --- Time Tracking ---
@app.route('/api/time-tracking/start', methods=['POST'])
@require_auth
def start_time_tracking():
    global time_tracker_active, time_tracker_thread
    if time_tracker_active:
        return jsonify({"error": "Time tracker already running"}), 409
    time_tracker_active = True
    time_tracker_thread = threading.Thread(target=time_tracker_loop, daemon=True)
    time_tracker_thread.start()
    db.add_alert("system", "low", "Time tracking started")
    return jsonify({"message": "Time tracker started"})

@app.route('/api/time-tracking/stop', methods=['POST'])
@require_auth
def stop_time_tracking():
    global time_tracker_active
    if not time_tracker_active:
        return jsonify({"error": "Time tracker not running"}), 409
    time_tracker_active = False
    db.add_alert("system", "low", "Time tracking stopped")
    return jsonify({"message": "Time tracker stopped"})

@app.route('/api/time-tracking/sites')
@require_auth
def get_time_sites():
    days = request.args.get('days', 7, type=int)
    return jsonify({"sites": db.get_site_visits(days=days)})

@app.route('/api/time-tracking/apps')
@require_auth
def get_time_apps():
    days = request.args.get('days', 7, type=int)
    return jsonify({"apps": db.get_app_usage(days=days)})

@app.route('/api/time-tracking/summary')
@require_auth
def get_time_summary():
    days = request.args.get('days', 7, type=int)
    return jsonify({
        "summary": db.get_time_summary(days=days),
        "daily": db.get_daily_screen_time(days=days),
        "active": time_tracker_active
    })


# --- Browser History (Enhanced) ---
@app.route('/api/history')
@require_auth
def get_history():
    top_n = request.args.get('top', 10, type=int)
    result, error = analyze_browser_history(top_n)
    if error:
        return jsonify({"error": error}), 500
    return jsonify(result)


# --- Metrics (aggregated dashboard data) ---
@app.route('/api/metrics')
@require_auth
def get_metrics():
    """Aggregated metrics for the dashboard."""
    days = request.args.get('days', 7, type=int)

    site_visits = db.get_site_visits(days=days)
    app_usage = db.get_app_usage(days=days)
    time_summary = db.get_time_summary(days=days)
    daily_screen = db.get_daily_screen_time(days=days)
    recent = db.get_recent_site_visits(limit=15)
    risk_events = db.get_risk_events(limit=10)
    alerts = db.get_alerts(limit=10)

    # Calculate total screen time
    total_screen_time = sum(d.get('total_time', 0) for d in daily_screen)

    return jsonify({
        "site_visits": site_visits,
        "app_usage": app_usage,
        "time_summary": time_summary,
        "daily_screen_time": daily_screen,
        "recent_visits": recent,
        "risk_events": risk_events,
        "recent_alerts": alerts,
        "total_screen_time": round(total_screen_time, 1),
    })


# --- Screenshots ---
@app.route('/api/screenshots', methods=['GET'])
@require_auth
def get_screenshots():
    return jsonify({"screenshots": list_screenshots()})

@app.route('/api/screenshots/capture', methods=['POST'])
@require_auth
def capture_screenshot():
    filename, error = take_screenshot()
    if error:
        return jsonify({"error": error}), 500
    db.add_alert("system", "low", f"Screenshot captured: {filename}")
    return jsonify({"message": "Screenshot captured", "filename": filename})

@app.route('/api/screenshots/<filename>')
@require_auth
def serve_screenshot(filename):
    return send_from_directory(SCREENSHOT_FOLDER, filename)


# --- Database Management ---
@app.route('/api/db/flush', methods=['POST'])
@require_auth
def flush_db():
    db.flush()
    return jsonify({"message": "Database encrypted and saved to disk"})


# ==============================================================================
# STARTUP — background services
# ==============================================================================

def start_background_services():
    """Start the alert checker on server boot."""
    global alert_checker_active, alert_checker_thread
    alert_checker_active = True
    alert_checker_thread = threading.Thread(target=alert_checker_loop, daemon=True)
    alert_checker_thread.start()
    print("  [OK] Alert checker started")


# ==============================================================================
# SHUTDOWN
# ==============================================================================

@app.route('/api/shutdown', methods=['POST'])
@require_auth
def shutdown_server():
    db.flush()
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
    else:
        os._exit(0)
    return jsonify({'message': 'Server shutting down'})


# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--headless', action='store_true', help='Run without console output')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)

    # Write PID file for process management
    pid_file = os.path.join(BASE_DIR, 'server.pid')
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))

    if not args.headless:
        print("\n +-------------------------------------------+")
        print(" |  Parental Control Dashboard Server        |")
        print(f" |  Running at http://127.0.0.1:{args.port}         |")
        print(" +-------------------------------------------+")
        print(" |  Database: AES-256 Encrypted              |")
        print(" |  Auth: Password protected                 |")
        print(" |  Alert checker: Active                    |")
        print(" +-------------------------------------------+\n")

    start_background_services()
    app.run(debug=False, host='127.0.0.1', port=args.port, use_reloader=False)
