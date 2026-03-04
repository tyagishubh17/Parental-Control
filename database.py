# database.py - AES-256 Encrypted SQLite Database for Parental Control
import os
import json
import sqlite3
import base64
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "parental_control.db.enc")
SALT_FILE = os.path.join(BASE_DIR, ".db_salt")
DEFAULT_KEY = "ParentalCtrl2026!"  # fallback if env var not set


# ==============================================================================
# AES-256 ENCRYPTION LAYER
# ==============================================================================

def _get_salt():
    """Get or create a persistent salt for key derivation."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt


def _derive_key(password: str) -> bytes:
    """Derive a Fernet-compatible key from a password using PBKDF2-HMAC-SHA256."""
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def _get_fernet() -> Fernet:
    """Get a Fernet cipher instance using the configured key."""
    password = os.environ.get("PARENTAL_DB_KEY", DEFAULT_KEY)
    key = _derive_key(password)
    return Fernet(key)


def encrypt_data(data: bytes) -> bytes:
    """Encrypt raw bytes with AES-256 (Fernet)."""
    return _get_fernet().encrypt(data)


def decrypt_data(data: bytes) -> bytes:
    """Decrypt AES-256 encrypted bytes."""
    return _get_fernet().decrypt(data)


# ==============================================================================
# ENCRYPTED DATABASE CLASS
# ==============================================================================

class EncryptedDB:
    """
    SQLite database with AES-256 encryption at rest.
    The DB file is encrypted on disk. On open, it is decrypted into memory.
    On close/flush, the in-memory DB is dumped and encrypted back to disk.
    """

    def __init__(self):
        self.conn = None
        self._open()

    def _open(self):
        """Open the database: decrypt from disk or create fresh."""
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'rb') as f:
                    encrypted = f.read()
                decrypted = decrypt_data(encrypted)
                # Load decrypted SQL dump into memory
                self.conn.executescript(decrypted.decode('utf-8'))
            except Exception as e:
                print(f"[DB] Warning: Could not decrypt DB ({e}), creating fresh.")
                self._create_schema()
        else:
            self._create_schema()

    def _create_schema(self):
        """Create all tables."""
        c = self.conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            message TEXT NOT NULL,
            read INTEGER DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS risk_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            keyword TEXT NOT NULL,
            context TEXT,
            severity TEXT NOT NULL DEFAULT 'medium'
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS risk_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL UNIQUE,
            severity TEXT NOT NULL DEFAULT 'medium',
            category TEXT DEFAULT 'general'
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS site_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            visit_time TEXT NOT NULL,
            duration_seconds REAL DEFAULT 0,
            title TEXT DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS app_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            duration_seconds REAL DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS time_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            date TEXT NOT NULL,
            total_seconds REAL DEFAULT 0
        )""")

        # Seed default risk keywords
        default_keywords = [
            ("drugs", "high", "substance"),
            ("suicide", "high", "safety"),
            ("self harm", "high", "safety"),
            ("kill", "high", "violence"),
            ("weapon", "high", "violence"),
            ("porn", "high", "adult"),
            ("xxx", "high", "adult"),
            ("gambling", "medium", "risky"),
            ("betting", "medium", "risky"),
            ("dark web", "high", "risky"),
            ("tor browser", "medium", "risky"),
            ("vpn bypass", "medium", "evasion"),
            ("proxy", "low", "evasion"),
            ("hack", "medium", "security"),
            ("password crack", "high", "security"),
            ("bully", "medium", "social"),
            ("hate", "low", "social"),
        ]
        for kw, sev, cat in default_keywords:
            try:
                c.execute("INSERT INTO risk_keywords (keyword, severity, category) VALUES (?, ?, ?)",
                          (kw, sev, cat))
            except sqlite3.IntegrityError:
                pass

        self.conn.commit()

    def flush(self):
        """Encrypt and write the in-memory DB to disk."""
        try:
            # Dump the in-memory database to SQL
            dump = "\n".join(self.conn.iterdump())
            encrypted = encrypt_data(dump.encode('utf-8'))
            with open(DB_FILE, 'wb') as f:
                f.write(encrypted)
        except Exception as e:
            print(f"[DB] Error flushing database: {e}")

    def close(self):
        """Flush and close."""
        self.flush()
        self.conn.close()

    # ------------------------------------------------------------------
    # ALERTS
    # ------------------------------------------------------------------
    def add_alert(self, alert_type: str, severity: str, message: str):
        ts = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO alerts (timestamp, type, severity, message) VALUES (?, ?, ?, ?)",
            (ts, alert_type, severity, message)
        )
        self.conn.commit()
        self.flush()

    def get_alerts(self, limit=50, alert_type=None):
        query = "SELECT * FROM alerts"
        params = []
        if alert_type:
            query += " WHERE type = ?"
            params.append(alert_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_unread_alert_count(self):
        row = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE read = 0").fetchone()
        return row[0]

    def mark_alerts_read(self):
        self.conn.execute("UPDATE alerts SET read = 1")
        self.conn.commit()
        self.flush()

    def clear_alerts(self):
        self.conn.execute("DELETE FROM alerts")
        self.conn.commit()
        self.flush()

    # ------------------------------------------------------------------
    # RISK KEYWORDS & DETECTION
    # ------------------------------------------------------------------
    def get_risk_keywords(self):
        rows = self.conn.execute("SELECT * FROM risk_keywords ORDER BY severity DESC, keyword").fetchall()
        return [dict(r) for r in rows]

    def add_risk_keyword(self, keyword: str, severity: str = "medium", category: str = "general"):
        try:
            self.conn.execute(
                "INSERT INTO risk_keywords (keyword, severity, category) VALUES (?, ?, ?)",
                (keyword.lower().strip(), severity, category)
            )
            self.conn.commit()
            self.flush()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_risk_keyword(self, keyword: str):
        self.conn.execute("DELETE FROM risk_keywords WHERE keyword = ?", (keyword,))
        self.conn.commit()
        self.flush()

    def add_risk_event(self, keyword: str, context: str, severity: str):
        ts = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO risk_events (timestamp, keyword, context, severity) VALUES (?, ?, ?, ?)",
            (ts, keyword, context, severity)
        )
        self.conn.commit()
        self.flush()

    def get_risk_events(self, limit=50):
        rows = self.conn.execute(
            "SELECT * FROM risk_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # SITE VISITS & TIME TRACKING
    # ------------------------------------------------------------------
    def add_site_visit(self, domain: str, visit_time: str, duration: float = 0, title: str = ""):
        self.conn.execute(
            "INSERT INTO site_visits (domain, visit_time, duration_seconds, title) VALUES (?, ?, ?, ?)",
            (domain, visit_time, duration, title)
        )
        self.conn.commit()

    def get_site_visits(self, days=7, limit=20):
        cutoff = datetime.now().isoformat()[:10]  # today
        rows = self.conn.execute("""
            SELECT domain,
                   COUNT(*) as visits,
                   SUM(duration_seconds) as total_time,
                   MAX(visit_time) as last_visit
            FROM site_visits
            WHERE visit_time >= date(?, '-' || ? || ' days')
            GROUP BY domain
            ORDER BY visits DESC
            LIMIT ?
        """, (cutoff, days, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_recent_site_visits(self, limit=20):
        rows = self.conn.execute("""
            SELECT domain, visit_time, duration_seconds, title
            FROM site_visits ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # APP USAGE TRACKING
    # ------------------------------------------------------------------
    def add_app_usage(self, app_name: str, start_time: str, duration: float):
        self.conn.execute(
            "INSERT INTO app_usage (app_name, start_time, duration_seconds) VALUES (?, ?, ?)",
            (app_name, start_time, duration)
        )
        self.conn.commit()

    def get_app_usage(self, days=7, limit=20):
        cutoff = datetime.now().isoformat()[:10]
        rows = self.conn.execute("""
            SELECT app_name,
                   COUNT(*) as sessions,
                   SUM(duration_seconds) as total_time,
                   MAX(start_time) as last_used
            FROM app_usage
            WHERE start_time >= date(?, '-' || ? || ' days')
            GROUP BY app_name
            ORDER BY total_time DESC
            LIMIT ?
        """, (cutoff, days, limit)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # TIME TRACKING SUMMARY
    # ------------------------------------------------------------------
    def update_time_tracking(self, target: str, target_type: str, seconds: float):
        today = datetime.now().strftime("%Y-%m-%d")
        existing = self.conn.execute(
            "SELECT id, total_seconds FROM time_tracking WHERE target = ? AND target_type = ? AND date = ?",
            (target, target_type, today)
        ).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE time_tracking SET total_seconds = ? WHERE id = ?",
                (existing['total_seconds'] + seconds, existing['id'])
            )
        else:
            self.conn.execute(
                "INSERT INTO time_tracking (target, target_type, date, total_seconds) VALUES (?, ?, ?, ?)",
                (target, target_type, today, seconds)
            )
        self.conn.commit()

    def get_time_summary(self, days=7):
        cutoff = datetime.now().isoformat()[:10]
        rows = self.conn.execute("""
            SELECT target, target_type,
                   SUM(total_seconds) as total_time
            FROM time_tracking
            WHERE date >= date(?, '-' || ? || ' days')
            GROUP BY target, target_type
            ORDER BY total_time DESC
        """, (cutoff, days)).fetchall()
        return [dict(r) for r in rows]

    def get_daily_screen_time(self, days=7):
        cutoff = datetime.now().isoformat()[:10]
        rows = self.conn.execute("""
            SELECT date, SUM(total_seconds) as total_time
            FROM time_tracking
            WHERE date >= date(?, '-' || ? || ' days')
            GROUP BY date
            ORDER BY date
        """, (cutoff, days)).fetchall()
        return [dict(r) for r in rows]
