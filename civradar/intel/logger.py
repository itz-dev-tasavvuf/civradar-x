import sqlite3
from datetime import datetime
import os

DB_PATH = "/opt/civradar-x/logs/civradar.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            mac TEXT,
            name TEXT,
            type TEXT,
            vendor TEXT,
            privacy_risk INTEGER,
            distance REAL,
            protocol TEXT,
            geo_lat REAL,
            geo_lon REAL,
            geo_alt REAL,
            geo_acc REAL,
            geo_timestamp TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS export_history (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            format TEXT,
            encrypted BOOLEAN,
            encryption_type TEXT,
            recipient TEXT,
            file_path TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_devices(devices, geo=None):
    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    for d in devices:
        if 'error' in d:
            continue
        conn.execute("""
            INSERT INTO devices (timestamp, mac, name, type, vendor, privacy_risk, distance, protocol, geo_lat, geo_lon, geo_alt, geo_acc, geo_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now,
            d.get('mac'), d.get('name'), d.get('type'), d.get('vendor'),
            d.get('privacy_risk'), d.get('distance'), d.get('protocol'),
            geo.get('lat') if geo else None,
            geo.get('lon') if geo else None,
            geo.get('alt') if geo else None,
            geo.get('acc') if geo else None,
            geo.get('timestamp') if geo else None
        ))
    conn.commit()
    conn.close()

def log_export_history(format_type, encrypted=False, encryption_type=None, recipient=None, file_path=None):
    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    conn.execute("""
        INSERT INTO export_history (timestamp, format, encrypted, encryption_type, recipient, file_path)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (now, format_type, encrypted, encryption_type, recipient, file_path))
    conn.commit()
    conn.close()