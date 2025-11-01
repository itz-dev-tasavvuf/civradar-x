"""
Database Logger Module for CIVRADAR-X

This module provides persistent data logging capabilities for the CIVRADAR-X
system using SQLite database storage. It maintains comprehensive records of
device discoveries, geospatial data, and export activities for intelligence
analysis and operational tracking.

Database Schema:
- devices: Stores all discovered device information with timestamps
- export_history: Tracks data export activities and encryption status

Key Features:
- SQLite-based persistent storage
- Automatic database initialization
- Device discovery logging with geospatial correlation
- Export activity tracking with security metadata
- Thread-safe database operations
- UTC timestamp standardization

Database Tables:

devices table:
- id: Primary key (auto-increment)
- timestamp: Discovery timestamp (UTC ISO)
- mac: Device MAC address
- name: Device hostname/display name
- type: Device classification (smart_home, security, etc.)
- vendor: Hardware manufacturer
- privacy_risk: Risk score (1-10)
- distance: Estimated distance from scanner
- protocol: Discovery protocol (arp, ble, mdns, wifi)
- geo_lat/lon/alt/acc: GPS coordinates and accuracy
- geo_timestamp: GPS fix timestamp

export_history table:
- id: Primary key (auto-increment)
- timestamp: Export timestamp (UTC ISO)
- format: Export format (csv, json, geojson)
- encrypted: Whether export was encrypted
- encryption_type: Type of encryption used
- recipient: Intended recipient (if applicable)
- file_path: Path to exported file

Security Considerations:
- Database contains sensitive device and location data
- Consider encryption for database files in production
- Implement access controls for database files
- Regular backup and secure deletion procedures

Performance Notes:
- SQLite suitable for moderate data volumes
- Consider partitioning for high-volume deployments
- Indexes on timestamp and mac for query optimization

Dependencies:
- sqlite3: Built-in Python SQLite support
- datetime: For timestamp handling
- os: For directory creation

Author: CIVRADAR-X Development Team
"""

import sqlite3
from datetime import datetime
import os

# Database file path - centralized logging location
DB_PATH = "/opt/civradar-x/logs/civradar.db"


def init_db():
    """
    Initialize the CIVRADAR-X logging database.

    This function creates the necessary database directory and tables if they
    don't exist. It should be called during system initialization.

    Database Structure:
        - devices: Stores device discovery records
        - export_history: Tracks data export activities

    Note:
        Uses IF NOT EXISTS to avoid errors on re-initialization.
    """
    # Ensure database directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    # Connect to database (creates file if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)

    # Create devices table for storing discovery data
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

    # Create export history table for tracking data exports
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

    # Commit changes and close connection
    conn.commit()
    conn.close()


def log_devices(devices, geo=None):
    """
    Log discovered devices to the database.

    This function records device discovery information along with optional
    geospatial data. It filters out error entries and uses UTC timestamps
    for consistency.

    Args:
        devices (list): List of device dictionaries from fusion engine
        geo (dict, optional): GPS coordinates for correlation

    Database Fields:
        - timestamp: Current UTC time of logging
        - mac/name/type/vendor: Device identification
        - privacy_risk/distance/protocol: Intelligence data
        - geo_*: GPS coordinates and metadata

    Note:
        Skips devices with 'error' key to avoid logging failed scans.
    """
    # Connect to database
    conn = sqlite3.connect(DB_PATH)

    # Generate consistent timestamp for this logging batch
    now = datetime.utcnow().isoformat()

    # Process each device
    for device in devices:
        # Skip error entries
        if 'error' in device:
            continue

        # Insert device record
        conn.execute("""
            INSERT INTO devices (
                timestamp, mac, name, type, vendor, privacy_risk,
                distance, protocol, geo_lat, geo_lon, geo_alt,
                geo_acc, geo_timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now,
            device.get('mac'),           # Device MAC address
            device.get('name'),          # Device name
            device.get('type'),          # Device classification
            device.get('vendor'),        # Hardware vendor
            device.get('privacy_risk'),  # Privacy risk score
            device.get('distance'),      # Estimated distance
            device.get('protocol'),      # Discovery protocol
            geo.get('lat') if geo else None,    # GPS latitude
            geo.get('lon') if geo else None,    # GPS longitude
            geo.get('alt') if geo else None,    # GPS altitude
            geo.get('acc') if geo else None,    # GPS accuracy
            geo.get('timestamp') if geo else None  # GPS timestamp
        ))

    # Commit transaction and close connection
    conn.commit()
    conn.close()


def log_export_history(format_type, encrypted=False, encryption_type=None,
                      recipient=None, file_path=None):
    """
    Log data export activities to the database.

    This function records export operations for audit and tracking purposes,
    including encryption status and recipient information.

    Args:
        format_type (str): Export format ('csv', 'json', 'geojson')
        encrypted (bool): Whether the export was encrypted
        encryption_type (str, optional): Type of encryption used
        recipient (str, optional): Intended recipient of the export
        file_path (str, optional): Path to the exported file

    Database Fields:
        - timestamp: Export timestamp (UTC)
        - format: Export format
        - encrypted: Encryption status
        - encryption_type: Encryption method
        - recipient: Export recipient
        - file_path: File location

    Note:
        Used for operational tracking and security auditing.
    """
    # Connect to database
    conn = sqlite3.connect(DB_PATH)

    # Generate export timestamp
    now = datetime.utcnow().isoformat()

    # Insert export record
    conn.execute("""
        INSERT INTO export_history (
            timestamp, format, encrypted, encryption_type,
            recipient, file_path
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        now,
        format_type,      # Export format
        encrypted,        # Encryption flag
        encryption_type,  # Encryption method
        recipient,        # Export recipient
        file_path         # File path
    ))

    # Commit transaction and close connection
    conn.commit()
    conn.close()