"""
Data Export Module for CIVRADAR-X

This module provides comprehensive data export capabilities for the CIVRADAR-X
system, supporting multiple formats for intelligence sharing and analysis.
It handles device discovery data export with proper formatting, filtering,
and geospatial encoding.

Supported Export Formats:
- CSV: Comma-separated values for spreadsheet analysis
- JSON: Structured data for programmatic processing
- GeoJSON: Geospatial features for mapping applications

Key Features:
- Automatic error filtering (excludes failed scans)
- Timestamp standardization (UTC ISO format)
- Geospatial data encoding for mapping
- Flask Response objects for web delivery
- Comprehensive field coverage for intelligence analysis

Export Fields:
- timestamp: UTC timestamp of export generation
- mac: Device MAC address
- name: Device hostname/display name
- type: Device classification (smart_home, security, etc.)
- vendor: Hardware manufacturer
- privacy_risk: Risk score (1-10)
- distance: Estimated distance from scanner
- protocol: Discovery protocol (arp, ble, mdns, wifi)
- geo_lat/lon/alt: GPS coordinates and altitude
- geo_acc: GPS accuracy estimate
- geo_timestamp: GPS fix timestamp

Security Considerations:
- Exports may contain sensitive location data
- Consider encryption for sensitive deployments
- Filter sensitive fields based on operational requirements

Dependencies:
- csv: For CSV format generation
- json: For JSON serialization
- datetime: For timestamp handling
- flask: For HTTP response generation

Author: CIVRADAR-X Development Team
"""

import csv
import json
from datetime import datetime
from flask import Response


def export_csv(devices):
    """
    Export device data to CSV format for spreadsheet analysis.

    This function generates a CSV file containing all discovered device
    information with standardized field names. It filters out error entries
    and provides consistent timestamp formatting.

    Args:
        devices (list): List of device dictionaries from fusion engine

    Returns:
        flask.Response: HTTP response with CSV content and download headers

    CSV Fields:
        - timestamp: Export generation time (UTC ISO)
        - mac: Device MAC address
        - name: Device name/hostname
        - type: Device classification
        - vendor: Hardware vendor
        - privacy_risk: Privacy risk score
        - distance: Estimated distance
        - protocol: Discovery protocol
        - geo_lat/lon/alt/acc: GPS data
        - geo_timestamp: GPS timestamp
    """
    from io import StringIO

    # Create in-memory string buffer for CSV content
    si = StringIO()

    # Define CSV field names in consistent order
    fieldnames = [
        'timestamp', 'mac', 'name', 'type', 'vendor', 'privacy_risk',
        'distance', 'protocol', 'geo_lat', 'geo_lon', 'geo_alt',
        'geo_acc', 'geo_timestamp'
    ]

    # Create CSV writer with specified field order
    writer = csv.DictWriter(si, fieldnames=fieldnames)
    writer.writeheader()

    # Generate consistent export timestamp
    now = datetime.utcnow().isoformat()

    # Process each device, skipping errors
    for device in devices:
        if 'error' in device:
            continue  # Skip failed scan results

        # Write device data with consistent field mapping
        writer.writerow({
            'timestamp': now,
            'mac': device.get('mac', ''),
            'name': device.get('name', ''),
            'type': device.get('type', ''),
            'vendor': device.get('vendor', ''),
            'privacy_risk': device.get('privacy_risk', ''),
            'distance': device.get('distance', ''),
            'protocol': device.get('protocol', ''),
            'geo_lat': device.get('geo_lat', ''),
            'geo_lon': device.get('geo_lon', ''),
            'geo_alt': device.get('geo_alt', ''),
            'geo_acc': device.get('geo_acc', ''),
            'geo_timestamp': device.get('geo_timestamp', '')
        })

    # Return Flask response with CSV content
    return Response(
        si.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=civradar_export.csv'}
    )


def export_json(devices):
    """
    Export device data to JSON format for programmatic processing.

    This function creates a clean JSON array of device data, filtering out
    any error entries and providing properly formatted JSON output.

    Args:
        devices (list): List of device dictionaries from fusion engine

    Returns:
        flask.Response: HTTP response with JSON content and download headers

    JSON Structure:
        Array of device objects with all available fields
        Excludes devices with 'error' key
        Pretty-printed with 2-space indentation
    """
    # Filter out devices with errors
    clean_devices = [device for device in devices if 'error' not in device]

    # Return Flask response with JSON content
    return Response(
        json.dumps(clean_devices, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=civradar_export.json'}
    )


def export_geojson(devices):
    """
    Export device data to GeoJSON format for geospatial mapping applications.

    This function converts device data to GeoJSON FeatureCollection format,
    encoding GPS coordinates as Point geometries. Only devices with valid
    GPS coordinates are included in the export.

    Args:
        devices (list): List of device dictionaries from fusion engine

    Returns:
        flask.Response: HTTP response with GeoJSON content and download headers

    GeoJSON Structure:
        {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [longitude, latitude, altitude]
                    },
                    "properties": {device_fields_except_coordinates}
                }
            ]
        }

    Notes:
        - Only includes devices with geo_lat coordinate
        - Altitude defaults to 0 if not available
        - Coordinates order: [longitude, latitude, altitude]
    """
    features = []

    # Process each device for GeoJSON conversion
    for device in devices:
        # Skip devices with errors or missing GPS coordinates
        if 'error' in device or not device.get('geo_lat'):
            continue

        # Create GeoJSON feature for device
        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [
                    device['geo_lon'],    # Longitude first (GeoJSON standard)
                    device['geo_lat'],    # Latitude second
                    device.get('geo_alt', 0)  # Altitude, default to 0
                ]
            },
            "properties": {
                # Include all device fields except coordinate components
                key: value for key, value in device.items()
                if key not in ['geo_lat', 'geo_lon', 'geo_alt']
            }
        }

        features.append(feature)

    # Create complete GeoJSON FeatureCollection
    geojson = {
        "type": "FeatureCollection",
        "features": features
    }

    # Return Flask response with GeoJSON content
    return Response(
        json.dumps(geojson, indent=2),
        mimetype='application/geo+json',
        headers={'Content-Disposition': 'attachment; filename=civradar_export.geojson'}
    )