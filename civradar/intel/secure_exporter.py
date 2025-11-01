# civradar/intel/secure_exporter.py
import zipfile
import io
import json
import os
import tempfile
import subprocess
from datetime import datetime
from flask import Response
from .exporter import export_csv, export_json, export_geojson
from .logger import log_export_history, DB_PATH

def create_zip_export(devices, geo_cache=None):
    """Create a ZIP file containing all export formats and metadata."""
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add CSV export
        csv_response = export_csv(devices)
        zip_file.writestr('civradar_export.csv', csv_response.get_data(as_text=True))

        # Add JSON export
        json_response = export_json(devices)
        zip_file.writestr('civradar_export.json', json_response.get_data(as_text=True))

        # Add GeoJSON export
        geojson_response = export_geojson(devices)
        zip_file.writestr('civradar_export.geojson', geojson_response.get_data(as_text=True))

        # Add SQLite database copy
        if os.path.exists(DB_PATH):
            zip_file.write(DB_PATH, 'civradar_export.db')

        # Add metadata
        metadata = {
            'export_timestamp': datetime.utcnow().isoformat(),
            'device_count': len([d for d in devices if 'error' not in d]),
            'formats': ['csv', 'json', 'geojson', 'sqlite'],
            'geo_cache': geo_cache,
            'version': '1.0'
        }
        zip_file.writestr('metadata.json', json.dumps(metadata, indent=2))

    zip_buffer.seek(0)
    return zip_buffer

def encrypt_with_gpg(data, password=None, recipient=None):
    """Encrypt data using GPG with password or key-based encryption."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_in:
        temp_in.write(data.getvalue())
        temp_in.flush()

        temp_out = tempfile.NamedTemporaryFile(delete=False, suffix='.gpg')
        temp_out.close()

        cmd = ['gpg', '--batch', '--yes', '--output', temp_out.name]

        if password:
            cmd.extend(['--passphrase', password, '--symmetric'])
        elif recipient:
            cmd.extend(['--encrypt', '--recipient', recipient])
        else:
            raise ValueError("Either password or recipient must be provided")

        cmd.append(temp_in.name)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            with open(temp_out.name, 'rb') as f:
                encrypted_data = f.read()
            return io.BytesIO(encrypted_data)
        finally:
            os.unlink(temp_in.name)
            os.unlink(temp_out.name)

def export_secure_zip(devices, geo_cache=None, password=None, recipient=None):
    """Create and optionally encrypt a secure ZIP export."""
    zip_data = create_zip_export(devices, geo_cache)

    encrypted = bool(password or recipient)
    encryption_type = None

    if encrypted:
        if password:
            encryption_type = 'password'
            zip_data = encrypt_with_gpg(zip_data, password=password)
        elif recipient:
            encryption_type = 'key'
            zip_data = encrypt_with_gpg(zip_data, recipient=recipient)

    # Log the export
    log_export_history(
        format_type='zip',
        encrypted=encrypted,
        encryption_type=encryption_type,
        recipient=recipient
    )

    filename = f"civradar_secure_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if encrypted:
        filename += '.gpg'
    else:
        filename += '.zip'

    return Response(
        zip_data.getvalue(),
        mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )