# civradar/intel/exporter.py
import csv
import json
from datetime import datetime
from flask import Response

def export_csv(devices):
    from io import StringIO
    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=[
        'timestamp', 'mac', 'name', 'type', 'vendor', 'privacy_risk', 'distance', 'protocol',
        'geo_lat', 'geo_lon', 'geo_alt', 'geo_acc', 'geo_timestamp'
    ])
    writer.writeheader()
    now = datetime.utcnow().isoformat()
    for d in devices:
        if 'error' in d:
            continue
        writer.writerow({
            'timestamp': now,
            'mac': d.get('mac', ''),
            'name': d.get('name', ''),
            'type': d.get('type', ''),
            'vendor': d.get('vendor', ''),
            'privacy_risk': d.get('privacy_risk', ''),
            'distance': d.get('distance', ''),
            'protocol': d.get('protocol', ''),
            'geo_lat': d.get('geo_lat', ''),
            'geo_lon': d.get('geo_lon', ''),
            'geo_alt': d.get('geo_alt', ''),
            'geo_acc': d.get('geo_acc', ''),
            'geo_timestamp': d.get('geo_timestamp', '')
        })
    return Response(si.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=civradar_export.csv'})

def export_json(devices):
    clean = [d for d in devices if 'error' not in d]
    return Response(json.dumps(clean, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=civradar_export.json'})

def export_geojson(devices):
    features = []
    for d in devices:
        if 'error' in d or not d.get('geo_lat'):
            continue
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [d['geo_lon'], d['geo_lat'], d.get('geo_alt', 0)]
            },
            "properties": {k: v for k, v in d.items() if k not in ['geo_lat', 'geo_lon', 'geo_alt']}
        })
    geojson = {"type": "FeatureCollection", "features": features}
    return Response(json.dumps(geojson, indent=2), mimetype='application/geo+json',
                    headers={'Content-Disposition': 'attachment; filename=civradar_export.geojson'})