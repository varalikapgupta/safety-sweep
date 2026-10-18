from agent.network_scan import scan_network
from agent.stalkerware_scan import analyze_inventory
import csv
import io
from fastapi.responses import StreamingResponse
import sqlite3
from datetime import datetime
from pathlib import Path

from bleak import BleakScanner
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI(title="Safety Sweep")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_FILE = BASE_DIR / "web" / "index.html"
DB_FILE = Path(__file__).resolve().parent / "safety_sweep.db"

APPLE_COMPANY_ID = 0x004C
SAMSUNG_UUIDS = {"fd5a"}
TILE_UUIDS = {"feed", "feec"}


def current_time():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    with get_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                address TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                sightings INTEGER NOT NULL DEFAULT 0
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS signal_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                rssi INTEGER
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_signal_address_id
            ON signal_readings(address, id)
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                devices_found INTEGER NOT NULL DEFAULT 0
            )
        """)


def record_scan(scan_time, device_count):
    with get_connection() as db:
        cursor = db.execute("""
            INSERT INTO scans (scanned_at, devices_found)
            VALUES (?, ?)
        """, (scan_time, device_count))
        return cursor.lastrowid


def record_observation(address, scan_time, rssi):
    with get_connection() as db:
        db.execute("""
            INSERT INTO observations (
                address, first_seen, last_seen, sightings
            )
            VALUES (?, ?, ?, 1)
            ON CONFLICT(address) DO UPDATE SET
                last_seen = excluded.last_seen,
                sightings = observations.sightings + 1
        """, (address, scan_time, scan_time))

        db.execute("""
            INSERT INTO signal_readings (address, recorded_at, rssi)
            VALUES (?, ?, ?)
        """, (address, scan_time, rssi))

        row = db.execute("""
            SELECT first_seen, last_seen, sightings
            FROM observations
            WHERE address = ?
        """, (address,)).fetchone()

        readings = db.execute("""
            SELECT recorded_at, rssi
            FROM (
                SELECT id, recorded_at, rssi
                FROM signal_readings
                WHERE address = ?
                ORDER BY id DESC
                LIMIT 30
            )
            ORDER BY id ASC
        """, (address,)).fetchall()

    return {
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "sightings": row["sightings"],
        "signal_history": [
            {"time": item["recorded_at"], "rssi": item["rssi"]}
            for item in readings
        ],
    }


def get_summary():
    with get_connection() as db:
        total_scans = db.execute("""
            SELECT COUNT(*) FROM scans
        """).fetchone()[0]

        unique_addresses = db.execute("""
            SELECT COUNT(*) FROM observations
        """).fetchone()[0]

        repeated_addresses = db.execute("""
            SELECT COUNT(*) FROM observations
            WHERE sightings >= 2
        """).fetchone()[0]

        latest_scan = db.execute("""
            SELECT scanned_at FROM scans
            ORDER BY id DESC LIMIT 1
        """).fetchone()

    return {
        "total_scans": total_scans,
        "unique_addresses": unique_addresses,
        "repeated_addresses": repeated_addresses,
        "latest_scan": latest_scan["scanned_at"] if latest_scan else None,
    }


def classify_device(name, advertisement):
    name = (name or "").strip()

    if name.lower() == "testtag":
        return (
            "DEMO BEACON",
            "Controlled test beacon; not a confirmed tracker",
        )

    services = {
        uuid.lower().split("-")[0][-4:]
        for uuid in (advertisement.service_uuids or [])
    }
    manufacturers = advertisement.manufacturer_data or {}
    reasons = []

    if APPLE_COMPANY_ID in manufacturers:
        reasons.append("Apple company identifier present")

    if services & SAMSUNG_UUIDS:
        reasons.append("Samsung-related service UUID present")

    if services & TILE_UUIDS:
        reasons.append("Tile-related service UUID present")

    if reasons:
        return "REVIEW", "; ".join(reasons)

    return "UNCLASSIFIED", "No configured indicator found"


@app.on_event("startup")
async def startup():
    init_database()


@app.get("/")
async def dashboard():
    if not WEB_FILE.exists():
        raise HTTPException(404, "web/index.html not found")
    return FileResponse(WEB_FILE)


@app.get("/api/summary")
async def summary():
    return get_summary()


@app.get("/api/export.csv")
async def export_csv():
    try:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Bluetooth Address",
            "First Seen",
            "Last Seen",
            "Sightings",
            "Reading Time",
            "RSSI (dBm)",
        ])

        with get_connection() as db:
            rows = db.execute("""
                SELECT
                    o.address,
                    o.first_seen,
                    o.last_seen,
                    o.sightings,
                    s.recorded_at,
                    s.rssi
                FROM observations AS o
                LEFT JOIN signal_readings AS s
                    ON s.address = o.address
                ORDER BY o.address, s.id
            """).fetchall()

        for row in rows:
            writer.writerow([
                row["address"],
                row["first_seen"],
                row["last_seen"],
                row["sightings"],
                row["recorded_at"] or "",
                row["rssi"] if row["rssi"] is not None else "",
            ])

        output.seek(0)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition":
                    'attachment; filename="safety_sweep_report.csv"'
            },
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"CSV export failed: {error}",
        ) from error
        
@app.get("/api/network-scan")
async def network_scan_endpoint():
    try:
        return await scan_network()
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Network scan failed: {error}",
        ) from error

from pydantic import BaseModel
from typing import Any


class AppInventoryRequest(BaseModel):
    apps: list[dict[str, Any]]


@app.post("/api/stalkerware-scan")
async def stalkerware_scan_endpoint(request: AppInventoryRequest):
    try:
        return analyze_inventory(request.apps)
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Stalkerware screening failed: {error}",
        ) from error


@app.get("/api/scan")
async def scan():
    try:
        results = await BleakScanner.discover(
            timeout=10.0,
            return_adv=True,
        )

        scan_time = current_time()
        record_scan(scan_time, len(results))
        devices = []

        for address, (device, advertisement) in results.items():
            name = (
                advertisement.local_name
                or device.name
                or "Unknown device"
            )
            status, reason = classify_device(name, advertisement)
            rssi = advertisement.rssi
            history = record_observation(address, scan_time, rssi)
            manufacturer_data = advertisement.manufacturer_data or {}

            devices.append({
                "name": name,
                "address": address,
                "rssi": rssi,
                "status": status,
                "reason": reason,
                "service_uuids": advertisement.service_uuids or [],
                "company_ids": [
                    f"0x{company_id:04X}"
                    for company_id in manufacturer_data
                ],
                "manufacturer_data": {
                    f"0x{company_id:04X}": data.hex(" ")
                    for company_id, data in manufacturer_data.items()
                },
                **history,
            })

        devices.sort(
            key=lambda item: (
                item["rssi"] if item["rssi"] is not None else -999
            ),
            reverse=True,
        )

        return {
            "count": len(devices),
            "devices": devices,
            "scan_time": scan_time,
            "summary": get_summary(),
            "message": (
                "History is saved locally. RSSI varies with obstacles "
                "and interference. Screening indicators are not proof "
                "of tracking. Addresses may rotate."
            ),
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"{type(error).__name__}: {error}",
        ) from error
