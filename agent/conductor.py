
import asyncio
import time

from agent.detector import scan_ble_devices
from agent.network_scan import scan_network
from agent.stalkerware_scan import analyze_inventory

NETWORK_TIMEOUT = 30
BLE_TIMEOUT = 45


async def run_conductor(app_inventory=None):
    started = time.monotonic()
    results = {}
    warnings = []

    # 1. Bluetooth Low Energy scan
    try:
        results["ble"] = await asyncio.wait_for(
            scan_ble_devices(),
            timeout=BLE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        results["ble"] = {
            "status": "timeout",
            "devices_found": 0,
            "devices": [],
        }
        warnings.append("BLE scan timed out.")
    except Exception as exc:
        results["ble"] = {
            "status": "error",
            "devices_found": 0,
            "devices": [],
        }
        warnings.append(f"BLE scan failed: {type(exc).__name__}")

    # 2. Local network screening
    try:
        results["network"] = await asyncio.wait_for(
            scan_network(),
            timeout=NETWORK_TIMEOUT,
        )
    except asyncio.TimeoutError:
        results["network"] = {
            "status": "timeout",
            "message": "Network scan exceeded its time limit.",
        }
        warnings.append("Network scan timed out.")
    except Exception as exc:
        results["network"] = {"status": "error"}
        warnings.append(f"Network scan failed: {type(exc).__name__}")

    # 3. App-permission screening
    if app_inventory is not None:
        try:
            results["stalkerware"] = analyze_inventory(app_inventory)
        except Exception as exc:
            results["stalkerware"] = {"status": "error"}
            warnings.append(
                f"App screening failed: {type(exc).__name__}"
            )
    else:
        results["stalkerware"] = {
            "status": "not_run",
            "message": "No app inventory was supplied.",
        }

    return {
        "status": "completed" if not warnings else "partial",
        "duration_seconds": round(time.monotonic() - started, 2),
        "results": results,
        "warnings": warnings,
        "disclaimer": (
            "Screening indicators are not proof of tracking, "
            "a camera, or stalkerware. Missing results do not prove safety."
        ),
    }


async def main():
    # Synthetic example only; not a real installed-app inventory.
    demo_inventory = [
        {
            "app_name": "Example App",
            "package_name": "demo.example",
            "permissions": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_SMS",
            ],
        }
    ]

    report = await run_conductor(demo_inventory)

    print("Conductor status:", report["status"])
    print("Duration:", report["duration_seconds"], "seconds")

    for module, result in report["results"].items():
        print(f"\n--- {module.upper()} ---")
        print(result)

    if report["warnings"]:
        print("\nWarnings:", report["warnings"])


if __name__ == "__main__":
    asyncio.run(main())
