
import asyncio
from bleak import BleakScanner

APPLE_COMPANY_ID = 0x004C
SAMSUNG_UUIDS = {"fd5a"}
TILE_UUIDS = {"feed", "feec"}

DISCLAIMER = (
    "BLE indicators are preliminary screening results, "
    "not proof of tracking."
)


def classify_device(name, advertisement):
    name = (name or "").strip()

    if name.lower() == "testtag":
        return (
            "DEMO BEACON",
            "Controlled test beacon; not a confirmed tracker"
        )

    services = {
        str(uuid).lower().split("-")[0]
        for uuid in (advertisement.service_uuids or [])
    }

    manufacturer_data = advertisement.manufacturer_data or {}
    indicators = []

    if APPLE_COMPANY_ID in manufacturer_data:
        indicators.append(
            "Apple manufacturer data present; device type unconfirmed"
        )

    if services & SAMSUNG_UUIDS:
        indicators.append("Samsung-related service UUID")

    if services & TILE_UUIDS:
        indicators.append("Tile-related service UUID")

    if indicators:
        return "REVIEW", "; ".join(indicators)

    return "UNCLASSIFIED", "No configured indicator found"


async def scan_ble_devices(timeout=30.0):
    discovered = {}

    def detection_callback(device, advertisement):
        name = (
            advertisement.local_name
            or device.name
            or "Unknown"
        )

        # Save the latest observation for each address.
        discovered[device.address] = (device, advertisement)

        if name.lower() == "testtag":
            print(
                f"BLE CALLBACK: {name} | "
                f"{device.address} | "
                f"RSSI: {advertisement.rssi} dBm"
            )

    scanner = BleakScanner(detection_callback)

    try:
        print(f"Listening for BLE advertisements for {timeout} seconds...")
        await scanner.start()

        try:
            await asyncio.sleep(timeout)
        finally:
            await scanner.stop()

        devices = []

        for address, (device, advertisement) in discovered.items():
            name = (
                advertisement.local_name
                or device.name
                or "Unknown"
            )

            status, reason = classify_device(name, advertisement)

            manufacturer_data = {
                f"0x{company_id:04X}": bytes(payload).hex()
                for company_id, payload
                in (advertisement.manufacturer_data or {}).items()
            }

            devices.append({
                "name": name,
                "address": address,
                "rssi": advertisement.rssi,
                "services": list(advertisement.service_uuids or []),
                "company_ids": list(manufacturer_data.keys()),
                "manufacturer_data": manufacturer_data,
                "status": status,
                "reason": reason,
            })

        return {
            "status": "completed",
            "devices_found": len(devices),
            "devices": devices,
            "disclaimer": DISCLAIMER,
        }

    except Exception as error:
        print(f"BLE scan error: {type(error).__name__}: {error}")
        return {
            "status": "error",
            "devices_found": 0,
            "devices": [],
            "error": str(error),
            "disclaimer": DISCLAIMER,
        }


async def main():
    print("=" * 50)
    print("SAFETY SWEEP - BLE DETECTOR")
    print("Keep your TestTag advertiser running.")
    print("=" * 50)

    result = await scan_ble_devices(timeout=30.0)

    print(f"Scan status: {result['status']}")
    print(f"Unique devices found: {result['devices_found']}")

    for device in result["devices"]:
        print("-" * 40)
        print(f"Name: {device['name']}")
        print(f"Address: {device['address']}")
        print(f"RSSI: {device['rssi']} dBm")
        print(f"Status: {device['status']}")
        print(f"Reason: {device['reason']}")
        print(f"Services: {device['services']}")

    print(DISCLAIMER)


if __name__ == "__main__":
    asyncio.run(main())
