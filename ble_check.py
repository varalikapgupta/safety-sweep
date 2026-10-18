
import asyncio
from bleak import BleakScanner

def detection_callback(device, advertisement_data):
    print(
        f"Device: {device.address} | "
        f"Name: {device.name} | "
        f"RSSI: {advertisement_data.rssi} | "
        f"Services: {advertisement_data.service_uuids}"
    )

async def main():
    print("Listening for BLE advertisements for 30 seconds...")
    scanner = BleakScanner(detection_callback)

    try:
        await scanner.start()
        await asyncio.sleep(30)
        await scanner.stop()
        print("Scan complete.")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")

asyncio.run(main())

