
import asyncio
from bleak import BleakScanner


async def main():
    print("Safety Sweep - BLE Beacon Test")
    print("Keep TestTag advertising on your iPhone.")
    print("Scanning for 20 seconds...\n")

    try:
        results = await BleakScanner.discover(
            timeout=20.0,
            return_adv=True
        )

        if not results:
            print("No BLE advertisements detected.")
            return

        testtag_found = False

        for address, (device, advertisement) in results.items():
            name = advertisement.local_name or device.name or "Unknown device"
            rssi = advertisement.rssi
            service_uuids = advertisement.service_uuids or []

            if name == "TestTag":
                testtag_found = True

            print(f"Name:     {name}")
            print(f"Address:  {address}")
            print(f"Signal:   {rssi} dBm")
            print(f"Services: {service_uuids}")
            print("-" * 45)

        if testtag_found:
            print("\nSUCCESS: TestTag detected!")
        else:
            print("\nTestTag not found during this scan.")

    except Exception as error:
        print(f"Bluetooth scan failed: {type(error).__name__}: {error}")


if __name__ == "__main__":
    asyncio.run(main())
