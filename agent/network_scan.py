
import asyncio
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

# IMPORTANT: Change this to your actual private subnet after checking ipconfig.
LOCAL_NETWORK = "192.168.1.0/24"

CAMERA_SERVICE_TYPES = [
    "_rtsp._tcp.local.",
    "_onvif._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
]

# These ports are clues, not proof of a camera.
CAMERA_RELATED_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    8554: "RTSP alternate",
}


class CameraServiceListener(ServiceListener):
    def __init__(self):
        self.devices = []

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if not info:
            return

        addresses = [
            str(ipaddress.ip_address(address))
            for address in (info.addresses or [])
        ]

        self.devices.append({
            "name": name,
            "service": service_type,
            "port": info.port,
            "addresses": addresses,
        })

    def update_service(self, zeroconf, service_type, name):
        self.add_service(zeroconf, service_type, name)

    def remove_service(self, zeroconf, service_type, name):
        pass


def check_host(host):
    """Check selected TCP ports on a host in the configured private subnet."""
    findings = []

    for port, service_name in CAMERA_RELATED_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=0.4):
                camera_related = port in (554, 8554)

                findings.append({
                    "port": port,
                    "service": service_name,
                    "status": "OPEN",
                    "camera_related": camera_related,
                    "reason": (
                        "Streaming-related port responded; verify the service."
                        if camera_related
                        else
                        "Generic web port responded; device type is unknown."
                    ),
                })
        except OSError:
            pass

    if not findings:
        return None

    camera_hints = [
        item for item in findings if item["camera_related"]
    ]

    return {
        "ip_address": host,
        "status": "REVIEW",
        "camera_indicator": bool(camera_hints),
        "reason": (
            "Streaming-related port found; verify device identity manually."
            if camera_hints
            else
            "Web service found; this alone is not a camera indicator."
        ),
        "open_ports": findings,
    }


async def scan_network():
    network = ipaddress.ip_network(LOCAL_NETWORK, strict=True)

    if not network.is_private:
        raise ValueError("Only a private local network is permitted.")

    listener = CameraServiceListener()
    zeroconf = Zeroconf()
    browsers = []

    try:
        for service_type in CAMERA_SERVICE_TYPES:
            browsers.append(
                ServiceBrowser(zeroconf, service_type, listener)
            )

        # Allow time for local service advertisements.
        await asyncio.sleep(5)

        advertised = []
        seen_services = set()

        for device in listener.devices:
            key = (
                device["name"],
                device["service"],
                tuple(device["addresses"]),
                device["port"],
            )
            if key in seen_services:
                continue
            seen_services.add(key)

            camera_hint = device["service"] in {
                "_rtsp._tcp.local.",
                "_onvif._tcp.local.",
            }

            advertised.append({
                **device,
                "camera_indicator": camera_hint,
                "status": "REVIEW" if camera_hint else "SERVICE FOUND",
                "reason": (
                    "RTSP/ONVIF advertised; verify device identity manually."
                    if camera_hint
                    else
                    "Web service advertised; device type is unknown."
                ),
            })
    finally:
        browsers.clear()
        zeroconf.close()

    loop = asyncio.get_running_loop()
    hosts = list(network.hosts())

    with ThreadPoolExecutor(max_workers=32) as pool:
        tasks = [
            loop.run_in_executor(pool, check_host, str(host))
            for host in hosts
        ]
        results = await asyncio.gather(*tasks)

    port_findings = [item for item in results if item]

    camera_services = [
        item for item in advertised if item["camera_indicator"]
    ]
    camera_port_hints = [
        item for item in port_findings if item["camera_indicator"]
    ]

    return {
        # Existing keys retained for dashboard compatibility.
        "status": "completed",
        "subnet_checked": str(network),
        "advertised_services_found": len(advertised),
        "port_findings_found": len(port_findings),
        "advertised_services": advertised,
        "port_findings": port_findings,

        # New camera-screening summary.
        "possible_camera_indicators": (
            len(camera_services) + len(camera_port_hints)
        ),
        "camera_screening_status": (
            "REVIEW"
            if camera_services or camera_port_hints
            else "NO INDICATORS FOUND"
        ),
        "limitations": (
            "This is a preliminary screening tool, not a hidden-camera "
            "detector. RTSP/ONVIF advertisements and streaming-related ports "
            "are clues, not proof. Generic web ports do not establish that "
            "a device is a camera. Offline devices, isolated Wi-Fi clients, "
            "firewalls, nonstandard ports, and unadvertised services may "
            "be missed. A clean scan does not rule out hidden cameras."
        ),
    }


if __name__ == "__main__":
    result = asyncio.run(scan_network())
    print("Network:", result["subnet_checked"])
    print("Advertised services:", result["advertised_services_found"])
    print("Hosts needing review:", result["port_findings_found"])
    print("Possible camera indicators:",
          result["possible_camera_indicators"])
    print("Screening status:", result["camera_screening_status"])

    for finding in result["port_findings"]:
        print(finding)

    print(result["limitations"])
