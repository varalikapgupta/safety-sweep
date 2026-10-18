
import json
from pathlib import Path


# Transparent screening rules, not a definitive spyware detector.
SENSITIVE_PERMISSIONS = {
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_CALL_LOG",
    "READ_CONTACTS",
    "READ_PHONE_STATE",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
}

LOCATION_PERMISSIONS = {
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
}

COMMUNICATION_PERMISSIONS = {
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_CALL_LOG",
    "READ_CONTACTS",
    "READ_PHONE_STATE",
}

SENSOR_PERMISSIONS = {
    "RECORD_AUDIO",
    "CAMERA",
}

PRIVILEGE_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
}


def normalize_permission(permission):
    """Accept Android permission names or fully qualified names."""
    return str(permission).strip().split(".")[-1].upper()


def analyze_app(app):
    name = str(app.get("app_name") or "Unknown app")
    package_name = str(app.get("package_name") or "unknown.package")

    raw_permissions = app.get("permissions") or []
    if not isinstance(raw_permissions, list):
        raw_permissions = []

    permissions = {
        normalize_permission(permission)
        for permission in raw_permissions
    }

    matched = permissions & SENSITIVE_PERMISSIONS
    reasons = []
    score = 0

    # Permission combinations deserve more attention than one permission.
    if permissions & LOCATION_PERMISSIONS:
        if permissions & SENSOR_PERMISSIONS:
            score += 2
            reasons.append(
                "Location and microphone/camera permissions coexist."
            )

        if permissions & COMMUNICATION_PERMISSIONS:
            score += 2
            reasons.append(
                "Location and communication-related permissions coexist."
            )

    if permissions & PRIVILEGE_PERMISSIONS:
        score += 1
        reasons.append(
            "A sensitive privilege or installation-related permission is listed."
        )

    if len(matched) >= 4:
        score += 1
        reasons.append(
            "Several sensitive permissions are listed together."
        )

    if not reasons:
        reasons.append(
            "No configured permission combination triggered a review rule."
        )

    if score >= 3:
        level = "HIGHER REVIEW PRIORITY"
    elif score >= 1:
        level = "REVIEW"
    else:
        level = "NO RULE TRIGGERED"

    return {
        "app_name": name,
        "package_name": package_name,
        "status": level,
        "score": score,
        "matched_permissions": sorted(matched),
        "reasons": reasons,
        "disclaimer": (
            "This is a heuristic screening result, not proof of "
            "stalkerware. Legitimate apps may use sensitive permissions, "
            "and harmful apps may evade these rules."
        ),
    }


def analyze_inventory(inventory):
    if not isinstance(inventory, list):
        raise ValueError("Inventory must be a JSON list of apps.")

    results = [analyze_app(app) for app in inventory if isinstance(app, dict)]

    priority = {
        "HIGHER REVIEW PRIORITY": 0,
        "REVIEW": 1,
        "NO RULE TRIGGERED": 2,
    }
    results.sort(key=lambda item: (priority[item["status"]], -item["score"]))

    return {
        "apps_analyzed": len(results),
        "higher_review_priority": sum(
            item["status"] == "HIGHER REVIEW PRIORITY" for item in results
        ),
        "needs_review": sum(
            item["status"] == "REVIEW" for item in results
        ),
        "results": results,
        "limitations": (
            "Analyze only app inventory data you own or are authorized "
            "to inspect. Permission lists alone cannot establish whether "
            "an app is malicious. This module does not inspect app code, "
            "network traffic, or device behavior."
        ),
    }


def main():
    # Small controlled dataset for testing the screening logic.
    demo_inventory = [
        {
            "app_name": "Example Maps",
            "package_name": "demo.maps",
            "permissions": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
            ],
        },
        {
            "app_name": "Example Background Utility",
            "package_name": "demo.utility",
            "permissions": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ],
        },
        {
            "app_name": "Example Calculator",
            "package_name": "demo.calculator",
            "permissions": [],
        },
    ]

    inventory_file = Path(__file__).with_name("app_inventory.json")

    if inventory_file.exists():
        try:
            with inventory_file.open("r", encoding="utf-8") as file:
                inventory = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"Could not read app_inventory.json: {error}")
    else:
        inventory = demo_inventory
        print("Using controlled demo data; no real phone was scanned.\n")

    report = analyze_inventory(inventory)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
