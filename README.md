# Safety Sweep 🛡️

**A privacy-focused tool for preliminary screening of nearby Bluetooth devices, local network indicators, and potential stalkerware risks.**

Safety Sweep helps users review suspicious indicators and understand what to check next. It is designed to provide calm, explainable results while being transparent about the limitations of automated screening.

## ✨ Features

- **Bluetooth device discovery:** Scan for nearby Bluetooth Low Energy (BLE) advertisements using the local scanning engine.
- **Local network screening:** Check selected network ports and discover advertised services that may warrant further review.
- **Preliminary camera-risk screening:** Display selected network indicators associated with camera protocols. This does not confirm whether a hidden camera exists.
- **Stalkerware screening:** Provides a starting point for checking potential stalkerware indicators.
- **Dashboard:** View scan results and relevant device information.
- **CSV export:** Download scan reports for your own review.
- **Demo mode:** Explore example results without treating them as real detections.

## 🧰 Tech Stack

- Python
- FastAPI
- Uvicorn
- Bleak
- Zeroconf
- HTML, CSS and JavaScript

## 🏗️ Project Structure

```text
safety-sweep/
├── agent/
│   ├── conductor.py
│   ├── detector.py
│   ├── network_scan.py
│   ├── scan_test.py
│   ├── server.py
│   ├── stalkerware_scan.py
│   └── requirements.txt
├── web/
│   └── index.html
├── ble_check.py
├── requirements.txt
└── README.md
```

## 🚀 Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/varalikapgupta/safety-sweep.git
cd safety-sweep
```

### 2. Create and activate a virtual environment

On Windows:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```cmd
python -m pip install -r requirements.txt
```

If your local setup requires additional Bluetooth or network-scanning dependencies, install the dependencies listed in `agent/requirements.txt` as well.

### 4. Start the application

```cmd
python -m uvicorn agent.server:app --host 127.0.0.1 --port 8000
```

### 5. Open the dashboard

Visit:

http://127.0.0.1:8000/

API documentation is available at:

http://127.0.0.1:8000/docs

## ☁️ Deployment

The project includes a public Render deployment:

https://safety-sweep.onrender.com

**Important:** The cloud deployment cannot directly access Bluetooth hardware or the private Wi-Fi network of the visitor. Real Bluetooth and local-network scanning must run on the user's local machine. Cloud mode therefore disables Bluetooth scanning.

## 🔒 Privacy and Limitations

- A detected indicator is not proof of tracking, stalking, spyware, or a hidden camera.
- Network screening checks selected ports and advertised services; devices may be missed due to firewalls, isolation, or unsupported configurations.
- Bluetooth results depend on the local adapter, operating system, permissions, and devices advertising nearby.
- Browser-based app access cannot independently inspect all installed applications on a phone.
- Do not use scan results as a substitute for professional security assistance when safety is at risk.

## 🧪 Testing

The dashboard, network scan endpoint, and CSV export have been tested. Bluetooth scanning works in the local environment; it is intentionally unavailable in cloud mode.

## 🔮 Future Improvements

- Secure communication between the public dashboard and a local scanning agent.
- Improved scan-history and report handling.
- Clearer explanations of risk indicators and safer next steps.
- Additional validation to measure false positives and missed detections.

## 👥 Team

**Team DUALBYTE**

- Varalika Prodhatoori
- Sadhana C

Built for HackFest 2026 — Season 1.

---

*Safety Sweep is a preliminary screening tool, not a guarantee that a device, network, or room is free from surveillance.*
