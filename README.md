# Trin-Tech-Recon-Suite
A lightweight, multi-threaded OSINT and infrastructure auditing suite.
# Trin Tech Digital Defense - Recon Suite 🚀

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform Support](https://img.shields.io/badge/platform-Linux%20%7C%20Termux%20%7C%20macOS-green)
![License](https://img.shields.io/badge/license-MIT-purple)

A lightweight, multi-threaded Open Source Intelligence (OSINT) footprinting and infrastructure auditing suite. Built to be highly portable, this framework runs seamlessly on enterprise Linux environments as well as directly inside mobile terminals like **Termux** for on-the-go security assessments.

---

## 🛠️ Features

* **Multi-Threaded Username Recon:** Scans 16+ core web platforms simultaneously using parallel execution (`ThreadPoolExecutor`) with customized user-agent rotation to prevent rate limiting.
* **Phone Metadata Parser:** Interrogates international telecom registries to extract carrier allocation, line routing profiles (Mobile vs. Landline), and regional data.
* **Website Infrastructure Audit:** Performs swift IPv4 target resolution, captures web server banner signatures (`Nginx`, `Apache`), and flags missing defensive configurations (HSTS and X-Frame-Options).
* **EXIF Location Tracker (Offline Trails):** Parses local image/document containers to uncover embedded forensic tags, device profiles, and physical GPS coordinates.
* **Automated Executive Reporting:** Instantly processes raw JSON log streams into clean, human-readable text summaries (`_EXECUTIVE_SUMMARY.txt`) ready for client delivery.

---

## 📦 Installation & Setup

### For Standard Linux / macOS
```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/Trin-Tech-Recon-Suite.git](https://github.com/YOUR_USERNAME/Trin-Tech-Recon-Suite.git)
cd Trin-Tech-Recon-Suite

# Install dependencies
pip install -r requirements.txt

# Run the suite
python3 osint_scanner.py
