# Trin-Tech Recon Suite

> **TrinTech Digital Defense** — Mass OSINT Username Enumeration & Digital Footprint Scanner

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platforms](https://img.shields.io/badge/Platforms-50%2B%20Social%20Media-yellow.svg)

---

## Overview

Trin-Tech Recon Suite is a comprehensive OSINT username enumeration tool that scans **50+ platforms** simultaneously to map a person's digital footprint. It checks for the existence of a given username across social media, professional networks, creative platforms, and developer communities — producing structured JSON reports.

## Features

- **Mass platform scanning** — 50+ sites checked in parallel via `ThreadPoolExecutor`
- **Phone number analysis** — carrier, location, and timezone lookup via `phonenumbers`
- **EXIF metadata extraction** — GPS coordinates, device info, timestamps from images
- **Structured JSON output** — every scan produces a timestamped report file
- **Configurable user-agent rotation** — mimics multiple browser profiles to avoid detection
- **Rate limiting** — built-in delays to prevent IP bans during scanning
- **Color-coded terminal output** — found vs not-found with visual distinction
- **Modular platform definitions** — easy to add new platforms

## Scanned Platforms

| Category | Platforms |
|----------|-----------|
| **Social** | Facebook, Twitter/X, Instagram, Reddit, TikTok, Telegram |
| **Professional** | LinkedIn, GitHub, Stack Overflow |
| **Creative** | SoundCloud, Spotify, Vimeo, Imgur, Pinterest, Dailymotion |
| **Developer** | DockerHub, PyPi, GitHub |
| **Other** | Linktree, Medium, Scribd, Patreon, Steam, Twitch, WhatsApp, WhatsApp-Status |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan a username
python3 osint_scanner.py

# Example: scan "jason.ramdharry" across 50+ platforms
# Output saved to: osint_username_jason_ramdharry_YYYYMMDD_HHMMSS.json
```

## Usage

```python
from osint_scanner import OSINTScanner

scanner = OSINTScanner()

# Scan username across all platforms
results = scanner.scan_username("target_user")

# Scan phone number
phone_data = scanner.scan_phone("+18683620679")

# Scan image EXIF data
exif_data = scanner.scan_image("photo.jpg")

# Export results
scanner.save_report("username", "target_user", results)
```

## Output

### Terminal
```
[🟢] Facebook:    FOUND — https://www.facebook.com/target_user
[🟡] Twitter:     FOUND — https://twitter.com/target_user
[⚫] Instagram:   Not found
[🟢] LinkedIn:    FOUND — https://linkedin.com/in/target_user
...
```

### JSON Report (`osint_username_<user>_YYYYMMDD_HHMMSS.json`)
```json
{
  "scan_type": "username",
  "identity": "target_user",
  "timestamp": "2026-07-27T01:30:00",
  "platforms_checked": 52,
  "platforms_found": 12,
  "platforms_not_found": 40,
  "results": {
    "facebook": {"found": true, "url": "https://www.facebook.com/target_user"},
    "twitter": {"found": true, "url": "https://twitter.com/target_user"},
    ...
  }
}
```

## Installation

```bash
apt update && apt upgrade -y
apt install python3 python3-pip git -y

git clone https://github.com/trintechdigitaldefense/Trin-Tech-Recon-Suite.git
cd Trin-Tech-Recon-Suite
pip install -r requirements.txt
python3 osint_scanner.py
```

## Dependencies

- `requests` — HTTP platform checks
- `phonenumbers` — Phone number analysis
- `Pillow` — Image EXIF metadata extraction (optional)

## Use Cases

- **Client onboarding** — map a client's existing online presence before security audit
- **Threat intelligence** — find attacker-associated accounts
- **Brand protection** — detect unauthorized accounts using brand names
- **Investigations** — identify individuals across platforms
- **Due diligence** — verify professional identities

## License

All Rights Reserved — TrinTech Digital Defense

## About

TrinTech Digital Defense is a Trinidad & Tobago cybersecurity consultancy.

- 🌐 [trintechdigitaldefense.github.io](https://trintechdigitaldefense.github.io)
- 📧 [trintechdigitaldefense@gmail.com](mailto:trintechdigitaldefense@gmail.com)
- 📱 +1 (868) 362-0679

---

*DEFEND. DETECT. DOMINATE. 🇹🇹*
