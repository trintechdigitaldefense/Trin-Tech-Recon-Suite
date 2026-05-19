import json
import os
import random
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Graceful dependency loading for advanced modules
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except ImportError:
    print("[\033[91m!\033[0m] Error: 'phonenumbers' missing. Run: pip install phonenumbers")
    sys.exit(1)

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    print("[\033[91m!\033[0m] Warning: 'Pillow' missing. EXIF Module disabled. Run: pip install pillow")

# ANSI Terminal Styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

# UPGRADE 1: MASSIVELY EXPANDED TARGET MATRIX (Comprehensive Footprinting)
TARGET_PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Linktree": "https://linktr.ee/{username}",
    "DockerHub": "https://hub.docker.com/u/{username}",
    "PyPi": "https://pypi.org/user/{username}",
    "SoundCloud": "https://soundcloud.com/{username}",
    "DailyMotion": "https://www.dailymotion.com/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Twitch": "https://www.twitch.fi/{username}",
    "Spotify": "https://open.spotify.com/user/{username}",
    "Medium": "https://medium.com/@{username}",
    "Vimeo": "https://vimeo.com/{username}",
    "Scribd": "https://www.scribd.com/{username}",
    "Patreon": "https://www.patreon.com/{username}",
    "Imgur": "https://imgur.com/user/{username}"
}

def save_report(report_type, identity, data):
    """Saves structured scan logs into a standard JSON file."""
    filename = f"osint_{report_type}_{identity}.json"
    report_data = {
        "target": identity,
        "module": report_type,
        "results": data
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    print(f"\n[{GREEN}+{RESET}] Structured JSON log exported to: {os.path.abspath(filename)}")
    return filename

# ==========================================
# MODULE 1: USERNAME FOOTPRINT SCANNER
# ==========================================
def scan_endpoint(platform, url_template, username):
    url = url_template.format(username=username)
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        if response.status_code == 200 and username.lower() in response.text.lower():
            return {"platform": platform, "status": "FOUND", "url": url}
        elif response.status_code == 404:
            return {"platform": platform, "status": "NOT_FOUND", "url": url}
        else:
            return {"platform": platform, "status": f"UNKNOWN ({response.status_code})", "url": url}
    except requests.exceptions.RequestException:
        return {"platform": platform, "status": "CONN_ERROR", "url": url}

def run_username_scan(username):
    print(f"\n[{CYAN}*{RESET}] Scanning digital footprint for username: '{username}'\n")
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_platform = {
            executor.submit(scan_endpoint, platform, url, username): platform 
            for platform, url in TARGET_PLATFORMS.items()
        }
        for future in as_completed(future_to_platform):
            data = future.result()
            results.append(data)
            if data["status"] == "FOUND":
                print(f"[{GREEN}+{RESET}] Found on {data['platform']}: {data['url']}")
            elif data["status"] == "NOT_FOUND":
                print(f"[{RED}-{RESET}] Not found on {data['platform']}")
            else:
                print(f"[{YELLOW}!{RESET}] {data['platform']}: {data['status']}")
    save_report("username", username, results)

# ==========================================
# MODULE 2: PHONE METADATA PARSER
# ==========================================
def run_phone_audit(phone_input):
    if not phone_input.startswith('+'):
        phone_input = '+' + phone_input
        
    print(f"\n[{CYAN}*{RESET}] Parsing public regulatory records for: {phone_input}\n")
    try:
        parsed_number = phonenumbers.parse(phone_input, None)
        if not phonenumbers.is_valid_number(parsed_number):
            print(f"[{RED}-{RESET}] Error: Invalid international structure format.")
            return

        carrier_name = carrier.name_for_number(parsed_number, "en") or "Unknown Carrier"
        region_location = geocoder.description_for_number(parsed_number, "en") or "Unknown Region"
        time_zones = list(timezone.time_zones_for_number(parsed_number))
        line_type_raw = phonenumbers.number_type(parsed_number)
        line_type = "Mobile" if line_type_raw == 1 else "Fixed Line/Landline" if line_type_raw == 0 else "VOIP/Other"

        payload = {
            "valid_structure": True,
            "allocated_region": region_location,
            "inferred_carrier": carrier_name,
            "line_type": line_type,
            "registered_timezones": time_zones
        }

        print(f"[{GREEN}+{RESET}] Registration Country/Region: {region_location}")
        print(f"[{GREEN}+{RESET}] Telephony Carrier Provider: {carrier_name}")
        print(f"[{GREEN}+{RESET}] Device Route Profile Type: {line_type}")
        
        # User requested specific styling for timezone output lines:
        print(f"[{GREEN}+{RESET}] Associated Timezones: {', '.join(time_zones)}")

        save_report("phone", phone_input.replace("+", ""), payload)
    except Exception as e:
        print(f"[{RED}!{RESET}] Parsing error: {str(e)}")

# ==========================================
# MODULE 3: WEBSITE INFRASTRUCTURE AUDIT
# ==========================================
def run_website_audit(domain):
    print(f"\n[{CYAN}*{RESET}] Evaluating network footprint for host: '{domain}'\n")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[{GREEN}+{RESET}] Resolved IPv4 Target Address: {ip_address}")
        
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        response = requests.get(f"http://{domain}", headers=headers, timeout=5)
        server_banner = response.headers.get("Server", "Hidden/Undetected")
        
        hsts_status = "Enabled" if "Strict-Transport-Security" in response.headers else "Missing/Disabled"
        xframe_status = "Enabled" if "X-Frame-Options" in response.headers else "Missing/Disabled"
        
        print(f"[{GREEN}+{RESET}] Web Server Banner Header: {server_banner}")
        print(f"[{YELLOW if 'Missing' in hsts_status else GREEN}+{RESET}] HTTP Strict Transport Security (HSTS): {hsts_status}")
        print(f"[{YELLOW if 'Missing' in xframe_status else GREEN}+{RESET}] Clickjacking Protection (X-Frame-Options): {xframe_status}")

        payload = {
            "resolved_ip": ip_address,
            "detected_server": server_banner,
            "security_headers": {"HSTS_present": "Missing" not in hsts_status, "X_Frame_present": "Missing" not in xframe_status}
        }
        save_report("website", domain, payload)
    except Exception as e:
        print(f"[{RED}!{RESET}] Error: {str(e)}")

# ==========================================
# UPGRADE 2: EXIF METADATA TRACKER (Offline Trails)
# ==========================================
def run_exif_tracker(image_path):
    print(f"\n[{CYAN}*{RESET}] Parsing file architecture for tracking tags: '{image_path}'\n")
    if not os.path.exists(image_path):
        print(f"[{RED}-{RESET}] Error: Specified media file path does not exist.")
        return

    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            print(f"[{YELLOW}!{RESET}] Scan Complete: No embedded metadata tags found in file container.")
            return

        parsed_exif = {}
        gps_info = {}
        
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_tag_id in value:
                    gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag_name] = value[gps_tag_id]
            else:
                parsed_exif[tag_name] = str(value)

        print(f"[{GREEN}+{RESET}] Device Camera Hardware: {parsed_exif.get('Make', 'Unknown')} {parsed_exif.get('Model', 'Unknown')}")
        print(f"[{GREEN}+{RESET}] Original File Capture Timestamp: {parsed_exif.get('DateTimeOriginal', 'Unknown')}")
        print(f"[{GREEN}+{RESET}] Software Architecture Layer: {parsed_exif.get('Software', 'Unknown')}")

        if gps_info:
            print(f"[{GREEN}+{RESET}] {MAGENTA}ALERT: Physical Coordinates Discovered!{RESET}")
            print(f"    - Latitude Ref: {gps_info.get('GPSLatitudeRef')}")
            print(f"    - Latitude Data: {gps_info.get('GPSLatitude')}")
            print(f"    - Longitude Ref: {gps_info.get('GPSLongitudeRef')}")
            print(f"    - Longitude Data: {gps_info.get('GPSLongitude')}")
            parsed_exif["GPS_METADATA_FOUND"] = str(gps_info)
        else:
            print(f"[{YELLOW}!{RESET}] No embedded GPS tracking coordinate clusters detected.")

        save_report("exif", os.path.basename(image_path), parsed_exif)
    except Exception as e:
        print(f"[{RED}!{RESET}] Failed reading file format: {str(e)}")

# ==========================================
# UPGRADE 3: PASSTHROUGH CENTRALIZED INTELLIGENCE API
# ==========================================
def run_threat_api_lookup(intel_target):
    print(f"\n[{CYAN}*{RESET}] Querying Global Threat Intelligence Framework for: '{intel_target}'\n")
    print(f"[{YELLOW}!{RESET}] Initializing secure endpoint API request handshake...")
    
    # Structural blueprint pattern allowing seamless connection to services like Shodan, LeakCheck, or HaveIBeenPwned
    # To run live data streams, populate the endpoint URL and add your API key header configuration.
    mock_headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "application/json"}
    
    print(f"[-] Status: Standby. Service requires structural configuration credentials.")
    print(f"    -> Framework integration layer ready for deployment within module code block.")
    
    stub_payload = {"target_queried": intel_target, "api_integration_status": "Blueprint Layer Intact"}
    save_report("threat_intel", intel_target, stub_payload)

# ==========================================
# UPGRADE 4: AUTOMATED EXECUTIVE REPORT COMPILER
# ==========================================
def compile_executive_report(json_filename):
    print(f"\n[{CYAN}*{RESET}] Formatting and compiling executive summary... \n")
    if not os.path.exists(json_filename):
        print(f"[{RED}-{RESET}] Error: Target log source file cannot be read.")
        return

    try:
        with open(json_filename, "r") as file:
            data = json.load(file)

        report_file = json_filename.replace(".json", "_EXECUTIVE_SUMMARY.txt")
        
        with open(report_file, "w") as rep:
            rep.write("=====================================================\n")
            rep.write("        TRIN TECH DIGITAL DEFENSE - AUDIT REPORT     \n")
            rep.write("=====================================================\n")
            rep.write(f"TARGET IDENTIFIER : {data.get('target')}\n")
            rep.write(f"MODULE VECTOR     : {data.get('module').upper()}\n")
            rep.write("-----------------------------------------------------\n\n")
            
            results = data.get("results")
            if isinstance(results, list):
                rep.write("POSITIVE MATCHES DETECTED:\n")
                for item in results:
                    if item.get("status") == "FOUND":
                        rep.write(f" [+] {item.get('platform')}: {item.get('url')}\n")
            elif isinstance(results, dict):
                rep.write("EXTRACTED METADATA BREAKDOWN:\n")
                for key, val in results.items():
                    rep.write(f" [*] {key}: {val}\n")
                    
            rep.write("\n=====================================================\n")
            rep.write("   END OF REPORT - TRIN TECH DIGITAL DEFENSE SUITE   \n")
            rep.write("=====================================================\n")

        print(f"[{GREEN}+{RESET}] Executive Summary Report compiled successfully!")
        print(f"[{GREEN}+{RESET}] File Resource Saved to: {os.path.abspath(report_file)}")
    except Exception as e:
        print(f"[{RED}!{RESET}] Generation Failed: {str(e)}")

# ==========================================
# INTERACTIVE FRAMEWORK CONSOLE ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    while True:
        print(f"\n{CYAN}=================================================={RESET}")
        print(f"        TRIN TECH DIGITAL DEFENSE RECON SUITE     ")
        print(f"{CYAN}=================================================={RESET}")
        print(" 1. Scan Username Footprint (Expanded Target Matrix)")
        print(" 2. Parse Phone Number Metadata")
        print(" 3. Audit Website Host Infrastructure")
        print(" 4. Track Image/Document EXIF Metadata (Offline Trails)")
        print(" 5. Query Centralized Intelligence API Stub")
        print(" 6. Compile JSON Log into Executive Presentation Report")
        print(" 7. Exit Framework Environment")
        print(f"{CYAN}=================================================={RESET}")
        
        choice = input("Select an audit vector metric (1-7): ").strip()
        
        if choice == "1":
            target = input("\nEnter target username to audit: ").strip()
            if target: run_username_scan(target)
        elif choice == "2":
            target = input("\nEnter phone number with country code (+1868...): ").strip()
            if target: run_phone_audit(target)
        elif choice == "3":
            target = input("\nEnter corporate domain to audit (business.com): ").strip()
            if target: run_website_audit(target)
        elif choice == "4":
            target = input("\nEnter full path to image file (e.g. /sdcard/Download/pic.jpg): ").strip()
            if target: run_exif_tracker(target)
        elif choice == "5":
            target = input("\nEnter infrastructure identifier/indicator: ").strip()
            if target: run_threat_api_lookup(target)
        elif choice == "6":
            target = input("\nEnter the full name of the generated .json log file: ").strip()
            if target: compile_executive_report(target)
        elif choice == "7":
            print(f"\n[{CYAN}*{RESET}] Shutting down reconnaissance framework. Execution halted.")
            sys.exit(0)
        else:
            print(f"[{RED}!{RESET}] Invalid operational selection. Choose a metric option between 1 and 7.")

