#!/usr/bin/env python3
"""
ScoutOut – VirusTotal backend test script
Sends HTTPS packets with known-malicious IPs to the API, then polls
/api/threats/enhanced until VirusTotal results come back.

Usage:
    python test_vt_packets.py
    python test_vt_packets.py --api http://192.168.4.115:5050/api
    python test_vt_packets.py --api http://localhost:5050/api --wait 45
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    raise SystemExit("requests not installed — run: pip install requests")

# ---------------------------------------------------------------------------
# Known-malicious IPs (confirmed flagged on VirusTotal)
# Replace / extend this list as needed.
# ---------------------------------------------------------------------------
MALICIOUS_IPS = [
    "185.220.101.34",   # Tor exit node / C2 — VT: ~17 malicious
    "194.165.16.77",    # Malware distribution — VT: ~1 malicious
    "45.142.212.100",   # Botnet C2 — VT: ~10 malicious
    "91.92.109.146",    # Phishing host
    "193.32.162.157",   # C2 server
    "179.43.154.138",   # Ransomware distribution
]

# Clean IPs to mix in (should return 0 detections)
CLEAN_IPS = [
    "8.8.8.8",          # Google DNS
    "1.1.1.1",          # Cloudflare DNS
    "142.250.80.46",    # Google
]


def build_packets(malicious_ips: list, clean_ips: list, src_prefix: str = "192.168.1") -> list:
    """Build a batch of realistic-looking HTTPS packets."""
    packets = []
    all_dests = malicious_ips + clean_ips

    for i, dest_ip in enumerate(all_dests):
        packets.append({
            "id": int(time.time() * 1000) + i,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "protocol": "HTTPS",
            "sourceIP": f"{src_prefix}.{random.randint(2, 50)}",
            "destIP": dest_ip,
            "sourcePort": random.randint(49152, 65535),
            "destPort": 443,
            "length": random.randint(64, 1400),
            "flags": "SYN|ACK",
            "payload": "TLS Application Data",
            "hostname": "",
        })

    return packets


def send_packets(api_base: str, packets: list) -> None:
    url = f"{api_base}/packets/"
    resp = requests.post(url, json=packets, timeout=10)
    resp.raise_for_status()
    result = resp.json()
    print(f"[+] Sent {len(packets)} packets → server accepted {result.get('packetsAdded', '?')}")


def check_vt_key(api_base: str) -> bool:
    try:
        resp = requests.get(f"{api_base}/settings/virustotal-key/status", timeout=5)
        configured = resp.json().get("configured", False)
        if configured:
            print("[+] VirusTotal API key: CONFIGURED")
        else:
            print("[!] VirusTotal API key: NOT SET — configure it in Settings or server/.env")
        return configured
    except Exception as e:
        print(f"[!] Could not check VT key status: {e}")
        return False


def poll_threats(api_base: str, wait_seconds: int) -> None:
    print(f"[*] Polling /api/threats/enhanced (waiting up to {wait_seconds}s for VT results)…")
    deadline = time.monotonic() + wait_seconds
    last_vt_count = 0

    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{api_base}/threats/enhanced", timeout=30)
            resp.raise_for_status()
            data = resp.json()
            threats = data.get("threats", [])
            vt_threats = [t for t in threats if "virustotal" in (t.get("type") or "")]

            print(f"    Total threats: {data.get('totalThreats', 0)} | "
                  f"HTTPS packets analysed: {data.get('httpsPacketsAnalyzed', 0)} | "
                  f"VT detections: {len(vt_threats)}")

            if len(vt_threats) > last_vt_count:
                last_vt_count = len(vt_threats)
                print("\n[+] VirusTotal detections:")
                for t in vt_threats:
                    vt = t.get("vtReport", {})
                    print(f"    {t['severity'].upper():8s}  {t['sourceIP']:20s}  "
                          f"malicious={vt.get('malicious', '?')}  "
                          f"suspicious={vt.get('suspicious', '?')}")
                print()

        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")

        time.sleep(5)

    print(f"[*] Done. Final VT detections found: {last_vt_count}")


def main():
    parser = argparse.ArgumentParser(description="ScoutOut VirusTotal test script")
    parser.add_argument("--api", default="http://localhost:5050/api",
                        help="ScoutOut API base URL (default: http://localhost:5050/api)")
    parser.add_argument("--wait", type=int, default=40,
                        help="Seconds to poll for results (default: 40)")
    parser.add_argument("--malicious-only", action="store_true",
                        help="Only send malicious IPs, no clean IPs")
    args = parser.parse_args()

    api = args.api.rstrip("/")
    print(f"\n=== ScoutOut VirusTotal Test ===")
    print(f"API: {api}\n")

    check_vt_key(api)

    clean = [] if args.malicious_only else CLEAN_IPS
    packets = build_packets(MALICIOUS_IPS, clean)

    print(f"[*] Sending {len(packets)} HTTPS packets "
          f"({len(MALICIOUS_IPS)} malicious IPs, {len(clean)} clean IPs)…")
    send_packets(api, packets)

    poll_threats(api, wait_seconds=args.wait)


if __name__ == "__main__":
    main()
