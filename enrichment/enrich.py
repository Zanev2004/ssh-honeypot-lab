import json
import os
import csv
import argparse
from pathlib import Path
from collections import defaultdict
import requests
from ipwhois import IPWhois
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

def get_unique_ips(log_dir):
    ip_counts = defaultdict(int)
    log_path = Path(log_dir)
    for log_file in log_path.glob("cowrie.json*"):
        with open(log_file, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ip = entry.get("src_ip")
                    if ip:
                        ip_counts[ip] += 1
                except json.JSONDecodeError:
                    continue
    return ip_counts

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "asn": result.get("asn", "unknown"),
            "org": result.get("asn_description", "unknown"),
            "country": result.get("asn_country_code", "unknown")
        }
    except Exception:
        return {"asn": "unknown", "org": "unknown", "country": "unknown"}

def get_abuse_info(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "usage_type": data.get("usageType", "unknown")
        }
    except Exception:
        return {"abuse_score": 0, "total_reports": 0, "usage_type": "unknown"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", required=True, help="Path to Cowrie JSON log directory")
    parser.add_argument("--output", default="results.csv", help="Output CSV file")
    args = parser.parse_args()

    print("Reading logs...")
    ip_counts = get_unique_ips(args.logs)
    print(f"Found {len(ip_counts)} unique IPs")

    results = []
    for i, (ip, count) in enumerate(ip_counts.items()):
        print(f"[{i+1}/{len(ip_counts)}] Enriching {ip}...")
        asn_info = get_asn_info(ip)
        abuse_info = get_abuse_info(ip)
        results.append({
            "ip": ip,
            "attack_count": count,
            "country": asn_info["country"],
            "asn": asn_info["asn"],
            "org": asn_info["org"],
            "abuse_score": abuse_info["abuse_score"],
            "total_reports": abuse_info["total_reports"],
            "usage_type": abuse_info["usage_type"]
        })

    results.sort(key=lambda x: x["attack_count"], reverse=True)

    output_path = Path(args.output)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to {output_path}")
    print("\nTop 10 ASNs by attack count:")
    asn_totals = defaultdict(int)
    for r in results:
        asn_totals[f"{r['asn']} ({r['org']})"] += r["attack_count"]
    for asn, count in sorted(asn_totals.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {asn}: {count} attempts")

if __name__ == "__main__":
    main()