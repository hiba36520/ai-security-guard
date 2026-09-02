"""
Threat Intelligence ingestion pipeline.

This is the production-grade counterpart to the static data/threat_intel/
JSON files used by the MVP: instead of a fixed snapshot, it pulls current
data directly from the two official sources referenced in architecture.md.

  - MITRE ATT&CK: pulled from the official STIX bundle published on GitHub
    by the MITRE ATT&CK team. No API key required.
  - CVE: pulled from the NVD REST API v2.0. NVD rate-limits unauthenticated
    requests to 5 requests / 30s — for anything beyond occasional manual
    refreshes, request a free API key from nvd.nist.gov and pass it via
    the NVD_API_KEY environment variable to raise that limit.

Usage:
    python src/rag_engine/ingest.py --mitre --cve-keyword "remote code execution" --cve-limit 20
    python src/rag_engine/ingest.py --mitre-only   # refresh only the ATT&CK data
"""

import argparse
import json
import os
import time

import requests

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "threat_intel")


def fetch_mitre_attack(top_level_only: bool = True) -> list:
    """Download and parse the official MITRE ATT&CK Enterprise STIX bundle."""
    print("Fetching MITRE ATT&CK STIX bundle...")
    resp = requests.get(MITRE_ATTACK_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    techniques = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if not attack_id:
            continue
        if top_level_only and "." in attack_id:
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "").split("\n")[0].replace("\r", " ").strip()
        if len(desc) > 280:
            desc = desc[:277] + "..."

        techniques.append({"id": attack_id, "source": "MITRE_ATTACK", "text": f"{name}: {desc}"})

    print(f"  -> {len(techniques)} techniques extracted")
    return techniques


def fetch_cves(keyword: str = None, limit: int = 20) -> list:
    """
    Query the NVD REST API v2.0 for CVEs, optionally filtered by keyword.

    Respects NVD's unauthenticated rate limit (5 req / 30s) with a small
    delay; set NVD_API_KEY to raise the limit for larger pulls.
    """
    print(f"Fetching CVEs from NVD (keyword={keyword!r}, limit={limit})...")
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {"resultsPerPage": min(limit, 2000)}
    if keyword:
        params["keywordSearch"] = keyword

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        text = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
        if not cve_id or not text:
            continue
        cves.append({"id": cve_id, "source": "CVE", "text": text})

    print(f"  -> {len(cves)} CVEs fetched")
    if not api_key:
        time.sleep(6)  # stay under the unauthenticated rate limit on repeated calls
    return cves


def main():
    parser = argparse.ArgumentParser(description="Refresh the Threat Intel corpus from live sources")
    parser.add_argument("--mitre", action="store_true", help="Refresh MITRE ATT&CK data")
    parser.add_argument("--mitre-only", action="store_true", help="Refresh only MITRE ATT&CK data")
    parser.add_argument("--cve-keyword", type=str, default=None, help="Keyword to filter CVE search")
    parser.add_argument("--cve-limit", type=int, default=20, help="Max number of CVEs to fetch")
    args = parser.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)

    if args.mitre or args.mitre_only:
        techniques = fetch_mitre_attack()
        with open(os.path.join(DATA_DIR, "mitre_attack.json"), "w", encoding="utf-8") as f:
            json.dump(techniques, f, indent=2)
        print(f"Wrote {DATA_DIR}/mitre_attack.json")

    if not args.mitre_only:
        cves = fetch_cves(keyword=args.cve_keyword, limit=args.cve_limit)
        if cves:
            with open(os.path.join(DATA_DIR, "cve_data.json"), "w", encoding="utf-8") as f:
                json.dump(cves, f, indent=2)
            print(f"Wrote {DATA_DIR}/cve_data.json")


if __name__ == "__main__":
    main()
