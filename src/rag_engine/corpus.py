"""
Threat Intelligence corpus loader (CVE + MITRE ATT&CK).

Loads from data/threat_intel/*.json:
  - mitre_attack.json: 222 real top-level MITRE ATT&CK Enterprise techniques,
    extracted from the official STIX bundle
    (https://github.com/mitre-attack/attack-stix-data). This is real,
    verifiable threat intelligence data, not synthetic examples.
  - cve_data.json: a curated set of well-documented, high-profile CVEs.
    This is a static curated snapshot, not a live feed from the NVD API —
    see ingest.py for the pattern that would replace this with a live
    pull in a production deployment.

Falls back to a small embedded starter set if the data files are missing,
so the rest of the system still runs in a fresh checkout before the data
files are fetched/generated.
"""

import json
import os

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "threat_intel")

_FALLBACK_CORPUS = [
    {
        "id": "CVE-2021-44228",
        "source": "CVE",
        "text": "Log4Shell: remote code execution vulnerability in the Apache Log4j "
                "logging library via unsafe JNDI lookups.",
    },
    {
        "id": "T1059",
        "source": "MITRE_ATTACK",
        "text": "Command and Scripting Interpreter: adversaries abuse command and "
                "script interpreters to execute commands during post-exploitation.",
    },
]


def _load_json(filename):
    path = os.path.join(_DATA_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_corpus():
    mitre = _load_json("mitre_attack.json")
    cve = _load_json("cve_data.json")

    if mitre is None and cve is None:
        return _FALLBACK_CORPUS

    corpus = []
    if cve:
        corpus.extend(cve)
    if mitre:
        corpus.extend(mitre)
    return corpus


THREAT_INTEL_CORPUS = load_corpus()

