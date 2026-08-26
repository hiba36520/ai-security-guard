"""
Starter Threat Intelligence corpus (CVE + MITRE ATT&CK).

This is a small curated set of well-known, stable entries for MVP
development and demoing the hybrid search engine end-to-end. In a
production version, this would be replaced/extended by an ingestion
pipeline pulling the live NVD CVE feed and the MITRE ATT&CK STIX bundle.
"""

THREAT_INTEL_CORPUS = [
    {
        "id": "CVE-2021-44228",
        "source": "CVE",
        "text": "Log4Shell: remote code execution vulnerability in the Apache Log4j "
                "logging library via unsafe JNDI lookups triggered by attacker-controlled "
                "input strings, allowing arbitrary code execution on the affected server.",
    },
    {
        "id": "CVE-2017-0144",
        "source": "CVE",
        "text": "EternalBlue: remote code execution vulnerability in Microsoft SMBv1 "
                "server due to improper handling of crafted packets, widely exploited by "
                "the WannaCry and NotPetya ransomware worms.",
    },
    {
        "id": "CVE-2014-0160",
        "source": "CVE",
        "text": "Heartbleed: out-of-bounds read vulnerability in the OpenSSL TLS "
                "heartbeat extension, allowing attackers to read sensitive memory "
                "contents including private keys and session data from the server.",
    },
    {
        "id": "CVE-2021-34527",
        "source": "CVE",
        "text": "PrintNightmare: remote code execution and privilege escalation "
                "vulnerability in the Windows Print Spooler service, exploitable via "
                "crafted print driver installation requests.",
    },
    {
        "id": "CVE-2019-0708",
        "source": "CVE",
        "text": "BlueKeep: remote code execution vulnerability in Windows Remote "
                "Desktop Services (RDP) that does not require authentication, allowing "
                "wormable exploitation across a network.",
    },
    {
        "id": "T1059",
        "source": "MITRE_ATTACK",
        "text": "Command and Scripting Interpreter: adversaries abuse command and "
                "script interpreters (PowerShell, cmd, bash, Python) to execute commands, "
                "scripts, or binaries during post-exploitation activity.",
    },
    {
        "id": "T1071",
        "source": "MITRE_ATTACK",
        "text": "Application Layer Protocol: adversaries communicate using application "
                "layer protocols (HTTP, DNS, HTTPS) to blend command-and-control traffic "
                "with legitimate network traffic and avoid detection.",
    },
    {
        "id": "T1055",
        "source": "MITRE_ATTACK",
        "text": "Process Injection: adversaries inject code into the address space of "
                "another running process to evade process-based defenses and elevate "
                "privileges.",
    },
    {
        "id": "T1003",
        "source": "MITRE_ATTACK",
        "text": "OS Credential Dumping: adversaries attempt to dump credentials from "
                "operating system memory, registry, or files to obtain account login "
                "information for lateral movement.",
    },
    {
        "id": "T1190",
        "source": "MITRE_ATTACK",
        "text": "Exploit Public-Facing Application: adversaries exploit a weakness in an "
                "internet-facing application (web server, database) to gain initial "
                "access to a network.",
    },
    {
        "id": "T1071.001",
        "source": "MITRE_ATTACK",
        "text": "Web Protocols: a sub-technique of Application Layer Protocol where "
                "adversaries specifically use HTTP or HTTPS to communicate with "
                "command-and-control infrastructure.",
    },
    {
        "id": "T1046",
        "source": "MITRE_ATTACK",
        "text": "Network Service Discovery: adversaries scan a network to gather "
                "information about running services, often as reconnaissance before "
                "exploitation (related to port scanning activity).",
    },
    {
        "id": "T1498",
        "source": "MITRE_ATTACK",
        "text": "Network Denial of Service: adversaries flood a target network or "
                "service with traffic to degrade or deny availability to legitimate "
                "users, covering volumetric DDoS attacks.",
    },
]
