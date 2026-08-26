"""
Demo/smoke test for the Agentic RAG Threat Intelligence hybrid search engine.

Usage:
    python src/rag_engine/demo.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.rag_engine.corpus import THREAT_INTEL_CORPUS
from src.rag_engine.hybrid_search import HybridSearchEngine

TEST_QUERIES = [
    "CVE-2021-44228",
    "log4j remote code execution",
    "attacker reading server memory via TLS bug",
    "ransomware worm spreading via SMB",
    "large volume of traffic overwhelming a server",
    "lateral movement using stolen credentials",
]


def main():
    engine = HybridSearchEngine(THREAT_INTEL_CORPUS)

    for query in TEST_QUERIES:
        print("=" * 70)
        print(f"QUERY: {query}")
        print("=" * 70)
        hits = engine.search(query, top_k=3)
        if not hits:
            print("  (no matches)")
        for hit in hits:
            print(f"  [{hit.source}] {hit.id}  (score: {hit.score})")
            print(f"      {hit.text[:100]}...")
        print()


if __name__ == "__main__":
    main()
