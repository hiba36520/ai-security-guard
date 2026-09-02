import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.rag_engine.corpus import THREAT_INTEL_CORPUS
from src.rag_engine.hybrid_search import HybridSearchEngine


def test_corpus_loaded():
    assert len(THREAT_INTEL_CORPUS) > 0
    assert any(e["source"] == "CVE" for e in THREAT_INTEL_CORPUS)
    assert any(e["source"] == "MITRE_ATTACK" for e in THREAT_INTEL_CORPUS)


def test_exact_id_match_ranks_first():
    engine = HybridSearchEngine(THREAT_INTEL_CORPUS)
    hits = engine.search("CVE-2021-44228", top_k=3)
    assert len(hits) > 0
    assert hits[0].id == "CVE-2021-44228"


def test_semantic_match_without_shared_keywords():
    engine = HybridSearchEngine(THREAT_INTEL_CORPUS)
    hits = engine.search("attacker reading server memory via TLS bug", top_k=3)
    ids = [h.id for h in hits]
    assert "CVE-2014-0160" in ids  # Heartbleed


def test_no_matches_returns_empty_list():
    engine = HybridSearchEngine(THREAT_INTEL_CORPUS)
    hits = engine.search("zzz qqq unrelated nonsense xyz", top_k=3)
    assert isinstance(hits, list)
