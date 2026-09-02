"""
Threat Intelligence Agent - the agentic layer over the hybrid search engine.

Rather than firing a single fixed query per event, this agent runs a
small perceive -> plan -> act -> observe loop:
  1. Extract candidate indicators from the raw event text (exact CVE/ATT&CK
     IDs are tried first, since they are the most reliable signal).
  2. Query the hybrid search engine once per indicator.
  3. If the best result so far is weak, broaden the query and retry
     (strip punctuation, fall back to bare keywords).
  4. Aggregate, deduplicate, and rank all results before returning.

The reasoning trace is kept on self.last_trace so the querying process is
auditable - useful for debugging and for showing *why* a given piece of
threat intel got attached to an alert.

Production upgrade path: replace _plan_queries() with an LLM call that
reasons about the event and proposes queries. The rest of the loop
(act/observe/aggregate) is unchanged - the same "clean interface
contract" principle used everywhere else in this project.
"""

import re

from src.rag_engine.hybrid_search import HybridSearchEngine

WEAK_RESULT_THRESHOLD = 0.4

_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b|\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class ThreatIntelAgent:
    def __init__(self, corpus: list, top_k: int = 3):
        self.engine = HybridSearchEngine(corpus)
        self.top_k = top_k
        self.last_trace = []

    def _plan_queries(self, primary_query: str) -> list:
        """Decide which queries to run. Exact IDs found in the text are
        tried first since they are the strongest possible signal."""
        queries = list(_ID_PATTERN.findall(primary_query))
        queries.append(primary_query)
        return queries

    def investigate(self, primary_query: str) -> list:
        """Run the perceive -> plan -> act -> observe loop for one event
        and return the aggregated, deduplicated, ranked hits."""
        self.last_trace = []
        queries = self._plan_queries(primary_query)

        all_hits = {}
        for q in queries:
            hits = self.engine.search(q, top_k=self.top_k)
            self.last_trace.append({
                "query": q,
                "n_results": len(hits),
                "top_score": hits[0].score if hits else 0.0,
            })
            for h in hits:
                if h.id not in all_hits or h.score > all_hits[h.id].score:
                    all_hits[h.id] = h

        best_score = max((h.score for h in all_hits.values()), default=0.0)
        if best_score < WEAK_RESULT_THRESHOLD and len(queries) == 1:
            broadened = re.sub(r"[^\w\s]", " ", primary_query)
            hits = self.engine.search(broadened, top_k=self.top_k)
            self.last_trace.append({
                "query": broadened,
                "n_results": len(hits),
                "top_score": hits[0].score if hits else 0.0,
                "broadened": True,
            })
            for h in hits:
                if h.id not in all_hits or h.score > all_hits[h.id].score:
                    all_hits[h.id] = h

        ranked = sorted(all_hits.values(), key=lambda h: h.score, reverse=True)
        return ranked[: self.top_k]
