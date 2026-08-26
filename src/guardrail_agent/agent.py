"""
Guardrail Defense Agent (MVP v1).

Rule-based + TF-IDF semantic-similarity detection - deliberately avoids
heavy dependencies (e.g. sentence-transformers/torch) so it stays fast and
easy to install. Emits DetectionEvent objects matching the schema shared
with the rest of the system (see src/schemas/events.py).
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.guardrail_agent.patterns import (
    ALLOWED_API_CALLS,
    EXFILTRATION_PATTERNS,
    KNOWN_INJECTION_EXAMPLES,
    PROMPT_INJECTION_PATTERNS,
)
from src.schemas.events import DetectionEvent, DetectionType


class GuardrailAgent:
    def __init__(self, similarity_threshold: float = 0.35):
        self.similarity_threshold = similarity_threshold
        self._injection_regexes = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]
        self._exfil_regexes = [re.compile(p) for p in EXFILTRATION_PATTERNS]

        self._vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2)).fit(KNOWN_INJECTION_EXAMPLES)
        self._known_vectors = self._vectorizer.transform(KNOWN_INJECTION_EXAMPLES)

    def _regex_hit(self, text: str, regexes) -> bool:
        return any(r.search(text) for r in regexes)

    def _semantic_injection_score(self, text: str) -> float:
        vec = self._vectorizer.transform([text])
        sims = cosine_similarity(vec, self._known_vectors)
        return float(sims.max())

    def scan_input(self, text: str, session_id: str = None) -> list:
        """Scan an incoming prompt for injection attempts."""
        events = []

        rule_hit = self._regex_hit(text, self._injection_regexes)
        sim_score = self._semantic_injection_score(text)
        sim_hit = sim_score >= self.similarity_threshold

        if rule_hit or sim_hit:
            confidence = 0.95 if rule_hit else min(0.5 + sim_score, 0.9)
            events.append(DetectionEvent(
                detection_type=DetectionType.PROMPT_INJECTION,
                confidence=confidence,
                raw_input_excerpt=text[:200],
                session_id=session_id,
            ))
        return events

    def scan_output(self, text: str, session_id: str = None) -> list:
        """Scan an outgoing LLM response for data exfiltration signals."""
        events = []
        if self._regex_hit(text, self._exfil_regexes):
            events.append(DetectionEvent(
                detection_type=DetectionType.DATA_EXFILTRATION,
                confidence=0.85,
                raw_output_excerpt=text[:200],
                session_id=session_id,
            ))
        return events

    def check_api_call(self, api_name: str, session_id: str = None) -> list:
        """Check a requested tool/API call against the allowlist."""
        events = []
        if api_name not in ALLOWED_API_CALLS:
            events.append(DetectionEvent(
                detection_type=DetectionType.UNAUTHORIZED_API_CALL,
                confidence=1.0,
                raw_input_excerpt=f"Requested API: {api_name}",
                session_id=session_id,
            ))
        return events
