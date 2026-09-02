"""
Orchestrator / correlation layer.

Ties the Guardrail Agent (DetectionEvent) and the network anomaly
classifier (AnomalyEvent) together with the RAG Threat Intel engine,
producing a single enriched IncidentAlert per event. This is the
"correlation layer" from architecture.md — it owns severity scoring and
decides when threat-intel enrichment is worth the query.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.rag_engine.agent import ThreatIntelAgent
from src.rag_engine.corpus import THREAT_INTEL_CORPUS
from src.schemas.events import (
    AnomalyEvent,
    ContextType,
    DetectionEvent,
    DetectionType,
    IncidentAlert,
    Severity,
    ThreatIntelMatch,
    ThreatIntelQuery,
    ThreatIntelResult,
)

# Anomaly classes considered non-actionable (normal traffic)
BENIGN_CLASSES = {"BENIGN"}

# Map DetectionType -> a search query fed into the RAG engine
DETECTION_QUERY_MAP = {
    DetectionType.PROMPT_INJECTION: "prompt injection command and scripting interpreter abuse",
    DetectionType.DATA_EXFILTRATION: "credential leak data exfiltration",
    DetectionType.UNAUTHORIZED_API_CALL: "unauthorized command execution",
}

# Relevance score threshold below which a RAG hit is not worth attaching
MIN_RELEVANCE = 0.15


class Orchestrator:
    def __init__(self):
        self._agent = ThreatIntelAgent(THREAT_INTEL_CORPUS)

    def _query_threat_intel(self, triggering_event_id, query_text, context_type):
        query = ThreatIntelQuery(
            triggering_event_id=triggering_event_id,
            indicators=[query_text],
            context_type=context_type,
        )
        hits = self._agent.investigate(query_text)
        matches = [
            ThreatIntelMatch(source=h.source, id=h.id, relevance_score=min(h.score, 1.0), summary=h.text)
            for h in hits if h.score >= MIN_RELEVANCE
        ]
        return ThreatIntelResult(query_id=query.query_id, matches=matches)

    def _score_severity(self, confidence, threat_result):
        best_match = max((m.relevance_score for m in threat_result.matches), default=0.0)

        if confidence >= 0.9 and best_match >= 0.5:
            return Severity.CRITICAL
        if confidence >= 0.9 or best_match >= 0.5:
            return Severity.HIGH
        if confidence >= 0.6:
            return Severity.MEDIUM
        return Severity.LOW

    def handle_detection_event(self, event: DetectionEvent) -> IncidentAlert:
        query_text = DETECTION_QUERY_MAP.get(event.detection_type, event.detection_type.value)
        threat_result = self._query_threat_intel(event.event_id, query_text, ContextType.LLM_BEHAVIOR)
        severity = self._score_severity(event.confidence, threat_result)

        action = {
            DetectionType.PROMPT_INJECTION: "Block session, review input for injection patterns.",
            DetectionType.DATA_EXFILTRATION: "Redact output, rotate any leaked credentials immediately.",
            DetectionType.UNAUTHORIZED_API_CALL: "Deny the call, review agent's tool permission scope.",
        }.get(event.detection_type, "Review manually.")

        return IncidentAlert(
            severity=severity,
            event_ids=[event.event_id],
            threat_intel=[threat_result] if threat_result.matches else [],
            recommended_action=action,
        )

    def handle_anomaly_event(self, event: AnomalyEvent):
        if event.predicted_class in BENIGN_CLASSES:
            return None  # not an incident

        query_text = f"{event.predicted_class} network attack"
        threat_result = self._query_threat_intel(event.event_id, query_text, ContextType.NETWORK)
        severity = self._score_severity(event.confidence, threat_result)

        src = event.src_ip or "unknown source"
        return IncidentAlert(
            severity=severity,
            event_ids=[event.event_id],
            threat_intel=[threat_result] if threat_result.matches else [],
            recommended_action=f"Investigate {event.predicted_class} activity from {src}.",
        )
