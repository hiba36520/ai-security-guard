"""
Contrats de données entre les composants du système :
Guardrail Agent -> Orchestrateur -> RAG Threat Intel -> Alerte

Garder ces schémas stables permet de remplacer/faire évoluer n'importe quel
composant (classifieur, LLM backend, moteur de recherche) sans casser les
autres — c'est le point que Dr. Pavlović a souligné.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class DetectionType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_API_CALL = "unauthorized_api_call"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContextType(str, Enum):
    NETWORK = "network"
    LLM_BEHAVIOR = "llm_behavior"


class DetectionEvent(BaseModel):
    """Émis par le Guardrail Defense Agent."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = "guardrail_agent"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_type: DetectionType
    confidence: float = Field(ge=0.0, le=1.0)
    raw_input_excerpt: Optional[str] = None
    raw_output_excerpt: Optional[str] = None
    model: Optional[str] = None
    session_id: Optional[str] = None


class AnomalyEvent(BaseModel):
    """Émis par le classifieur CICIDS2017 (XGBoost)."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = "network_classifier"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    predicted_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class ThreatIntelQuery(BaseModel):
    """Envoyé par l'orchestrateur vers le moteur RAG."""

    query_id: str = Field(default_factory=lambda: str(uuid4()))
    triggering_event_id: str
    indicators: list[str]
    context_type: ContextType


class ThreatIntelMatch(BaseModel):
    source: str  # "CVE" | "MITRE_ATTACK"
    id: str  # ex: "CVE-2024-3094", "T1059.001"
    relevance_score: float = Field(ge=0.0, le=1.0)
    summary: str


class ThreatIntelResult(BaseModel):
    """Retourné par le moteur RAG vers l'orchestrateur."""

    query_id: str
    matches: list[ThreatIntelMatch] = Field(default_factory=list)


class IncidentAlert(BaseModel):
    """Sortie finale du système."""

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Severity
    event_ids: list[str]
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    recommended_action: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
