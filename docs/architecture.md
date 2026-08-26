# AI Security Guard — Architecture & MVP Plan

**Concept:** Guardrail Defense Agent + Agentic RAG Threat Intelligence Engine
**Status:** Approved by Dr. Goran Pavlović — data foundation upgraded NSL-KDD → CICIDS2017
**Owner:** Hiba Skandrani

---

## 1. System Overview

Three components, connected by structured JSON contracts, no tight coupling:

```
                    ┌─────────────────────────┐
   LLM Input/Output │  Guardrail Defense Agent │──── DetectionEvent ────┐
   (prompts, tool    │  - prompt injection      │                        │
    calls, outputs)  │  - data exfiltration     │                        ▼
                    │  - unauthorized API calls│              ┌──────────────────┐
                    └─────────────────────────┘              │  Orchestrator /   │
                                                                │  Correlation Layer│
   Network traffic   ┌─────────────────────────┐              │                    │
   (CICIDS2017-      │  Anomaly Classifier      │── Anomaly ──▶│  - merges signals  │
    trained model)   │  (XGBoost, Phase 1)      │   Event      │  - dedups          │
                    └─────────────────────────┘              │  - severity score  │
                                                                └────────┬───────────┘
                                                                         │ ThreatIntelQuery
                                                                         ▼
                                                                ┌──────────────────┐
                                                                │ Agentic RAG       │
                                                                │ Threat Intel      │
                                                                │ - CVE / MITRE     │
                                                                │   ATT&CK corpus   │
                                                                │ - hybrid search   │
                                                                │   (BM25 + dense)  │
                                                                └────────┬───────────┘
                                                                         │ ThreatIntelResult
                                                                         ▼
                                                                ┌──────────────────┐
                                                                │  Incident Alert   │
                                                                │  (enriched, with  │
                                                                │  ATT&CK mapping)  │
                                                                └──────────────────┘
```

Two independent detection sources (LLM guardrail + network anomaly classifier) feed a shared orchestrator, which queries the RAG engine to enrich raw detections with threat intel context before alerting. This is what makes it "one ecosystem" rather than two side projects glued together.

---

## 2. Components

### 2.1 Data Foundation — CICIDS2017 Anomaly Classifier (Phase 1)
- **Model:** XGBoost (already chosen — keep it, it's the right call for tabular flow data)
- **Known dataset issues to handle in preprocessing** (per Dr. Pavlović's note):
  - Class imbalance (benign traffic vastly outweighs attack classes, and attack classes are themselves imbalanced — e.g. DDoS >> Heartbleed)
  - Infinite values in `Flow Bytes/s` and `Flow Packets/s` (division-by-zero artifacts in the original CICFlowMeter export)
  - Missing values scattered across several flow-duration-derived columns
  - Leading/trailing whitespace in column names (classic CICIDS2017 quirk — breaks naive column selection)
- See `src/preprocess_cicids2017.py` — implemented below.

### 2.2 Guardrail Defense Agent (Phase 2)
- Wraps LLM calls (input + output) and tool-call events
- Detects: prompt injection patterns, data exfiltration attempts (e.g. base64 blobs, credential-shaped strings in output), unauthorized/out-of-policy API calls
- MVP approach: start with rule-based + embedding-similarity detectors (fast, explainable, no training data needed), layer in the QLoRA-fine-tuned LLM Guard classifier from your Phase 2 plan once you have labeled examples
- Emits a `DetectionEvent` (schema below) — does **not** decide severity or alert on its own; that's the orchestrator's job

### 2.3 Agentic RAG Threat Intelligence Engine
- **Corpus:** CVE feed (NVD) + MITRE ATT&CK technique/tactic data
- **Retrieval:** hybrid search — BM25/keyword (critical for exact CVE-ID and technique-ID matching, e.g. `CVE-2024-3094`, `T1059.001`) combined with dense embeddings for semantic similarity on free-text descriptions
- **Agent loop:** given a `DetectionEvent` or `AnomalyEvent`, the agent (a) extracts candidate indicators (ports, protocols, payload patterns), (b) queries the hybrid index, (c) ranks/filters results, (d) returns a structured `ThreatIntelResult` with ATT&CK technique mapping and confidence
- If you want to reuse infra from the customer-support RAG project: same Qdrant + hybrid search pattern applies here, just a different corpus and a different downstream consumer (agent, not chat)

### 2.4 Orchestrator / Correlation Layer
- Receives events from both detectors
- Deduplicates, scores severity, decides whether to query the RAG engine
- Produces the final enriched `IncidentAlert`

---

## 3. JSON Schema Contracts

Keeping these stable is what lets you swap the classifier or the LLM backend later without touching the other components.

```json
// DetectionEvent — emitted by Guardrail Agent
{
  "event_id": "uuid",
  "source": "guardrail_agent",
  "timestamp": "ISO8601",
  "detection_type": "prompt_injection | data_exfiltration | unauthorized_api_call",
  "confidence": 0.0,
  "raw_input_excerpt": "string, truncated/redacted",
  "raw_output_excerpt": "string, truncated/redacted",
  "metadata": { "model": "string", "session_id": "string" }
}

// AnomalyEvent — emitted by CICIDS2017 classifier
{
  "event_id": "uuid",
  "source": "network_classifier",
  "timestamp": "ISO8601",
  "predicted_class": "string (e.g. DDoS, PortScan, BENIGN)",
  "confidence": 0.0,
  "flow_features": { "src_ip": "string", "dst_ip": "string", "dst_port": 0 }
}

// ThreatIntelQuery — orchestrator → RAG engine
{
  "query_id": "uuid",
  "triggering_event_id": "uuid",
  "indicators": ["string"],
  "context_type": "network | llm_behavior"
}

// ThreatIntelResult — RAG engine → orchestrator
{
  "query_id": "uuid",
  "matches": [
    {
      "source": "CVE | MITRE_ATTACK",
      "id": "string (e.g. CVE-2024-3094, T1059.001)",
      "relevance_score": 0.0,
      "summary": "string"
    }
  ]
}

// IncidentAlert — final output
{
  "alert_id": "uuid",
  "severity": "low | medium | high | critical",
  "events": ["event_id", "..."],
  "threat_intel": ["ThreatIntelResult", "..."],
  "recommended_action": "string"
}
```

---

## 4. MVP Build Order

1. **CICIDS2017 preprocessing pipeline** (script provided — start here, everything else depends on clean data)
2. XGBoost classifier trained on cleaned data, wrapped to emit `AnomalyEvent`
3. Guardrail Agent — rule-based v1, emits `DetectionEvent`
4. Threat intel corpus ingestion (CVE + MITRE ATT&CK) into Qdrant, hybrid search wired up
5. Orchestrator that ties 2+3 → 4 → `IncidentAlert`
6. Simple dashboard/log output for alerts (defer a full UI until the pipeline works end-to-end)

Don't build all four components in parallel — get one detection source flowing all the way through to an alert first (recommend: network classifier, since Phase 1 is furthest along), then add the Guardrail Agent as a second event source into the same orchestrator.
