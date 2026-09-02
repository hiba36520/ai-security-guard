# AI Security Guard

Système multi-agents de sécurité combinant :
- **Détection d'anomalies réseau** (XGBoost entraîné sur CICIDS2017)
- **Guardrail Defense Agent** (détection prompt injection, exfiltration de données, appels API non autorisés)
- **Agentic RAG Threat Intelligence** (enrichissement des alertes via CVE + MITRE ATT&CK réels, hybrid search, boucle de raisonnement multi-requêtes)
- **Orchestrateur** (corrélation des événements, scoring de sévérité, alertes enrichies)

Architecture complète et contrats de données : voir [`docs/architecture.md`](docs/architecture.md).

> Projet réalisé dans le cadre du suivi académique avec Dr. Goran Pavlović, ciblant le marché AI/cybersécurité en Allemagne.

## Structure du repo

```
ai-security-guard/
├── docs/
│   └── architecture.md          # design complet, diagramme, schémas JSON
├── src/
│   ├── classifier/               # preprocessing + XGBoost
│   │   ├── preprocess_cicids2017.py
│   │   └── train_xgboost_cicids2017.py
│   ├── guardrail_agent/          # détection règles + TF-IDF
│   │   ├── agent.py
│   │   ├── patterns.py
│   │   └── demo.py
│   ├── rag_engine/                # RAG hybride + agent de raisonnement
│   │   ├── corpus.py              # charge data/threat_intel/*.json
│   │   ├── hybrid_search.py       # BM25 + TF-IDF/SVD
│   │   ├── agent.py               # boucle perceive->plan->act->observe
│   │   ├── ingest.py              # pipeline d'ingestion réelle (NVD + MITRE STIX)
│   │   └── demo.py
│   ├── orchestrator/
│   │   ├── orchestrator.py        # corrélation + scoring de sévérité
│   │   └── demo.py
│   └── schemas/
│       └── events.py              # contrats Pydantic entre tous les composants
├── data/
│   ├── raw/                       # CSV CICIDS2017 (non versionnés)
│   ├── processed/                 # sorties du preprocessing (non versionné)
│   └── threat_intel/
│       ├── mitre_attack.json      # 222 techniques réelles (source officielle MITRE)
│       └── cve_data.json          # 20 CVE réels, curés manuellement
├── model_artifacts/                # modèle entraîné + évaluation (non versionné)
├── tests/                          # suite pytest
├── requirements.txt
└── .gitignore
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation

```bash
# Preprocessing (place les 8 CSV CICIDS2017 dans data/raw/ d'abord)
python3 src/classifier/preprocess_cicids2017.py --input-dir data/raw --output-dir data/processed

# Entraînement XGBoost
python3 src/classifier/train_xgboost_cicids2017.py --data-dir data/processed --output-dir model_artifacts

# Démos individuelles
python3 src/guardrail_agent/demo.py
python3 src/rag_engine/demo.py
python3 src/orchestrator/demo.py

# Rafraîchir les données Threat Intel depuis les sources réelles
python3 src/rag_engine/ingest.py --mitre --cve-keyword "remote code execution" --cve-limit 20

# Tests
pytest tests/ -v
```

## Limites connues

Ce projet est un MVP fonctionnel bout en bout, pas un système de production. Limites assumées :

- **Guardrail Agent contournable.** La détection repose sur des règles regex + similarité TF-IDF, pas sur un modèle sémantique entraîné. Une reformulation habile d'une injection peut passer inaperçue. Une v2 utiliserait un classifieur fine-tuné (ex. LLM Guard via QLoRA) sur un jeu de données d'attaques réelles.
- **Corpus CVE statique.** Les 20 CVE dans `data/threat_intel/cve_data.json` sont une sélection manuelle figée, pas un flux live de la NVD. Le script `ingest.py` montre le vrai pattern de production (appel à l'API NVD), mais n'est pas exécuté automatiquement/périodiquement.
- **Corpus MITRE ATT&CK réel mais figé.** Les 222 techniques viennent de la source officielle (STIX bundle GitHub) — c'est un vrai instantané, mais pas rafraîchi automatiquement.
- **Agent RAG heuristique, pas basé sur un LLM.** La boucle "perceive → plan → act → observe" (`src/rag_engine/agent.py`) décide des requêtes à lancer par des règles (extraction d'ID, seuil de confiance), pas par un raisonnement LLM. C'est un vrai comportement multi-étapes auditable, mais pas un agent au sens agentique complet du terme.
- **Modèle XGBoost livré en version rapide** (100 arbres) pour valider le pipeline. La version complète (400 arbres + analyse SHAP) est disponible via les mêmes scripts avec les paramètres par défaut.
- **Pas de CI/CD.** Les tests s'exécutent manuellement (`pytest tests/`), pas encore intégrés dans un pipeline GitHub Actions.

## Roadmap

- [x] Architecture définie et validée (Dr. Pavlović)
- [x] Pipeline de preprocessing CICIDS2017
- [x] Script d'entraînement XGBoost + évaluation SHAP
- [x] Contrats de données (schémas Pydantic)
- [x] Guardrail Defense Agent (v1 règles + TF-IDF)
- [x] Corpus Threat Intel réel (MITRE ATT&CK officiel + CVE curés) + hybrid search BM25/sémantique
- [x] Agent de raisonnement multi-requêtes (perceive/plan/act/observe)
- [x] Orchestrateur / couche de corrélation
- [x] Intégration bout-en-bout + tests unitaires
- [x] Publication GitHub
- [ ] CI/CD (GitHub Actions)
- [ ] Guardrail Agent v2 (classifieur fine-tuné)
- [ ] Ingestion Threat Intel automatisée/planifiée

## License

MIT
