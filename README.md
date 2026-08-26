# AI Security Guard

Système multi-agents de sécurité combinant :
- **Détection d'anomalies réseau** (XGBoost entraîné sur CICIDS2017)
- **Guardrail Defense Agent** (détection prompt injection, exfiltration de données, appels API non autorisés)
- **Agentic RAG Threat Intelligence** (enrichissement des alertes via CVE + MITRE ATT&CK, hybrid search)

Architecture complète et contrats de données : voir [`docs/architecture.md`](docs/architecture.md).

> Projet réalisé dans le cadre du suivi académique avec Dr. Goran Pavlović, ciblant le marché AI/cybersécurité en Allemagne.

## Structure du repo

```
ai-security-guard/
├── docs/
│   └── architecture.md          # design complet, diagramme, schémas JSON
├── src/
│   ├── classifier/               # Phase 1-2 : preprocessing + XGBoost
│   │   ├── preprocess_cicids2017.py
│   │   └── train_xgboost_cicids2017.py
│   ├── guardrail_agent/          # Phase 3 : à implémenter
│   ├── rag_engine/               # Phase 4 : à implémenter
│   ├── orchestrator/             # Phase 5 : à implémenter
│   └── schemas/
│       └── events.py             # contrats Pydantic entre tous les composants
├── data/
│   ├── raw/                      # CSV CICIDS2017 (non versionnés — voir .gitignore)
│   └── processed/                # sorties du preprocessing
├── model_artifacts/               # modèle entraîné + évaluation (non versionné)
├── tests/
├── requirements.txt
└── .gitignore
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation — Phase 1 : Preprocessing

Place les 8 CSV CICIDS2017 dans `data/raw/`, puis :

```bash
python3 src/classifier/preprocess_cicids2017.py \
    --input-dir data/raw \
    --output-dir data/processed
```

## Utilisation — Phase 2 : Entraînement

```bash
python3 src/classifier/train_xgboost_cicids2017.py \
    --data-dir data/processed \
    --output-dir model_artifacts
```

## Roadmap

- [x] Architecture définie et validée (Dr. Pavlović)
- [x] Pipeline de preprocessing CICIDS2017
- [x] Script d'entraînement XGBoost + évaluation SHAP
- [x] Contrats de données (schémas Pydantic)
- [ ] Guardrail Defense Agent (v1 règles + embeddings)
- [ ] Corpus Threat Intel (CVE + MITRE ATT&CK) + Qdrant hybrid search
- [ ] Orchestrateur / couche de corrélation
- [ ] Intégration bout-en-bout + alerting
- [ ] Documentation + présentation finale

## License

MIT
