# Android Malware Research Collection

Public Android malware metadata and behavior evidence collection. Pipeline: discovery, investigation, validation, deterministic JSON synthesis.

Configure `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_RESEARCH_MODEL`, and optionally `MAX_LLM_REQUESTS`. Run with `PYTHONPATH=src python -m research_agent.collection_orchestrator --behavior "SMS / OTP / Notification Interception" --limit 1`.

Outputs are under `data/candidates`, `data/rejected`, and manually reviewed `data/validated`. SHA256 is optional; `analyst_verified` stays false until human review. APKs are never downloaded or stored automatically.
