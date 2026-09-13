from research_agent.collection_models import Investigation, parse_json, prompt

def investigate_candidate(candidate, behavior, client):
    result = client.generate_grounded(prompt("evidence_investigator", {"behavior": behavior, "candidate": candidate.model_dump(), "output_schema": Investigation.model_json_schema()}))
    investigation = Investigation.model_validate(parse_json(result.text))
    ids = [c.claim_id for c in investigation.claims]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate claim IDs")
    return investigation, result
