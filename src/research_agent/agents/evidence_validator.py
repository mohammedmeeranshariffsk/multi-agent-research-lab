import re
from research_agent.collection_models import Validation, parse_json, prompt

def parse_validation(text):
    # Require an unambiguous final decision marker as well as valid JSON.
    match = re.search(r"\nDATASET_DECISION: (ACCEPT|REJECT)\s*$", text)
    if not match:
        raise ValueError("missing final DATASET_DECISION")
    result = Validation.model_validate(parse_json(text[:match.start()]))
    if result.dataset_decision != match.group(1):
        raise ValueError("conflicting decisions")
    ids = [a.claim_id for a in result.assessments]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate assessments")
    return result

def validate_evidence(candidate, behavior, investigation, client):
    result = client.generate_grounded(prompt("evidence_validator", {"behavior": behavior, "candidate": candidate.model_dump(), "investigation": investigation.model_dump(), "output_schema": Validation.model_json_schema()}))
    return parse_validation(result.text), result
