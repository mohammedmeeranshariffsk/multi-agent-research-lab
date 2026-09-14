import json
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
    request = prompt("evidence_validator", {"behavior": behavior, "candidate": candidate.model_dump(), "investigation": investigation.model_dump(), "output_schema": Validation.model_json_schema()})
    evidence = json.dumps({
        "candidate": candidate.model_dump(),
        "investigation": investigation.model_dump(),
        "sample_sources": [s.model_dump() for s in investigation.sample_sources],
        "behavior": behavior,
    }, ensure_ascii=False)
    result_text = client.analyze_evidence(request, evidence)
    # Keep the parser's existing audit/error contract without introducing search metadata.
    from research_agent.llm.gemini import GroundedResult
    result = GroundedResult(result_text, [], [])
    try:
        return parse_validation(result.text), result
    except ValueError as exc:
        exc.grounded_result = result
        raise
