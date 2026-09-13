from research_agent.collection_models import SampleCandidate, SampleSource
from research_agent.sample_normalizer import normalize_candidates

def c(**kwargs):
    return SampleCandidate(**kwargs)

def src(url, **kwargs):
    return SampleSource(sample_page_url=url, useful_for_manual_acquisition=True, evidence_scope="HASH_LEVEL", **kwargs)

def test_same_hash_merges_sources_and_status():
    out = normalize_candidates([c(sha256="A"*64, family="X", location_status="PARTIAL", sources=[src("https://bazaar.abuse.ch/a")]), c(sha256="a"*64, sources=[src("https://any.run/task/1")], location_status="VERIFIED")])
    assert len(out) == 1 and len(out[0].sources) == 2 and out[0].location_status == "VERIFIED" and out[0].identifier_strength == "SHA256"

def test_package_merges_without_conflicting_hash():
    assert len(normalize_candidates([c(package_name="com.example.test"), c(package_name="COM.EXAMPLE.TEST", app_name="App")])) == 1

def test_conflicting_hashes_and_family_only_do_not_merge():
    assert len(normalize_candidates([c(family="TrickMo", sha256="A"*64), c(family="TrickMo", sha256="B"*64)])) == 2
    assert len(normalize_candidates([c(family="TrickMo"), c(family="TrickMo")])) == 2

def test_duplicate_url_normalized_once_and_multi_provider():
    out = normalize_candidates([c(sha256="A"*64, sources=[src("HTTPS://BAZAAR.ABUSE.CH/a/")]), c(sha256="A"*64, sources=[src("https://bazaar.abuse.ch/a"), src("https://hybrid-analysis.com/sample/1")])])
    assert len(out) == 1 and len(out[0].sources) == 2

def test_identifier_priority():
    assert normalize_candidates([c(family="F", variant="1", app_name="A", package_name="p", sha256="A"*64)])[0].identifier_strength == "SHA256"
