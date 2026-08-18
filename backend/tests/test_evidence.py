"""Deterministic evidence shaping + baseline findings."""

import json

from pipeline import evidence as evidence_mod
from pipeline.collectors.base import RequestsCollector
from pipeline.scope import Scope


def _evidence(fetch):
    scope = Scope.from_seed("http://test.local/")
    caps = RequestsCollector(fetch=fetch).collect(scope)
    return evidence_mod.shape(caps, scope), caps


def test_shape_produces_inventories(fetch):
    ev, _ = _evidence(fetch)
    assert ev.endpoints
    assert ev.forms and ev.forms[0]["destructive"] is False or ev.forms[0]["method"] == "GET"
    assert ev.dom_sinks  # innerHTML sink in the inline script / app.js
    assert ev.secrets    # hardcoded api_key in app.js


def test_evidence_never_leaks_raw_secret(fetch):
    ev, _ = _evidence(fetch)
    assert "SUPERSECRETKEY123456" not in json.dumps(ev.to_dict())


def test_query_values_are_stripped(fetch):
    ev, _ = _evidence(fetch)
    # api endpoint keeps param names but not secret-bearing values
    joined = json.dumps(ev.endpoints)
    assert "SUPERSECRETKEY" not in joined


def test_baseline_findings_surface_secret(fetch):
    ev, _ = _evidence(fetch)
    baseline = evidence_mod.baseline_findings(ev)
    types = {f["type"] for f in baseline}
    assert "Hardcoded Secret" in types
    assert all("SUPERSECRETKEY123456" not in json.dumps(f) for f in baseline)


def test_to_chunks_are_retrievable(fetch):
    ev, _ = _evidence(fetch)
    chunks = evidence_mod.to_chunks(ev)
    assert chunks and all(c.kind == "evidence" for c in chunks)
