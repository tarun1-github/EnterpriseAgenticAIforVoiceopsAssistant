"""Unit tests for KnowledgeLoader and InMemoryKnowledgeRetriever."""

import pytest

from app.knowledge.loader import KnowledgeLoader
from app.knowledge.retriever import InMemoryKnowledgeRetriever


def test_knowledge_loader_reads_yaml():
    loader = KnowledgeLoader()
    items = loader.load_all(force_reload=True)
    assert len(items) > 0

    item_ids = {item.id for item in items}
    assert "signal_CcSetupReq" in item_ids
    assert "proc_Cdcc" in item_ids
    assert "ident_CI" in item_ids
    assert "fail_SIP_503_SERVICE_UNAVAILABLE" in item_ids


def test_retriever_search_signal():
    retriever = InMemoryKnowledgeRetriever()
    results = retriever.search_knowledge("CcSetupReq", top_k=3)

    assert len(results) >= 1
    assert results[0].id == "signal_CcSetupReq"
    assert results[0].category == "signal"
    assert "Cdcc" in results[0].details["related_processes"]


def test_retriever_search_failure():
    retriever = InMemoryKnowledgeRetriever()
    results = retriever.search_knowledge("503 Service Unavailable", top_k=3)

    assert len(results) >= 1
    top = results[0]
    assert top.category == "failure"
    assert "SIP_503" in top.id
    assert any("bandwidth" in str(c).lower() or "unreachable" in str(c).lower() for c in top.details.get("possible_causes", []))


def test_retriever_category_filter():
    retriever = InMemoryKnowledgeRetriever()
    # Search for "SIP" with filter category="signal"
    sig_results = retriever.search_knowledge("SIP", filters={"category": "signal"}, top_k=5)
    for res in sig_results:
        assert res.category == "signal"
