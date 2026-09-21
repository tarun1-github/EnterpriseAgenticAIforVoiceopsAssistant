"""Abstract retriever interface and in-memory implementation for CUCM domain knowledge."""

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.knowledge.loader import KnowledgeLoader
from app.knowledge.models import KnowledgeItem


class BaseKnowledgeRetriever(ABC):
    """Abstract interface for knowledge retrieval (RAG).

    Allows seamless swapping between in-memory keyword matching and vector stores (Chroma, FAISS, etc.).
    """

    @abstractmethod
    def search_knowledge(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
    ) -> List[KnowledgeItem]:
        """Search knowledge items relevant to the given query string and filters."""
        pass


class InMemoryKnowledgeRetriever(BaseKnowledgeRetriever):
    """In-memory multi-field keyword and relevance scoring retriever."""

    def __init__(self, loader: Optional[KnowledgeLoader] = None):
        self.loader = loader or KnowledgeLoader()
        self._items: List[KnowledgeItem] = []
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        if not self._items:
            self._items = self.loader.load_all()

    def reload(self) -> None:
        """Reload knowledge items from source files."""
        self._items = self.loader.load_all(force_reload=True)

    def search_knowledge(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
    ) -> List[KnowledgeItem]:
        """Search knowledge items with token scoring and category/confidence filtering."""
        self._ensure_loaded()
        if not query.strip():
            return self._items[:top_k]

        filters = filters or {}
        cat_filter = filters.get("category")
        conf_filter = filters.get("confidence")

        # Extract search tokens
        tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]
        if not tokens:
            return self._items[:top_k]

        scored_items = []
        for item in self._items:
            # Apply filters
            if cat_filter and item.category.lower() != str(cat_filter).lower():
                continue
            if conf_filter and item.confidence.lower() != str(conf_filter).lower():
                continue

            score = 0.0
            title_low = item.title.lower()
            desc_low = item.description.lower()
            tags_low = [t.lower() for t in item.tags]
            details_str = str(item.details).lower()

            for tok in tokens:
                if tok in title_low:
                    score += 5.0
                if any(tok in t for t in tags_low):
                    score += 3.0
                if tok in desc_low:
                    score += 2.0
                if tok in details_str:
                    score += 1.0

            if score > 0:
                scored_items.append((score, item))

        # Sort descending by score
        scored_items.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored_items[:top_k]]
