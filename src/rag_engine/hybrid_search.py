"""
Hybrid search engine for the Agentic RAG Threat Intelligence component.

Combines:
  - BM25 (keyword/lexical matching) - critical for exact CVE-ID and
    ATT&CK-technique-ID matches (e.g. "CVE-2021-44228", "T1059.001"),
    which pure semantic similarity handles poorly.
  - TF-IDF + TruncatedSVD (a lightweight semantic/"dense" signal, i.e.
    classic Latent Semantic Analysis) - catches queries that are
    conceptually related but do not share exact vocabulary.

Note: a transformer embedding model (e.g. sentence-transformers) would
normally be used for the semantic component. This project deliberately
uses TF-IDF+SVD instead to avoid the heavy PyTorch dependency during
local development. Swapping in a transformer encoder later only requires
replacing the semantic part - the rest of the hybrid ranking is unaffected.
"""

import re
from dataclasses import dataclass

import numpy as np
from rank_bm25 import BM25Okapi
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def _tokenize(text: str) -> list:
    return re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", text.lower())


@dataclass
class SearchHit:
    id: str
    source: str
    text: str
    score: float


class HybridSearchEngine:
    def __init__(self, corpus: list, semantic_components: int = 8, bm25_weight: float = 0.5):
        self.corpus = corpus
        self.bm25_weight = bm25_weight

        tokenized = [_tokenize(entry["text"] + " " + entry["id"]) for entry in corpus]
        self._bm25 = BM25Okapi(tokenized)

        texts = [entry["text"] for entry in corpus]
        n_components = min(semantic_components, max(1, len(corpus) - 1))
        self._tfidf = TfidfVectorizer(stop_words="english")
        tfidf_matrix = self._tfidf.fit_transform(texts)
        self._svd = TruncatedSVD(n_components=n_components, random_state=42)
        self._semantic_matrix = self._svd.fit_transform(tfidf_matrix)

    def _bm25_scores(self, query: str) -> np.ndarray:
        scores = np.array(self._bm25.get_scores(_tokenize(query)))
        max_score = scores.max()
        return scores / max_score if max_score > 0 else scores

    def _semantic_scores(self, query: str) -> np.ndarray:
        query_tfidf = self._tfidf.transform([query])
        query_vec = self._svd.transform(query_tfidf)
        sims = cosine_similarity(query_vec, self._semantic_matrix)[0]
        return np.clip(sims, 0, None)

    def search(self, query: str, top_k: int = 3) -> list:
        bm25_scores = self._bm25_scores(query)
        semantic_scores = self._semantic_scores(query)

        combined = self.bm25_weight * bm25_scores + (1 - self.bm25_weight) * semantic_scores

        top_indices = np.argsort(combined)[::-1][:top_k]
        hits = []
        for idx in top_indices:
            if combined[idx] <= 0:
                continue
            entry = self.corpus[idx]
            hits.append(SearchHit(
                id=entry["id"],
                source=entry["source"],
                text=entry["text"],
                score=round(float(combined[idx]), 4),
            ))
        return hits
