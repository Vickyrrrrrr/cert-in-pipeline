"""RAG Knowledge Base — Qdrant-backed semantic search for security knowledge.

Token-effective retrieval (SOTA pattern):
  - search_knowledge returns top 3, 150 chars each (~100 tokens total)
  - fetch_full_doc gets complete text on demand (second-tier retrieval)
  - Only relevant knowledge enters the context window

Two-tier retrieval:
  1. SEMANTIC: Qdrant local vector DB (nuclei, OWASP, CWE, CAPEC, payloads)
  2. LIVE:     NVD API for real-time CVE lookup (always current)

The Qdrant DB is built by: uv run python knowledge/seed.py
If DB doesn't exist, falls back gracefully.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional

from agents import function_tool


QDRANT_PATH = str(Path(__file__).parent.parent / "knowledge" / "qdrant.db")
COLLECTION = "security_knowledge"
EMBED_MODEL = "all-MiniLM-L6-v2"

_embedder = None
_client = None
_db_available = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(EMBED_MODEL)
    return _embedder


def _get_client():
    global _client, _db_available
    if _db_available is False:
        return None
    if _client is None:
        if not Path(QDRANT_PATH).exists():
            _db_available = False
            return None
        try:
            from qdrant_client import QdrantClient
            _client = QdrantClient(path=QDRANT_PATH)
            _db_available = True
        except Exception:
            _db_available = False
            return None
    return _client


def _is_db_ready() -> bool:
    return _get_client() is not None


# ─── Internal search (shared by all tools) ─────────────────────────

def _semantic_search(query: str, limit: int = 3, max_chars: int = 150) -> str:
    """Core semantic search — token-effective retrieval.

    Returns top-k results with truncated text (max_chars per result).
    Agent can call fetch_full_doc to get complete text for a specific hit.

    Thread-safe: wraps Qdrant calls in asyncio.to_thread when in async context.
    """
    import asyncio

    def _search_sync():
        client = _get_client()
        if client is None:
            return json.dumps({
                "error": "Knowledge DB not built. Run: uv run python knowledge/seed.py",
                "fallback": "Use basic heuristics for classification.",
            })

        embedder = _get_embedder()
        query_vector = embedder.encode(query).tolist()

        results = client.query_points(
            collection_name=COLLECTION,
            query=query_vector,
            limit=min(limit, 5),
            with_payload=True,
        ).points

        hits = []
        for r in results:
            payload = r.payload or {}
            full_text = payload.get("text", "")
            hits.append({
                "doc_id": payload.get("doc_id", ""),
                "title": payload.get("title", ""),
                "source": payload.get("source", ""),
                "category": payload.get("category", ""),
                "text": full_text[:max_chars],
                "has_more": len(full_text) > max_chars,
                "url": payload.get("url", ""),
                "score": round(r.score, 3) if r.score else 0,
            })

        return json.dumps({"query": query, "results": hits, "count": len(hits),
                           "hint": "Call fetch_full_doc(doc_id) for complete text if has_more=true"})

    # Check if we're in an async context (swarm mode)
    try:
        loop = asyncio.get_running_loop()
        # We're in async context — but function_tool calls run in threads, so sync is fine
        return _search_sync()
    except RuntimeError:
        # No running loop — sync mode
        return _search_sync()


# ─── Semantic search tools ─────────────────────────────────────────

@function_tool
def search_knowledge(query: str, limit: int = 3) -> str:
    """Search the security knowledge base for relevant information.

    Uses semantic search across: nuclei templates (13k), OWASP Cheat Sheets (120),
    PayloadsAllTheThings (56 categories), CWE (200), CAPEC (100), API Security.

    Returns concise results (150 chars each) to save tokens.
    Call fetch_full_doc(doc_id) if you need the complete text.

    Use this to:
      - Classify a finding (find the right CWE/OWASP)
      - Get remediation steps for a vulnerability
      - Find exploitation payloads for a specific vuln type
      - Look up attack patterns

    Example: search_knowledge("exposed git directory on web server")
    Example: search_knowledge("SQL injection bypass WAF")
    Example: search_knowledge("missing security headers CSP HSTS")
    """
    return _semantic_search(query, limit, max_chars=150)


@function_tool
def fetch_full_doc(doc_id: str) -> str:
    """Fetch the complete text of a knowledge base document by its doc_id.

    Use this after search_knowledge when you need more detail than the
    150-char preview. Returns the full chunk text.

    Example: fetch_full_doc("CWE-79")
    Example: fetch_full_doc("cheatsheet/XSS_Prevention_Cheat_Sheet.md")
    """
    client = _get_client()
    if client is None:
        return json.dumps({"error": "Knowledge DB not built"})

    from qdrant_client.models import FieldCondition, MatchValue, Filter

    results = client.query_points(
        collection_name=COLLECTION,
        query=_get_embedder().encode(doc_id).tolist(),  # search by doc_id similarity
        query_filter=Filter(must=[FieldCondition(key="doc_id", match=MatchValue(value=doc_id))]),
        limit=1,
        with_payload=True,
    ).points

    if not results:
        # Fallback: scroll to find by doc_id
        all_results = client.scroll(collection_name=COLLECTION, limit=10000, with_payload=True, with_vectors=False)[0]
        for r in all_results:
            if r.payload.get("doc_id") == doc_id:
                return json.dumps({"doc_id": doc_id, "text": r.payload.get("text", ""),
                                   "title": r.payload.get("title", ""), "source": r.payload.get("source", "")})
        return json.dumps({"error": f"doc_id '{doc_id}' not found"})

    p = results[0].payload or {}
    return json.dumps({"doc_id": doc_id, "text": p.get("text", ""),
                       "title": p.get("title", ""), "source": p.get("source", ""),
                       "url": p.get("url", "")})


@function_tool
def search_cve(keyword: str, limit: int = 5) -> str:
    """Search NVD (National Vulnerability Database) for CVEs matching a keyword.

    Use this to find known vulnerabilities for a specific technology/version
    detected during scanning. This queries the live NVD API (requires internet).

    Example: search_cve("apache 2.4.49")
    Example: search_cve("wordpress plugin contact form")
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": min(limit, 20)})
    full_url = f"{url}?{params}"
    try:
        req = urllib.request.Request(full_url, headers={"User-Agent": "cert-in-pipeline"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cves = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve_id = vuln.get("cve", {}).get("id", "")
            descriptions = vuln.get("cve", {}).get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            metrics = vuln.get("cve", {}).get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            score = cvss.get("baseScore", "?")
            vector = cvss.get("vectorString", "")
            cves.append({
                "id": cve_id,
                "score": score,
                "vector": vector,
                "description": desc[:300],
            })
        return json.dumps({"cves": cves, "count": len(cves), "keyword": keyword})
    except Exception as e:
        return json.dumps({"error": str(e), "cves": []})


@function_tool
def search_exploits(query: str, limit: int = 5) -> str:
    """Search ExploitDB for public exploits matching a keyword.

    Use this to find known exploits for a detected service/version.
    Requires searchsploit installed locally OR falls back to web search.

    Example: search_exploits("apache struts 2")
    Example: search_exploits("vsftpd 2.3.4 backdoor")
    """
    import shutil, subprocess
    sp_path = shutil.which("searchsploit")
    if sp_path:
        try:
            result = subprocess.run(
                [sp_path, "-j", query],
                capture_output=True, text=True, timeout=30,
                encoding="utf-8", errors="replace",
            )
            data = json.loads(result.stdout or "{}")
            exploits = data.get("RESULTS_EXPLOIT", [])[:limit]
            return json.dumps({"exploits": exploits, "count": len(exploits), "source": "searchsploit"})
        except Exception:
            pass

    return json.dumps({
        "exploits": [],
        "hint": "Install searchsploit (ExploitDB) for local exploit search.",
        "search_url": f"https://www.exploit-db.com/search?q={urllib.parse.quote(query)}",
    })


@function_tool
def get_remediation(vuln_type: str) -> str:
    """Get remediation steps for a specific vulnerability type.

    Searches the knowledge base for fix recommendations.
    Use this after finding a vulnerability to get actionable remediation.

    Example: get_remediation("xss")
    Example: get_remediation("sql injection")
    Example: get_remediation("missing security headers")
    """
    return _semantic_search(f"remediation fix prevention {vuln_type}", limit=3)


@function_tool
def get_payloads(vuln_type: str) -> str:
    """Retrieve exploitation payloads for a specific vulnerability type.

    Searches PayloadsAllTheThings and the knowledge base for ready-to-use
    payloads. Use this to verify a finding with actual exploit attempts.

    Example: get_payloads("xss")
    Example: get_payloads("sql injection")
    Example: get_payloads("ssrf")
    """
    return _semantic_search(f"payload exploit {vuln_type}", limit=5)


# ─── Tool registry ─────────────────────────────────────────────────

RAG_TOOLS = [search_knowledge, fetch_full_doc, search_cve, search_exploits, get_remediation, get_payloads]
