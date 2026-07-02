"""Seed script — downloads security knowledge and populates Qdrant vector DB.

Sources (all public, open-source):
  1. OWASP WSTG (Web Security Testing Guide) — GitHub raw
  2. CWE (Common Weakness Enumeration) — MITRE XML
  3. CAPEC (Common Attack Pattern Enumeration) — MITRE XML
  4. PayloadsAllTheThings — GitHub repo (injection payloads)
  5. CERT-In advisories — public RSS
  6. HackTricks — key pages

Usage:
  python knowledge/seed.py            # full rebuild
  python knowledge/seed.py --check    # show stats only

The Qdrant DB is stored locally at knowledge/qdrant.db — no Docker, no cloud.
Embedding model: all-MiniLM-L6-v2 (384 dims, 80MB, runs on CPU).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, asdict

KNOWLEDGE_DIR = Path(__file__).parent
QDRANT_PATH = str(KNOWLEDGE_DIR / "qdrant.db")
COLLECTION = "security_knowledge"
EMBED_MODEL = "all-MiniLM-L6-v2"
EMBED_DIMS = 384


@dataclass
class Chunk:
    text: str
    source: str       # "owasp-wstg", "cwe", "capec", "payloads", "cert-in"
    category: str     # "xss", "sqli", "ssrf", "info-disclosure", etc.
    title: str
    url: str
    doc_id: str       # unique ID within source


# ─── HTTP helper ────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 30) -> str:
    """Fetch URL content as text."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "cert-in-pipeline-seed/1.0",
        "Accept": "text/html,application/json,application/xml,text/plain",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: int = 30) -> dict:
    return json.loads(_fetch(url, timeout))


# ─── Source 1: OWASP WSTG ──────────────────────────────────────────

def fetch_owasp_wstg() -> list[Chunk]:
    """Fetch OWASP Web Security Testing Guide test cases."""
    print("  [1/6] Fetching OWASP WSTG...")
    chunks = []
    try:
        api_url = "https://api.github.com/repos/OWASP/WSTG/contents/v2/src/markdown"
        dirs = _fetch_json(api_url)
        for d in dirs:
            if d.get("type") != "dir" or not d.get("name", "").startswith("0"):
                continue
            try:
                files = _fetch_json(d["url"])
                for f in files:
                    if not f["name"].endswith(".md"):
                        continue
                    try:
                        content = _fetch(f["download_url"])
                        category = d["name"].split("-", 1)[-1] if "-" in d["name"] else d["name"]
                        chunks.append(Chunk(
                            text=content[:4000],
                            source="owasp-wstg",
                            category=category.lower(),
                            title=f["name"].replace(".md", ""),
                            url=f["html_url"],
                            doc_id=f["name"],
                        ))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception as e:
        print(f"    WARN: OWASP WSTG fetch failed: {e}")
    print(f"    Got {len(chunks)} WSTG chunks")
    return chunks


# ─── Source 2: CWE (MITRE) ─────────────────────────────────────────

def fetch_cwe() -> list[Chunk]:
    """Fetch CWE definitions from MITRE."""
    print("  [2/6] Fetching CWE definitions...")
    chunks = []
    try:
        url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        import zipfile, io
        req = urllib.request.Request(url, headers={"User-Agent": "cert-in-pipeline-seed/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            zdata = resp.read()
        zf = zipfile.ZipFile(io.BytesIO(zdata))
        xml_name = [n for n in zf.namelist() if n.endswith(".xml")][0]
        xml_content = zf.read(xml_name).decode("utf-8", errors="replace")

        root = ET.fromstring(xml_content)
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

        for weakness in root.findall(".//cwe:Weakness", ns):
            cwe_id = weakness.get("ID", "")
            name = weakness.findtext("cwe:Name", "", ns)
            desc = weakness.findtext("cwe:Description", "", ns)
            extended = weakness.findtext("cwe:Extended_Description", "", ns)
            text = f"CWE-{cwe_id}: {name}\n\n{desc}\n\n{extended}"[:3000]
            chunks.append(Chunk(
                text=text,
                source="cwe",
                category="weakness",
                title=f"CWE-{cwe_id}: {name}",
                url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                doc_id=f"CWE-{cwe_id}",
            ))
            if len(chunks) >= 200:
                break
    except Exception as e:
        print(f"    WARN: CWE fetch failed: {e}, using fallback")
        fallback_cwe = {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-200": "Information Exposure",
            "CWE-209": "Error Message with Sensitive Info",
            "CWE-284": "Improper Access Control",
            "CWE-287": "Improper Authentication",
            "CWE-319": "Cleartext Transmission",
            "CWE-352": "Cross-Site Request Forgery",
            "CWE-538": "Sensitive File in Web Root",
            "CWE-611": "XXE",
            "CWE-614": "Cookie Without Secure Flag",
            "CWE-693": "Protection Mechanism Failure",
            "CWE-918": "SSRF",
            "CWE-942": "Permissive Cross-domain Policy",
        }
        for cid, name in fallback_cwe.items():
            chunks.append(Chunk(
                text=f"{cid}: {name}",
                source="cwe", category="weakness",
                title=f"{cid}: {name}",
                url=f"https://cwe.mitre.org/data/definitions/{cid.split('-')[1]}.html",
                doc_id=cid,
            ))
    print(f"    Got {len(chunks)} CWE chunks")
    return chunks


# ─── Source 3: CAPEC (MITRE) ───────────────────────────────────────

def fetch_capec() -> list[Chunk]:
    """Fetch CAPEC attack patterns from MITRE."""
    print("  [3/6] Fetching CAPEC attack patterns...")
    chunks = []
    try:
        url = "https://capec.mitre.org/data/xml/capec_latest.xml"
        xml_content = _fetch(url, timeout=60)
        root = ET.fromstring(xml_content)
        ns = {"capec": "http://capec.mitre.org/capec-3"}

        for ap in root.findall(".//capec:Attack_Pattern", ns):
            ap_id = ap.get("ID", "")
            name = ap.findtext("capec:Name", "", ns)
            desc = ap.findtext("capec:Description", "", ns)
            text = f"CAPEC-{ap_id}: {name}\n\n{desc}"[:3000]
            chunks.append(Chunk(
                text=text,
                source="capec",
                category="attack-pattern",
                title=f"CAPEC-{ap_id}: {name}",
                url=f"https://capec.mitre.org/data/definitions/{ap_id}.html",
                doc_id=f"CAPEC-{ap_id}",
            ))
            if len(chunks) >= 100:
                break
    except Exception as e:
        print(f"    WARN: CAPEC fetch failed: {e}")
    print(f"    Got {len(chunks)} CAPEC chunks")
    return chunks


# ─── Source 4: PayloadsAllTheThings ────────────────────────────────

def fetch_payloads() -> list[Chunk]:
    """Fetch key injection payloads from PayloadsAllTheThings."""
    print("  [4/6] Fetching PayloadsAllTheThings...")
    chunks = []
    categories = [
        "SQL Injection", "XSS Injection", "SSRF Server Side Request Forgery",
        "Command Injection", "File Upload", "Path Traversal",
        "LDAP Injection", "XXE Injection", "CSRF Cross Site Request Forgery",
        "Open Redirect", "IDOR",
    ]
    for cat in categories:
        try:
            safe_name = cat.replace(" ", "%20")
            api_url = f"https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/contents/{safe_name}"
            files = _fetch_json(api_url)
            for f in files:
                if f.get("type") != "file" or not f["name"].endswith(".md"):
                    continue
                try:
                    content = _fetch(f["download_url"])
                    chunks.append(Chunk(
                        text=content[:4000],
                        source="payloads",
                        category=cat.lower().replace(" ", "-"),
                        title=f"{cat}: {f['name']}",
                        url=f["html_url"],
                        doc_id=f"{cat}/{f['name']}",
                    ))
                except Exception:
                    continue
        except Exception:
            continue
    print(f"    Got {len(chunks)} payload chunks")
    return chunks


# ─── Source 5: CERT-In advisories ──────────────────────────────────

def fetch_cert_in() -> list[Chunk]:
    """Fetch CERT-In vulnerability advisories."""
    print("  [5/6] Fetching CERT-In advisories...")
    chunks = []
    try:
        url = "https://www.cert-in.org.in/data/advisories.js"
        data = _fetch(url, timeout=20)
        try:
            advisories = json.loads(data)
            for adv in advisories[:50]:
                chunks.append(Chunk(
                    text=f"CERT-In Advisory {adv.get('id', '')}: {adv.get('title', '')}\n\n{adv.get('description', '')}",
                    source="cert-in",
                    category="advisory",
                    title=f"CERT-In {adv.get('id', '')}: {adv.get('title', '')}",
                    url="https://www.cert-in.org.in/",
                    doc_id=f"cert-in-{adv.get('id', '')}",
                ))
        except json.JSONDecodeError:
            pass
    except Exception as e:
        print(f"    WARN: CERT-In fetch failed: {e}")
    print(f"    Got {len(chunks)} CERT-In chunks")
    return chunks


# ─── Source 6: Built-in security checklist ─────────────────────────

def fetch_security_checklist() -> list[Chunk]:
    """Built-in security knowledge — always available, no network needed."""
    print("  [6/6] Loading built-in security checklist...")
    checklist = [
        ("xss-reflected", "Reflected XSS",
         "User input is reflected in HTML without encoding. Test: inject <script>alert(1)</script> in URL params. "
         "CWE-79. Fix: HTML-encode all output, use CSP headers."),
        ("xss-stored", "Stored XSS",
         "User input is stored and displayed without encoding. More dangerous than reflected. "
         "Test: inject payload in comment/profile fields, check if it executes on view. CWE-79."),
        ("sqli-error", "Error-based SQL Injection",
         "SQL errors visible to user. Test: append ' to URL params. Look for SQL syntax errors. "
         "CWE-89. Fix: parameterized queries, WAF."),
        ("sqli-blind", "Blind SQL Injection",
         "No visible errors but app behaves differently. Test: append AND 1=1 vs AND 1=2. "
         "Use sqlmap for automation. CWE-89."),
        ("ssrf", "Server-Side Request Forgery",
         "Server fetches URLs without validation. Test: replace URL params with http://localhost, http://169.254.169.254. "
         "CWE-918. Fix: allowlist of domains, block internal IPs."),
        ("idor", "Insecure Direct Object Reference",
         "User can access other users' data by changing IDs. Test: increment/decrement ID in URL. "
         "CWE-284. Fix: authorization checks on every object access."),
        ("path-traversal", "Path Traversal",
         "App allows reading arbitrary files. Test: ../../../etc/passwd in file params. "
         "CWE-22. Fix: validate and sanitize file paths."),
        ("open-redirect", "Open Redirect",
         "App redirects to arbitrary URLs. Test: ?next=https://evil.com. "
         "CWE-601. Fix: validate redirect URLs against allowlist."),
        ("info-disclosure", "Information Disclosure",
         "Sensitive info in responses. Check: verbose errors, .git/.env exposed, version headers, source maps. "
         "CWE-200. Fix: custom error pages, disable directory listing, remove sensitive files."),
        ("missing-headers", "Missing Security Headers",
         "Check for: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. "
         "CWE-693. Fix: add all security headers in web server config."),
        ("cookie-flags", "Insecure Cookie Configuration",
         "Cookies missing Secure, HttpOnly, SameSite flags. "
         "CWE-614, CWE-1004. Fix: Set-Cookie with Secure; HttpOnly; SameSite=Strict."),
        ("csrf", "Cross-Site Request Forgery",
         "No CSRF token on state-changing requests. Test: craft HTML form that submits to target. "
         "CWE-352. Fix: CSRF tokens, SameSite cookies."),
        ("default-creds", "Default Credentials",
         "Services using default passwords. Check: admin/admin, root/root, tomcat/tomcat. "
         "CWE-798. Fix: force password change on first login."),
        ("exposed-admin", "Exposed Admin Panel",
         "Admin interface accessible without auth or with default creds. Check: /admin, /admin/login, /phpmyadmin. "
         "CWE-284. Fix: restrict admin to VPN/IP allowlist, strong auth."),
        ("cors-wildcard", "Wildcard CORS",
         "Access-Control-Allow-Origin: * with credentials. Test: check response headers for ACAO. "
         "CWE-942. Fix: specific origin allowlist, don't use * with credentials."),
        ("rate-limit", "Missing Rate Limiting",
         "No throttling on login/API. Test: send 100 requests rapidly. "
         "CWE-770. Fix: rate limiting middleware, exponential backoff."),
        ("insecure-deserialization", "Insecure Deserialization",
         "App deserializes untrusted data. Test: look for base64-encoded serialized objects in params. "
         "CWE-502. Fix: use JSON, validate before deserialization."),
        ("xxe", "XML External Entity",
         "XML parser processes external entities. Test: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>. "
         "CWE-611. Fix: disable DTD processing in XML parser."),
        ("cmd-injection", "OS Command Injection",
         "User input passed to system(). Test: ; ls, | whoami, && id. "
         "CWE-78. Fix: use safe APIs, never pass user input to shell."),
        ("file-upload", "Unrestricted File Upload",
         "App allows uploading executable files. Test: upload .php, .jsp, .aspx files. "
         "CWE-434. Fix: validate file type, rename, store outside webroot."),
    ]
    chunks = []
    for cat, title, text in checklist:
        chunks.append(Chunk(
            text=text, source="checklist", category=cat,
            title=title, url="", doc_id=f"checklist-{cat}",
        ))
    print(f"    Got {len(chunks)} checklist chunks")
    return chunks


# ─── Qdrant seeding ────────────────────────────────────────────────

def seed_qdrant(chunks: list[Chunk]) -> None:
    """Create Qdrant collection and insert all chunks with embeddings."""
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    from sentence_transformers import SentenceTransformer

    print(f"\n  Loading embedding model ({EMBED_MODEL})...")
    embedder = SentenceTransformer(EMBED_MODEL)
    print(f"  Model loaded. Dimension: {embedder.get_sentence_embedding_dimension()}")

    client = QdrantClient(path=QDRANT_PATH)

    # Recreate collection
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass

    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=EMBED_DIMS, distance=Distance.COSINE),
    )

    # Batch embed and insert
    BATCH = 50
    total = len(chunks)
    print(f"\n  Embedding {total} chunks (batch={BATCH})...")

    for i in range(0, total, BATCH):
        batch = chunks[i:i + BATCH]
        texts = [c.text for c in batch]
        vectors = embedder.encode(texts, show_progress_bar=False).tolist()

        points = []
        for j, (chunk, vector) in enumerate(zip(batch, vectors)):
            points.append(PointStruct(
                id=i + j,
                vector=vector,
                payload={
                    "text": chunk.text,
                    "source": chunk.source,
                    "category": chunk.category,
                    "title": chunk.title,
                    "url": chunk.url,
                    "doc_id": chunk.doc_id,
                },
            ))

        client.upsert(collection_name=COLLECTION, points=points)
        pct = min(100, int((i + len(batch)) / total * 100))
        print(f"    [{pct:3d}%] {i + len(batch)}/{total} chunks embedded", end="\r")

    print(f"\n  Done! {total} chunks in Qdrant at {QDRANT_PATH}")


def show_stats() -> None:
    """Show Qdrant collection stats."""
    from qdrant_client import QdrantClient

    client = QdrantClient(path=QDRANT_PATH)
    try:
        info = client.get_collection(COLLECTION)
        count = info.points_count
        print(f"\n  Qdrant: {QDRANT_PATH}")
        print(f"  Collection: {COLLECTION}")
        print(f"  Points: {count}")
        print(f"  Vector size: {info.config.params.vectors.size}")
        print(f"  Distance: {info.config.params.vectors.distance}")

        # Count by source
        from qdrant_client.models import FieldCondition, MatchValue, Filter
        sources = ["owasp-wstg", "cwe", "capec", "payloads", "cert-in", "checklist"]
        print(f"\n  By source:")
        for src in sources:
            r = client.count(
                COLLECTION,
                count_filter=Filter(must=[FieldCondition(key="source", match=MatchValue(value=src))]),
                exact=True,
            )
            print(f"    {src:15s}: {r.count}")
    except Exception as e:
        print(f"  Error: {e}. Run 'python knowledge/seed.py' to build the DB.")


# ─── Main ──────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Seed Qdrant security knowledge base")
    parser.add_argument("--check", action="store_true", help="Show stats only")
    args = parser.parse_args()

    print("=" * 55)
    print("  CERT-In Pipeline — Knowledge Base Seeder")
    print("=" * 55)

    if args.check:
        show_stats()
        return

    # Fetch all sources
    print("\nFetching security knowledge sources...\n")
    all_chunks: list[Chunk] = []
    all_chunks.extend(fetch_owasp_wstg())
    all_chunks.extend(fetch_cwe())
    all_chunks.extend(fetch_capec())
    all_chunks.extend(fetch_payloads())
    all_chunks.extend(fetch_cert_in())
    all_chunks.extend(fetch_security_checklist())

    print(f"\n  Total chunks: {len(all_chunks)}")

    if not all_chunks:
        print("  No chunks fetched. Check network connection.")
        sys.exit(1)

    # Seed Qdrant
    print("\nSeeding Qdrant vector database...\n")
    seed_qdrant(all_chunks)

    # Show stats
    show_stats()
    print(f"\n  Done! Knowledge base ready for RAG queries.")
    print(f"  Run: python pipeline.py swarm --target example.com --provider glm --model glm-5-turbo")


if __name__ == "__main__":
    main()
