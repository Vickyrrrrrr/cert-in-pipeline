"""Seed script v2 — expanded knowledge base with smart chunking.

Sources (all open-source, permissive licenses):
  1. Nuclei templates (MIT) — 13k structured YAML with description+remediation
  2. PayloadsAllTheThings (MIT) — 56 vuln categories, payloads+bypasses
  3. OWASP Cheat Sheet Series (CC-BY-SA-4.0) — 120 remediation guides
  4. OWASP API Security Top 10 (CC-BY-SA-4.0) — API-specific vulns
  5. CWE (MITRE) — weakness definitions
  6. CAPEC (MITRE) — attack patterns
  7. Built-in security checklist — 20 vuln types

Smart chunking:
  - Split markdown by ## headers (semantic boundaries)
  - Max 500 chars per chunk (~125 tokens)
  - 50 char overlap between adjacent chunks
  - Rich metadata: source, category, title, url, doc_id

Token-effective retrieval:
  - search_knowledge returns top 3, 300 chars each (~225 tokens total)
  - fetch_full_doc gets complete text on demand

Usage:
  uv run python knowledge/seed.py            # full rebuild (~5-10 min)
  uv run python knowledge/seed.py --check    # stats only
  uv run python knowledge/seed.py --quick    # skip nuclei (fast, ~2 min)
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

CHUNK_MAX = 500       # max chars per chunk (~125 tokens)
CHUNK_OVERLAP = 50    # overlap between adjacent chunks


@dataclass
class Chunk:
    text: str
    source: str
    category: str
    title: str
    url: str
    doc_id: str


# ─── Smart chunking ────────────────────────────────────────────────

def smart_chunk(text: str, source: str, category: str, title: str, url: str, doc_id: str) -> list[Chunk]:
    """Split text into semantic chunks by headers, with overlap.

    Strategy:
      1. Split by ## headers (markdown sections)
      2. If a section > CHUNK_MAX, split by paragraphs
      3. If a paragraph > CHUNK_MAX, split by sentences
      4. Add overlap between chunks for context continuity
    """
    chunks = []
    text = text.strip()

    if not text or len(text) < 20:
        return chunks

    # Split by ## headers
    sections = []
    current_header = ""
    current_content = []

    for line in text.split("\n"):
        if line.startswith("## ") or line.startswith("# "):
            if current_content:
                sections.append((current_header, "\n".join(current_content)))
            current_header = line.lstrip("# ").strip()
            current_content = [line]
        else:
            current_content.append(line)

    if current_content:
        sections.append((current_header, "\n".join(current_content)))

    # If no headers found, treat whole text as one section
    if not sections:
        sections = [("", text)]

    for header, content in sections:
        content = content.strip()
        if not content or len(content) < 20:
            continue

        # If content fits in one chunk, keep it whole
        if len(content) <= CHUNK_MAX:
            chunk_title = f"{title}: {header}" if header else title
            chunks.append(Chunk(
                text=content, source=source, category=category,
                title=chunk_title, url=url, doc_id=f"{doc_id}_{len(chunks)}",
            ))
            continue

        # Split by paragraphs
        paragraphs = content.split("\n\n")
        current_chunk = ""

        for para in paragraphs:
            if len(current_chunk) + len(para) + 2 <= CHUNK_MAX:
                current_chunk = f"{current_chunk}\n\n{para}" if current_chunk else para
            else:
                if current_chunk:
                    chunk_title = f"{title}: {header}" if header else title
                    chunks.append(Chunk(
                        text=current_chunk, source=source, category=category,
                        title=chunk_title, url=url, doc_id=f"{doc_id}_{len(chunks)}",
                    ))
                    # Overlap: keep last CHUNK_OVERLAP chars
                    current_chunk = current_chunk[-CHUNK_OVERLAP:] if len(current_chunk) > CHUNK_OVERLAP else ""

                # If single paragraph > CHUNK_MAX, split by sentences
                if len(para) > CHUNK_MAX:
                    sentences = para.replace(". ", ". \n").split("\n")
                    for sent in sentences:
                        if len(current_chunk) + len(sent) + 1 <= CHUNK_MAX:
                            current_chunk = f"{current_chunk} {sent}" if current_chunk else sent
                        else:
                            if current_chunk:
                                chunks.append(Chunk(
                                    text=current_chunk, source=source, category=category,
                                    title=f"{title}: {header}" if header else title,
                                    url=url, doc_id=f"{doc_id}_{len(chunks)}",
                                ))
                                current_chunk = sent[:CHUNK_MAX]
                            else:
                                current_chunk = sent[:CHUNK_MAX]
                else:
                    current_chunk = para

        if current_chunk and len(current_chunk) > 20:
            chunk_title = f"{title}: {header}" if header else title
            chunks.append(Chunk(
                text=current_chunk, source=source, category=category,
                title=chunk_title, url=url, doc_id=f"{doc_id}_{len(chunks)}",
            ))

    return chunks


# ─── HTTP helpers ──────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 30) -> str:
    headers = {
        "User-Agent": "cert-in-pipeline-seed/1.0",
        "Accept": "text/html,application/json,application/xml,text/plain",
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: int = 30) -> dict | list:
    return json.loads(_fetch(url, timeout))


def _clone_repo(repo: str, dest: str) -> Path | None:
    """Clone a GitHub repo (shallow) — no API rate limits."""
    dest_path = KNOWLEDGE_DIR / "sources" / dest
    if dest_path.exists() and any(dest_path.iterdir()):
        print(f"    Already cloned: {dest}")
        return dest_path
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"
    import subprocess
    try:
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest_path)],
                       capture_output=True, timeout=120, check=True)
        return dest_path
    except Exception as e:
        print(f"    WARN: clone {repo} failed: {e}")
        return None


def _read_md_files(directory: Path, max_per_file: int = 3) -> list[tuple[str, str, str]]:
    """Read all .md files from a directory. Returns [(filename, content, relpath)]."""
    results = []
    for md in directory.rglob("*.md"):
        try:
            content = md.read_text(encoding="utf-8", errors="replace")
            if len(content) > 20:
                relpath = str(md.relative_to(directory))
                results.append((md.name, content, relpath))
        except Exception:
            continue
    return results


# ─── Source 1: Nuclei templates (MIT) ──────────────────────────────

def fetch_nuclei_templates(quick: bool = False) -> list[Chunk]:
    """Fetch nuclei template descriptions via git clone (no API rate limits)."""
    print("  [1/7] Fetching nuclei templates...")
    chunks = []
    repo_dir = _clone_repo("projectdiscovery/nuclei-templates", "nuclei-templates")
    if not repo_dir:
        print(f"    Got 0 nuclei template chunks")
        return chunks

    categories = {
        "http/cves": "cve",
        "http/vulnerabilities": "vulnerability",
        "http/misconfiguration": "misconfig",
        "http/exposed-panels": "exposed-panel",
        "http/takeovers": "subdomain-takeover",
    }

    cap = 30 if quick else 100
    for subdir, category in categories.items():
        cat_dir = repo_dir / subdir
        if not cat_dir.exists():
            continue
        yaml_files = list(cat_dir.rglob("*.yaml"))[:cap]
        for yf in yaml_files:
            try:
                content = yf.read_text(encoding="utf-8", errors="replace")
                tmpl_id = _extract_yaml_field(content, "id")
                name = _extract_yaml_field(content, "name")
                severity = _extract_yaml_field(content, "severity")
                description = _extract_yaml_field(content, "description")
                remediation = _extract_yaml_field(content, "remediation")
                if not description and not name:
                    continue
                text = f"Nuclei: {name}\nSeverity: {severity}\nDescription: {description}\nRemediation: {remediation}"[:CHUNK_MAX]
                relpath = str(yf.relative_to(repo_dir)).replace("\\", "/")
                chunks.append(Chunk(
                    text=text, source="nuclei-templates", category=category,
                    title=f"{name} ({severity})",
                    url=f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{relpath}",
                    doc_id=tmpl_id or relpath,
                ))
            except Exception:
                continue
    print(f"    Got {len(chunks)} nuclei template chunks")
    return chunks


def _extract_yaml_field(yaml_text: str, field: str) -> str:
    """Lightweight YAML field extraction — handles nested info: block and block scalars."""
    import re
    # Try top-level: field: value  OR  indented under info:  field: value
    match = re.search(rf'^\s*{field}:\s*["\']?(.+?)["\']?\s*$', yaml_text, re.MULTILINE)
    if match:
        val = match.group(1).strip()
        if val and val != "|":
            return val
    # Block scalar: field: | followed by indented lines
    match = re.search(rf'^\s*{field}:\s*\|?\s*\n((?:[ \t]+.+\n?)+)', yaml_text, re.MULTILINE)
    if match:
        lines = [line.strip() for line in match.group(1).strip().split("\n")]
        return " ".join(lines)[:300]
    return ""


# ─── Source 2: PayloadsAllTheThings (MIT) ──────────────────────────

def fetch_payloads_all() -> list[Chunk]:
    """Fetch ALL PayloadsAllTheThings via git clone."""
    print("  [2/7] Fetching PayloadsAllTheThings (all categories)...")
    chunks = []
    repo_dir = _clone_repo("swisskyrepo/PayloadsAllTheThings", "payloadsallthethings")
    if not repo_dir:
        print(f"    Got 0 payload chunks")
        return chunks

    for vuln_dir in repo_dir.iterdir():
        if not vuln_dir.is_dir() or vuln_dir.name.startswith("."):
            continue
        cat_name = vuln_dir.name
        md_files = list(vuln_dir.rglob("*.md"))[:5]
        for md in md_files:
            try:
                content = md.read_text(encoding="utf-8", errors="replace")
                file_chunks = smart_chunk(
                    content, source="payloads",
                    category=cat_name.lower().replace(" ", "-"),
                    title=f"{cat_name}: {md.stem}",
                    url=f"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/{cat_name}/{md.name}",
                    doc_id=f"payloads/{cat_name}/{md.name}",
                )
                chunks.extend(file_chunks[:5])
            except Exception:
                continue
    print(f"    Got {len(chunks)} payload chunks")
    return chunks


# ─── Source 3: OWASP Cheat Sheet Series (CC-BY-SA) ─────────────────

def fetch_owasp_cheatsheets() -> list[Chunk]:
    """Fetch OWASP Cheat Sheet Series via git clone."""
    print("  [3/7] Fetching OWASP Cheat Sheets...")
    chunks = []
    repo_dir = _clone_repo("OWASP/CheatSheetSeries", "cheatsheets")
    if not repo_dir:
        print(f"    Got 0 cheat sheet chunks")
        return chunks

    cs_dir = repo_dir / "cheatsheets"
    if not cs_dir.exists():
        cs_dir = repo_dir

    for md in cs_dir.glob("*.md"):
        try:
            content = md.read_text(encoding="utf-8", errors="replace")
            sheet_name = md.stem.replace("_", " ")
            file_chunks = smart_chunk(
                content, source="owasp-cheatsheet",
                category="remediation",
                title=f"OWASP Cheat Sheet: {sheet_name}",
                url=f"https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/{md.name}",
                doc_id=f"cheatsheet/{md.name}",
            )
            chunks.extend(file_chunks[:3])
        except Exception:
            continue
    print(f"    Got {len(chunks)} cheat sheet chunks")
    return chunks


# ─── Source 4: OWASP API Security Top 10 (CC-BY-SA) ────────────────

def fetch_owasp_api() -> list[Chunk]:
    """Fetch OWASP API Security Top 10 via git clone."""
    print("  [4/7] Fetching OWASP API Security...")
    chunks = []
    repo_dir = _clone_repo("OWASP/API-Security", "api-security")
    if not repo_dir:
        print(f"    Got 0 API security chunks")
        return chunks

    en_dir = repo_dir / "editions" / "2023" / "en"
    if not en_dir.exists():
        en_dir = repo_dir

    for md in en_dir.rglob("*.md"):
        try:
            content = md.read_text(encoding="utf-8", errors="replace")
            file_chunks = smart_chunk(
                content, source="owasp-api",
                category="api-security",
                title=f"API Security: {md.stem}",
                url=f"https://github.com/OWASP/API-Security/blob/master/editions/2023/en/{md.name}",
                doc_id=f"api-security/{md.name}",
            )
            chunks.extend(file_chunks[:5])
        except Exception:
            continue
    print(f"    Got {len(chunks)} API security chunks")
    return chunks


# ─── Source 5: CWE (MITRE) ─────────────────────────────────────────

def fetch_cwe() -> list[Chunk]:
    """Fetch CWE definitions from MITRE."""
    print("  [5/7] Fetching CWE definitions...")
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
            text = f"CWE-{cwe_id}: {name}\n\n{desc}"[:CHUNK_MAX]
            chunks.append(Chunk(
                text=text, source="cwe", category="weakness",
                title=f"CWE-{cwe_id}: {name}",
                url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                doc_id=f"CWE-{cwe_id}",
            ))
            if len(chunks) >= 200:
                break
    except Exception as e:
        print(f"    WARN: CWE fetch failed: {e}, using fallback")
        fallback = {
            "CWE-79": "Cross-site Scripting (XSS)", "CWE-89": "SQL Injection",
            "CWE-200": "Information Exposure", "CWE-284": "Improper Access Control",
            "CWE-287": "Improper Authentication", "CWE-319": "Cleartext Transmission",
            "CWE-352": "CSRF", "CWE-538": "Sensitive File in Web Root",
            "CWE-611": "XXE", "CWE-614": "Cookie Without Secure Flag",
            "CWE-693": "Protection Mechanism Failure", "CWE-918": "SSRF",
            "CWE-942": "Permissive Cross-domain Policy",
        }
        for cid, name in fallback.items():
            chunks.append(Chunk(text=f"{cid}: {name}", source="cwe", category="weakness",
                                title=f"{cid}: {name}", url="", doc_id=cid))
    print(f"    Got {len(chunks)} CWE chunks")
    return chunks


# ─── Source 6: CAPEC (MITRE) ───────────────────────────────────────

def fetch_capec() -> list[Chunk]:
    """Fetch CAPEC attack patterns from MITRE."""
    print("  [6/7] Fetching CAPEC attack patterns...")
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
            text = f"CAPEC-{ap_id}: {name}\n\n{desc}"[:CHUNK_MAX]
            chunks.append(Chunk(
                text=text, source="capec", category="attack-pattern",
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


# ─── Source 7: Built-in security checklist ─────────────────────────

def fetch_security_checklist() -> list[Chunk]:
    """Built-in security knowledge — always available, no network needed."""
    print("  [7/7] Loading built-in security checklist...")
    checklist = [
        ("xss-reflected", "Reflected XSS",
         "User input reflected in HTML without encoding. Test: <script>alert(1)</script> in URL params. CWE-79. Fix: HTML-encode output, CSP headers."),
        ("xss-stored", "Stored XSS",
         "Input stored and displayed without encoding. More dangerous than reflected. Test: inject in comment/profile, check execution on view. CWE-79."),
        ("sqli-error", "Error-based SQL Injection",
         "SQL errors visible. Test: append ' to params. Look for syntax errors. CWE-89. Fix: parameterized queries."),
        ("sqli-blind", "Blind SQL Injection",
         "No errors but app behaves differently. Test: AND 1=1 vs AND 1=2. Use sqlmap. CWE-89."),
        ("ssrf", "Server-Side Request Forgery",
         "Server fetches URLs without validation. Test: http://localhost, http://169.254.169.254 (AWS metadata). CWE-918. Fix: allowlist domains."),
        ("idor", "Insecure Direct Object Reference",
         "Access other users' data by changing IDs. Test: increment ID in URL. CWE-284. Fix: authz checks per object."),
        ("path-traversal", "Path Traversal",
         "Read arbitrary files. Test: ../../../etc/passwd. CWE-22. Fix: sanitize paths."),
        ("open-redirect", "Open Redirect",
         "Redirect to arbitrary URLs. Test: ?next=https://evil.com. CWE-601. Fix: validate redirect URLs."),
        ("info-disclosure", "Information Disclosure",
         "Sensitive info in responses. Check: verbose errors, .git/.env, version headers, source maps. CWE-200."),
        ("missing-headers", "Missing Security Headers",
         "Check: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. CWE-693."),
        ("cookie-flags", "Insecure Cookie Configuration",
         "Missing Secure, HttpOnly, SameSite. CWE-614. Fix: Set-Cookie with Secure; HttpOnly; SameSite=Strict."),
        ("csrf", "Cross-Site Request Forgery",
         "No CSRF token on state-changing requests. CWE-352. Fix: CSRF tokens, SameSite cookies."),
        ("default-creds", "Default Credentials",
         "Services using default passwords. Check: admin/admin, root/root. CWE-798. Fix: force password change."),
        ("exposed-admin", "Exposed Admin Panel",
         "Admin interface accessible. Check: /admin, /phpmyadmin. CWE-284. Fix: restrict to VPN/IP allowlist."),
        ("cors-wildcard", "Wildcard CORS",
         "ACAO: * with credentials. CWE-942. Fix: specific origin allowlist."),
        ("rate-limit", "Missing Rate Limiting",
         "No throttling on login/API. CWE-770. Fix: rate limiting, exponential backoff."),
        ("xxe", "XML External Entity",
         "XML parser processes external entities. Test: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>. CWE-611."),
        ("cmd-injection", "OS Command Injection",
         "User input to system(). Test: ; ls, | whoami. CWE-78. Fix: safe APIs, no shell."),
        ("file-upload", "Unrestricted File Upload",
         "Upload executable files. Test: .php, .jsp. CWE-434. Fix: validate type, rename, store outside webroot."),
        ("deserialization", "Insecure Deserialization",
         "App deserializes untrusted data. Test: base64 serialized objects. CWE-502. Fix: use JSON, validate."),
    ]
    chunks = []
    for cat, title, text in checklist:
        chunks.append(Chunk(text=text, source="checklist", category=cat, title=title, url="", doc_id=f"checklist-{cat}"))
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
    print(f"  Model loaded. Dimension: {embedder.get_embedding_dimension()}")

    client = QdrantClient(path=QDRANT_PATH)

    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass

    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=EMBED_DIMS, distance=Distance.COSINE),
    )

    BATCH = 64
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
    from qdrant_client import QdrantClient
    from qdrant_client.models import FieldCondition, MatchValue, Filter

    client = QdrantClient(path=QDRANT_PATH)
    try:
        info = client.get_collection(COLLECTION)
        count = info.points_count
        print(f"\n  Qdrant: {QDRANT_PATH}")
        print(f"  Collection: {COLLECTION}")
        print(f"  Points: {count}")
        print(f"  Vector size: {info.config.params.vectors.size}")
        print(f"  Distance: {info.config.params.vectors.distance}")

        sources = ["nuclei-templates", "payloads", "owasp-cheatsheet", "owasp-api", "cwe", "capec", "checklist"]
        print(f"\n  By source:")
        for src in sources:
            r = client.count(COLLECTION, count_filter=Filter(must=[FieldCondition(key="source", match=MatchValue(value=src))]), exact=True)
            print(f"    {src:20s}: {r.count}")
    except Exception as e:
        print(f"  Error: {e}. Run 'python knowledge/seed.py' to build the DB.")


# ─── Main ──────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Seed Qdrant security knowledge base v2")
    parser.add_argument("--check", action="store_true", help="Show stats only")
    parser.add_argument("--quick", action="store_true", help="Skip nuclei templates (fast mode)")
    args = parser.parse_args()

    print("=" * 55)
    print("  CERT-In Pipeline — Knowledge Base Seeder v2")
    print("=" * 55)

    if args.check:
        show_stats()
        return

    print("\nFetching security knowledge sources...\n")
    all_chunks: list[Chunk] = []
    all_chunks.extend(fetch_nuclei_templates(quick=args.quick))
    all_chunks.extend(fetch_payloads_all())
    all_chunks.extend(fetch_owasp_cheatsheets())
    all_chunks.extend(fetch_owasp_api())
    all_chunks.extend(fetch_cwe())
    all_chunks.extend(fetch_capec())
    all_chunks.extend(fetch_security_checklist())

    print(f"\n  Total chunks: {len(all_chunks)}")

    if not all_chunks:
        print("  No chunks fetched. Check network connection.")
        sys.exit(1)

    print("\nSeeding Qdrant vector database...\n")
    seed_qdrant(all_chunks)
    show_stats()
    print(f"\n  Done! Knowledge base ready for RAG queries.")


if __name__ == "__main__":
    main()
