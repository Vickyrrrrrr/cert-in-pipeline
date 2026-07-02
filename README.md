# CERT-In Vulnerability Pipeline

An open-source **multi-agent security scanning swarm** with LLM-powered analysis, RAG knowledge base, and independent vulnerability verification. Reports to CERT-In (Indian Computer Emergency Response Team).

## What Makes This Different

| Feature | This Pipeline | Traditional Scanners |
|---------|--------------|---------------------|
| Architecture | 5 specialized AI agents (swarm) | Single scanner |
| False positives | Independent Verifier agent replays each PoC | Manual triage |
| Knowledge base | 1,259 chunks (CWE, CAPEC, OWASP, PayloadsAllTheThings) via Qdrant semantic search | None |
| Context management | SQLite evidence store — raw output never enters LLM context | Dumps everything |
| Hallucination guard | Pydantic output types enforced on every agent | Free-text reports |
| Parallel execution | Recon + Enumeration run simultaneously via `asyncio.gather` | Sequential |
| LLM providers | 22 providers (GLM, OpenAI, Claude, Groq, DeepSeek, Ollama, etc.) | Vendor-locked |
| Cost | ~$0.07 per finding verified (MAPTA benchmark) | $$$$ licensing |

---

## Quick Start

### 1. Install

```bash
# Linux/macOS
curl -sSL https://raw.githubusercontent.com/Vickyrrrrrr/cert-in-pipeline/master/scripts/install.sh | bash

# Windows (PowerShell)
curl -sSL https://raw.githubusercontent.com/Vickyrrrrrr/cert-in-pipeline/master/scripts/install.ps1 | powershell -c -
```

This installs: uv (Python package manager), Python deps, nuclei, nmap, subfinder, httpx, ffuf, sqlmap.

### 2. Build the knowledge base (one-time, ~2 min)

```bash
cd ~/cert-in-pipeline
uv run python knowledge/seed.py
```

Downloads and embeds 1,259 security knowledge chunks from 6 open-source sources:
- PayloadsAllTheThings (484 chunks — 56 vuln categories, MIT license)
- OWASP Cheat Sheet Series (352 chunks — 120 remediation guides)
- OWASP API Security Top 10 (103 chunks)
- CWE definitions from MITRE (200 chunks)
- CAPEC attack patterns from MITRE (100 chunks)
- Built-in security checklist (20 chunks)

Stored in local Qdrant vector DB (`knowledge/qdrant.db`) — **no Docker, no cloud, runs on CPU**.

### 3. Set your API key

```bash
# Pick any one provider:
export GLM_API_KEY="your-key"        # GLM (Z.ai) — https://z.ai
export OPENAI_API_KEY="your-key"     # OpenAI
export GROQ_API_KEY="your-key"       # Groq — free tier available
export DEEPSEEK_API_KEY="your-key"   # DeepSeek
```

Local providers (Ollama, LM Studio) don't need a key.

### 4. Run the swarm

```bash
uv run python pipeline.py swarm --target example.com --provider glm --model glm-5-turbo
```

---

## How It Works

### Multi-Agent Swarm Architecture

```
 Phase 1: Recon + Enumeration ──── asyncio.gather (PARALLEL)
          │              │
          │ subfinder    │ ffuf
          │ nmap         │ curl
          │ httpx        │ check_headers
          │ whatweb      │ wpscan
          ▼              ▼
 Phase 2: Vulnerability Scanning ── depends on recon results
          │
          │ nuclei + nikto + sqlmap + search_cve + search_exploits
          ▼
 Phase 3: Independent Verification ── fresh agent per finding (max 3 parallel)
          │
          │ Verifier replays each PoC with curl
          │ Filters false positives
          │ Adjusts severity if needed
          ▼
 Phase 4: Report Generation ──────── handoff to Reporter (clean context)
          │
          │ Only VERIFIED findings reach the report
          │ CVSS 3.1 scores + CWE/OWASP/CERT-In references
          ▼
        results/cert-in-report.json
```

### 5 Specialized Agents

| Agent | Role | Tools | Output Type |
|-------|------|-------|-------------|
| **Recon** | Discover attack surface (subdomains, ports, tech) | 21 | `ReconOutput` |
| **Enum** | Find hidden paths, API endpoints, sensitive files | 17 | `EnumOutput` |
| **VulnScan** | Scan for vulnerabilities + classify with RAG | 21 | `VulnOutput` |
| **Verifier** | Independently replay PoC to confirm findings | 3 | `VerifiedFinding` |
| **Reporter** | Generate CERT-In report (verified findings only) | 0 | `ScanReport` |

### 17 Security Tools

nuclei, nmap, subfinder, httpx, ffuf, curl, sqlmap, whatweb, nikto, wpscan, searchsploit, dns_lookup, check_security_headers, store_evidence, fetch_evidence, read_file, write_file

### 6 RAG Knowledge Tools

- `search_knowledge(query)` — semantic search across 1,259 chunks
- `fetch_full_doc(doc_id)` — get complete text for a specific hit
- `search_cve(keyword)` — live NVD API for CVE lookup
- `search_exploits(query)` — ExploitDB / searchsploit
- `get_remediation(vuln_type)` — find fix recommendations
- `get_payloads(vuln_type)` — get exploitation payloads

### Token-Effective Retrieval

- Search returns **3 results, 150 chars each** (~100 tokens)
- Agent calls `fetch_full_doc` only when it needs full text
- Raw tool output stored in **SQLite evidence DB** — never inlined into LLM context
- Each finding carries an `evidence_ref` ID pointing to stored raw output

---

## All Commands

### Swarm mode (recommended — multi-agent)

```bash
uv run python pipeline.py swarm --target example.com --provider glm --model glm-5-turbo
```

### Agent mode (single LLM agent — legacy)

```bash
uv run python pipeline.py agent --target example.com --provider glm --model glm-5-turbo
```

### Benchmark mode (test LLM capability)

Tests if a model can analyze security data. No real scanning. Scores 0-100%.

```bash
uv run python pipeline.py benchmark --provider glm --model glm-5.2
uv run python pipeline.py benchmark --provider ollama --model qwen2.5:7b
uv run python pipeline.py benchmark --provider groq --model llama-3.3-70b-versatile
```

### Live mode (single-agent pipeline)

```bash
uv run python pipeline.py live --target example.com --provider glm --model glm-5.2
```

### List providers

```bash
uv run python.py providers
```

### Score a previous run

```bash
uv run python pipeline.py score results/benchmark-results.json
```

### Rebuild knowledge base

```bash
uv run python knowledge/seed.py           # full rebuild
uv run python knowledge/seed.py --quick   # skip nuclei (fast)
uv run python knowledge/seed.py --check   # show stats only
```

---

## Output

All results save to `./results/`:

| File | What it contains |
|------|-----------------|
| `cert-in-report.json` | Final CERT-In report (verified findings only) |
| `evidence.db` | SQLite — raw tool output keyed by evidence_id |
| `sessions/*.jsonl` | Session transcripts (audit trail) |
| `benchmark-results.json` | Benchmark output + model score |

---

## Benchmark Pipeline (9 Skills)

| Step | Skill | What the LLM does | Weight |
|------|-------|-------------------|--------|
| 01 | recon | Analyze DNS, SSL, headers, tech stack | 10% |
| 02 | enumeration | Identify high-value subdomains & paths | 10% |
| 03 | port-scan | Analyze nmap results for exposures | 10% |
| 04 | vuln-scan | Classify nuclei findings by severity | 15% |
| 05 | analysis | Verify true vs false positives | 15% |
| 06 | severity | Assign CVSS 3.1 scores | 10% |
| 07 | exploitability | Map attack scenarios | 10% |
| 08 | report | Generate CERT-In disclosure report | 15% |
| 09 | remediation | Provide code-level fixes | 5% |

A model scoring **80%+** is certified as **"CERT-In Pipeline Ready"**.

---

## 22 Supported Providers

| Provider | ID | Key env var | Needs key? |
|----------|----|------------|------------|
| Ollama (local) | `ollama` | — | No |
| LM Studio (local) | `lmstudio` | — | No |
| llama.cpp (local) | `llamacpp` | — | No |
| vLLM | `vllm` | — | No |
| **GLM (Z.ai)** | `glm` | `GLM_API_KEY` | Yes |
| BigModel (China) | `bigmodel` | `BIGMODEL_API_KEY` | Yes |
| OpenAI | `openai` | `OPENAI_API_KEY` | Yes |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | Yes |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | Yes |
| Groq | `groq` | `GROQ_API_KEY` | Yes |
| Together AI | `together` | `TOGETHER_API_KEY` | Yes |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | Yes |
| Fireworks AI | `fireworks` | `FIREWORKS_API_KEY` | Yes |
| Cerebras | `cerebras` | `CEREBRAS_API_KEY` | Yes |
| Mistral | `mistral` | `MISTRAL_API_KEY` | Yes |
| NVIDIA NIM | `nvidia` | `NVIDIA_API_KEY` | Yes |
| xAI (Grok) | `xai` | `XAI_API_KEY` | Yes |
| Moonshot (Kimi) | `moonshot` | `MOONSHOT_API_KEY` | Yes |
| MiniMax | `minimax` | `MINIMAX_API_KEY` | Yes |
| Hugging Face | `huggingface` | `HUGGINGFACE_API_KEY` | Yes |
| Amazon Bedrock | `bedrock` | `AWS_ACCESS_KEY_ID` | AWS creds |
| Google Vertex | `vertex` | `GOOGLE_APPLICATION_CREDENTIALS` | GCP creds |

---

## CERT-In Reporting

- **Email:** vdisclose@cert-in.org.in
- **Policy:** [RVDCP](https://www.cert-in.org.in/RVDCP.jsp)
- **PGP:** Recommended for sensitive reports
- **CVE:** CERT-In is a CNA and can assign CVE IDs

---

## Docker (Sandboxed)

```bash
# Build
docker build -t cert-in-pipeline .

# Run
docker run -e GLM_API_KEY=your-key cert-in-pipeline swarm --target example.com --provider glm --model glm-5-turbo
```

Or use the helper scripts:
```bash
# Linux/macOS
./scripts/run-docker.sh example.com glm glm-5-turbo your-key

# Windows
.\scripts\run-docker.ps1 -Target example.com -ApiKey your-key
```

---

## Project Structure

```
cert-in-pipeline/
├── pipeline.py              # CLI entry point (swarm | agent | benchmark | live)
├── config.yaml              # Configuration
├── providers.yaml           # 22 LLM provider configs
│
├── llm/
│   ├── orchestrator.py      # Multi-agent swarm (5 agents, parallel, verification)
│   ├── schemas.py           # Pydantic output types (hallucination guard)
│   ├── evidence.py          # SQLite evidence store (context isolation)
│   ├── rag.py               # Qdrant semantic search (6 RAG tools)
│   ├── tools.py             # 17 security tools
│   ├── agent.py             # Legacy single-agent mode
│   └── interface.py         # Provider resolution
│
├── knowledge/
│   ├── seed.py              # Builds Qdrant DB from 6 open sources
│   └── qdrant.db            # 1,259 embedded chunks (gitignored)
│
├── skills/                  # 9 benchmark skills (test LLM capability)
├── pipeline/                # Engine & data models
├── tools/                   # Legacy scanner wrappers
├── scoring/                 # Evaluation & scoring
├── reporting/               # CERT-In formatter
├── scripts/                 # Install + Docker run scripts
├── Dockerfile               # Kali Linux sandbox
└── docker-compose.yml
```

---

## Research Foundation

This pipeline implements patterns from peer-reviewed security AI research:

| Paper | Implementation |
|-------|---------------|
| [MAPTA](https://arxiv.org/abs/2508.20816) (UCL 2025) | Independent Verifier agent per finding (eliminates false positives) |
| [xOffense](https://arxiv.org/abs/2509.13021) (2025) | Multi-agent task coordination, specialized roles |
| [PentestAgent](https://arxiv.org/abs/2411.05185) (AsiaCCS 2025) | RAG knowledge enhancement for exploitation |
| [VulnBot](https://arxiv.org/abs/2501.13411) (2025) | Role specialization, penetration task graph |
| [HackSynth](https://arxiv.org/abs/2412.01778) (2024) | Planner + Summarizer dual-module pattern |

---

## Disclaimer

Only scan websites you have **explicit authorization** to test. Unauthorized scanning is illegal under the Information Technology Act, 2000 (India) and similar laws worldwide.

## License

MIT
