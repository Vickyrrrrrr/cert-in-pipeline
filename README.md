# CERT-In Vulnerability Pipeline

An open-source pipeline for finding website vulnerabilities and reporting them to CERT-In (Indian Computer Emergency Response Team).

Runs inside a **Docker sandbox** (Kali Linux) — your host system is never touched. Supports **22 LLM providers** (GLM, Ollama, OpenAI, Claude, Groq, DeepSeek, etc.).

## What This Does

1. **Scans** real websites for vulnerabilities (nuclei, nmap, subfinder, httpx)
2. **Analyzes** scan results using any LLM
3. **Verifies** findings to filter false positives
4. **Scores** vulnerabilities with CVSS 3.1
5. **Generates** CERT-In compliant disclosure reports
6. **Benchmarks** LLMs on security analysis (9-step test, scored 0-100%)

---

## Setup

### 1. Install dependencies

```powershell
# Windows
pip install -r requirements.txt

# Or use Docker (recommended — includes all security tools)
docker build -t cert-in-pipeline .
```

### 2. Set your API key

Each provider reads its key from a specific environment variable:

```powershell
# GLM (Z.ai) — get key from https://z.ai
$env:GLM_API_KEY = "your-key-here"

# OpenAI
$env:OPENAI_API_KEY = "your-key-here"

# Groq — get key from https://console.groq.com
$env:GROQ_API_KEY = "your-key-here"

# DeepSeek — get key from https://platform.deepseek.com
$env:DEEPSEEK_API_KEY = "your-key-here"

# Anthropic
$env:ANTHROPIC_API_KEY = "your-key-here"
```

```bash
# Linux/macOS
export GLM_API_KEY="your-key-here"
```

Local providers (Ollama, LM Studio, llama.cpp) don't need a key.

### 3. List all supported providers

```bash
python pipeline.py providers
```

---

## Usage

### Benchmark mode (test LLM capability with sample data)

Tests if a model can analyze security data. No real scanning. Scores the model 0-100%.

```powershell
# GLM-5.2
python pipeline.py benchmark --provider glm --model glm-5.2

# Ollama (local, no key needed)
python pipeline.py benchmark --provider ollama --model qwen2.5:7b

# OpenAI
python pipeline.py benchmark --provider openai --model gpt-4o

# Groq
python pipeline.py benchmark --provider groq --model llama-3.3-70b-versatile

# DeepSeek
python pipeline.py benchmark --provider deepseek --model deepseek-chat

# Or pass key directly (skip env var)
python pipeline.py benchmark --provider glm --model glm-5.2 --api-key "your-key"
```

### Live mode (scan a real website)

Runs actual security tools, feeds results to LLM, generates CERT-In report.

```powershell
# With GLM
python pipeline.py live --target example.com --provider glm --model glm-5.2

# With local Ollama
python pipeline.py live --target example.com --provider ollama --model qwen2.5:7b

# Skip running tools (use if tools aren't installed)
python pipeline.py live --target example.com --provider glm --model glm-5.2 --skip-tools
```

### Docker sandbox (all tools pre-installed)

```powershell
# Windows
.\scripts\run-docker.ps1 -Target example.com -ApiKey your-glm-key

# Linux/macOS
chmod +x scripts/run-docker.sh
./scripts/run-docker.sh example.com openai/glm-5.2 your-glm-key
```

### Score a previous run

```powershell
python pipeline.py score results/benchmark-results.json
```

---

## Output

All results save to `./results/`:

| File | What it contains |
|------|-----------------|
| `benchmark-results.json` | Full benchmark output + model score |
| `live-results.json` | Full live scan output + score |
| `cert-in-report-{target}.json` | CERT-In disclosure report (from live mode) |
| `state.json` | Pipeline state (for debugging) |

---

## Pipeline Steps

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

## Supported Providers

22 providers — run `python pipeline.py providers` to see all.

| Provider | ID | Key env var | Needs key? |
|----------|----|------------|------------|
| Ollama (local) | `ollama` | `OLLAMA_API_KEY` | No |
| LM Studio (local) | `lmstudio` | `LMSTUDIO_API_KEY` | No |
| llama.cpp (local) | `llamacpp` | `LLAMACPP_API_KEY` | No |
| vLLM | `vllm` | `VLLM_API_KEY` | No |
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

## Project Structure

```
cert-in-pipeline/
├── pipeline.py              # Main entry point
├── config.yaml              # Configuration (model, timeout, etc.)
├── providers.yaml           # 22 LLM provider configs
├── Dockerfile               # Kali Linux sandbox
├── docker-compose.yml
├── skills/                  # 9 LLM skill files (the benchmark)
├── pipeline/                # Engine & data models
├── tools/                   # Scanner wrappers (nuclei, nmap, etc.)
├── llm/                     # LiteLLM interface
├── scoring/                 # Evaluation & scoring
├── reporting/               # CERT-In formatter
└── scripts/                 # Docker run scripts
```

## Disclaimer

Only scan websites you have explicit authorization to test. Unauthorized scanning is illegal under the Information Technology Act, 2000 (India) and similar laws worldwide.

## License

MIT
