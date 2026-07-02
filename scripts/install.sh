#!/bin/bash
# CERT-In Pipeline — Linux/macOS Installer (uv)
# Installs: uv, Python deps, Go, nuclei, subfinder, httpx, ffuf, nmap, sqlmap
# Usage: chmod +x scripts/install.sh && ./scripts/install.sh

set -e

echo "========================================"
echo "  CERT-In Pipeline — Installer (Linux)"
echo "========================================"

# ─── 1. Install uv ─────────────────────────────────────────────
echo -e "\n[1/8] Installing uv (Python package manager)..."
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "  uv already installed — skipping"
fi

# ─── 2. Install Python dependencies ────────────────────────────
echo -e "\n[2/8] Installing Python dependencies..."
uv sync
echo "  Python deps installed"

# ─── 3. Install Go ─────────────────────────────────────────────
echo -e "\n[3/8] Installing Go..."
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    grep -q '/usr/local/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
else
    echo "  Go already installed — skipping"
fi

# ─── 4. Install nmap ───────────────────────────────────────────
echo -e "\n[4/8] Installing Nmap..."
if ! command -v nmap &> /dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq nmap
else
    echo "  Nmap already installed — skipping"
fi

# ─── 5. Install nuclei ─────────────────────────────────────────
echo -e "\n[5/8] Installing nuclei..."
if ! command -v nuclei &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
else
    echo "  nuclei already installed — skipping"
fi

# ─── 6. Install subfinder ──────────────────────────────────────
echo -e "\n[6/8] Installing subfinder..."
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
    echo "  subfinder already installed — skipping"
fi

# ─── 7. Install httpx + ffuf ───────────────────────────────────
echo -e "\n[7/8] Installing httpx + ffuf..."
if ! command -v httpx &> /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    echo "  httpx already installed — skipping"
fi
if ! command -v ffuf &> /dev/null; then
    go install -v github.com/ffuf/ffuf/v2@latest
else
    echo "  ffuf already installed — skipping"
fi

# ─── 8. Install sqlmap + nuclei templates ──────────────────────
echo -e "\n[8/8] Installing sqlmap + nuclei templates..."
uv pip install sqlmap 2>/dev/null || pip install sqlmap 2>/dev/null
if command -v nuclei &> /dev/null; then
    nuclei -update-templates
    echo "  Nuclei templates updated"
fi

# ─── Summary ───────────────────────────────────────────────────
echo -e "\n========================================"
echo "  Installation Complete"
echo "========================================"

echo -e "\nInstalled tools:"
for tool in uv python go nmap nuclei subfinder httpx ffuf sqlmap; do
    if command -v $tool &> /dev/null; then
        echo "  [OK] $tool"
    else
        echo "  [MISSING] $tool"
    fi
done

echo -e "\nNext steps:"
echo "  1. Restart your terminal (to pick up new PATH entries)"
echo "  2. Set your API key:"
echo "     export GLM_API_KEY='your-key'"
echo "  3. Run benchmark:"
echo "     uv run pipeline.py benchmark --provider glm --model glm-5.2"
echo "  4. Run live scan:"
echo "     uv run pipeline.py live --target example.com --provider glm --model glm-5.2"
