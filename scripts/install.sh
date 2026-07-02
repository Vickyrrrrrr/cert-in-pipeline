#!/bin/bash
# CERT-In Pipeline — One-liner install (Linux/macOS)
#   curl -sSL https://raw.githubusercontent.com/Vickyrrrrrr/cert-in-pipeline/main/scripts/install.sh | bash
set -e

REPO="Vickyrrrrrr/cert-in-pipeline"
BIN="${HOME}/.local/bin"
mkdir -p "$BIN"

echo "========================================"
echo "  CERT-In Pipeline — Quick Install"
echo "========================================"

# ─── 1. Install uv ──────────────────────────────────────────────────
echo -e "\n[1/5] Installing uv..."
if ! command -v uv &>/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
echo "  uv $(uv --version 2>/dev/null || echo 'ok')"

# ─── 2. Clone / pull repo ──────────────────────────────────────────
echo -e "\n[2/5] Fetching cert-in-pipeline..."
TARGET="${HOME}/cert-in-pipeline"
if [ -d "$TARGET" ]; then
  echo "  Already cloned at $TARGET"
else
  git clone --depth 1 "https://github.com/${REPO}.git" "$TARGET"
fi
cd "$TARGET"

# ─── 3. Python deps ────────────────────────────────────────────────
echo -e "\n[3/5] Installing Python dependencies..."
uv sync
echo "  Python deps done"

# ─── 4. Pre-compiled security tools (no Go needed) ─────────────────
echo -e "\n[4/5] Downloading nuclei, subfinder, httpx, ffuf..."
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
download() {
  local repo="$1" name="$2" pattern="$3"
  local exe="${BIN}/${name}"
  [ -f "$exe" ] && echo "  $name already installed" && return
  echo "  Fetching $name..."
  local url=$(curl -sL "https://api.github.com/repos/${repo}/releases/latest" \
    -H "User-Agent: cert-in-pipeline" \
    | grep browser_download_url | grep -E "$pattern" | head -1 | cut -d'"' -f4)
  [ -z "$url" ] && echo "  [SKIP] $name — no binary for ${OS}_${ARCH}" && return
  local tmp="/tmp/${name}.tar.gz"
  curl -sL "$url" -o "$tmp"
  tar -xzf "$tmp" -C "$BIN" 2>/dev/null || unzip -o "$tmp" -d "$BIN" 2>/dev/null || true
  chmod +x "$exe" 2>/dev/null || true
  rm -f "$tmp"
  [ -f "$exe" ] && echo "  [OK] $name" || echo "  [FAIL] $name"
}
download "projectdiscovery/nuclei"   "nuclei"    "${OS}_${ARCH}.*\.tar\.gz"
download "projectdiscovery/subfinder" "subfinder" "${OS}_${ARCH}.*\.tar\.gz"
download "projectdiscovery/httpx"    "httpx"     "${OS}_${ARCH}.*\.tar\.gz"
download "ffuf/ffuf"                 "ffuf"      "${OS}_${ARCH}.*\.tar\.gz"
export PATH="${BIN}:$PATH"

# ─── 5. Nmap + sqlmap + nuclei templates ───────────────────────────
echo -e "\n[5/5] Finishing up..."
if ! command -v nmap &>/dev/null; then
  if command -v brew &>/dev/null; then
    brew install nmap 2>/dev/null || true
  elif command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq nmap 2>/dev/null || true
  fi
fi
uv pip install sqlmap --system 2>/dev/null || true
command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true

# ─── Summary ────────────────────────────────────────────────────────
echo -e "\n========================================"
echo "  ✓ Installation Complete"
echo "========================================"
echo ""
for tool in uv python3 nuclei subfinder httpx ffuf nmap sqlmap; do
  command -v "$tool" &>/dev/null \
    && echo "  [OK] $tool" \
    || echo "  [MISSING] $tool"
done
echo ""
echo "Next:"
echo "  cd ~/cert-in-pipeline"
echo '  export API_KEY="your-key"'
echo "  uv run pipeline.py agent --target example.com --provider glm --model glm-5-turbo"
