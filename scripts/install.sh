#!/bin/bash
# Argus — One-liner install (Linux/macOS)
#   curl -sSL https://raw.githubusercontent.com/Vickyrrrrrr/argus/master/scripts/install.sh | bash
set -e

BIN="${HOME}/.local/bin"
TOOLS="${HOME}/tools"
mkdir -p "$BIN" "$TOOLS"

echo "========================================"
echo "  Argus — Quick Install"
echo "========================================"

# ─── 1. uv ──────────────────────────────────────────────────────────
echo -e "\n[1/8] Installing uv..."
if ! command -v uv &>/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
echo "  uv $(uv --version 2>/dev/null || echo 'ok')"

# ─── 2. Clone repo ──────────────────────────────────────────────────
echo -e "\n[2/8] Fetching argus..."
TARGET="${HOME}/argus"
if [ -d "$TARGET" ]; then
  echo "  Already cloned at $TARGET"
else
  git clone --depth 1 https://github.com/Vickyrrrrrr/argus.git "$TARGET"
fi
cd "$TARGET"

# ─── 3. Python deps ─────────────────────────────────────────────────
echo -e "\n[3/8] Installing Python dependencies..."
uv sync
echo "  Python deps done"

# ─── 4. System tools (nmap, nikto, whatweb, ruby) ──────────────────
echo -e "\n[4/8] Installing system packages..."
if command -v apt-get &>/dev/null; then
  sudo apt-get update -qq && sudo apt-get install -y -qq nmap nikto whatweb ruby 2>/dev/null || true
elif command -v brew &>/dev/null; then
  brew install nmap nikto whatweb ruby 2>/dev/null || true
elif command -v yum &>/dev/null; then
  sudo yum install -y -q nmap nikto whatweb ruby 2>/dev/null || true
fi
echo "  System packages done"

# ─── 5. Pre-compiled Go tools ───────────────────────────────────────
echo -e "\n[5/8] Downloading nuclei, subfinder, httpx, ffuf..."
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
    -H "User-Agent: argus" \
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

# ─── 6. sqlmap ──────────────────────────────────────────────────────
echo -e "\n[6/8] Installing sqlmap..."
if ! command -v sqlmap &>/dev/null; then
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$TOOLS/sqlmap" 2>/dev/null || true
  ln -sf "$TOOLS/sqlmap/sqlmap.py" "$BIN/sqlmap" 2>/dev/null || true
fi
echo "  [OK] sqlmap"

# ─── 7. ExploitDB / searchsploit ────────────────────────────────────
echo -e "\n[7/8] Installing ExploitDB (searchsploit)..."
if ! command -v searchsploit &>/dev/null; then
  git clone --depth 1 https://github.com/offensive-security/exploitdb.git "$TOOLS/exploitdb" 2>/dev/null || true
  ln -sf "$TOOLS/exploitdb/searchsploit" "$BIN/searchsploit" 2>/dev/null || true
fi
echo "  [OK] searchsploit"

# ─── 8. wpscan (Ruby gem) ───────────────────────────────────────────
echo -e "\n[8/8] Installing wpscan..."
if command -v gem &>/dev/null; then
  gem install wpscan 2>/dev/null || true
  echo "  [OK] wpscan"
else
  echo "  [SKIP] wpscan (needs Ruby: gem install wpscan)"
fi

# ─── Nuclei templates ───────────────────────────────────────────────
command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true

# ─── Summary ────────────────────────────────────────────────────────
echo -e "\n========================================"
echo "  ✓ Installation Complete"
echo "========================================"
echo ""
for tool in uv python3 nuclei subfinder httpx ffuf nmap sqlmap nikto whatweb searchsploit wpscan; do
  command -v "$tool" &>/dev/null \
    && echo "  [OK] $tool" \
    || echo "  [MISSING] $tool"
done
echo ""
echo "Next:"
echo "  cd ~/argus"
echo "  uv run python knowledge/seed.py"
echo '  export API_KEY="your-key"'
echo "  uv run python pipeline.py swarm --target example.com --provider glm --model glm-5-turbo"
