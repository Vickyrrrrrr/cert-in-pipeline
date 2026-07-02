#!/bin/bash
# Install security tools for CERT-In Pipeline (Linux)

set -e

echo "Installing CERT-In Pipeline tools..."

# Install Go
if ! command -v go &> /dev/null; then
    echo "[1/6] Installing Go..."
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
fi

# Install nmap
echo "[2/6] Installing Nmap..."
sudo apt-get update -qq && sudo apt-get install -y -qq nmap

# Install Python deps
echo "[3/6] Installing Python dependencies..."
pip install -r requirements.txt

# Install nuclei
echo "[4/6] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install subfinder
echo "[5/6] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install httpx (ProjectDiscovery)
echo "[6/6] Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei templates
echo "Downloading nuclei templates..."
nuclei -update-templates

echo "=== Installation Complete ==="
echo "Installed tools:"
for tool in go nmap nuclei subfinder httpx python; do
    if command -v $tool &> /dev/null; then
        echo "  [OK] $tool -> $(which $tool)"
    else
        echo "  [MISSING] $tool"
    fi
done

echo "Next steps:"
echo "  python pipeline.py benchmark --model ollama/qwen2.5:7b"
