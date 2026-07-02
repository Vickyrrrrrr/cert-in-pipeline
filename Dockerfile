FROM kalilinux/kali-rolling

LABEL maintainer="CERT-In Pipeline"
LABEL description="Sandboxed environment for security scanning pipeline"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install system packages + security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    nikto \
    dirb \
    gobuster \
    whois \
    dnsutils \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install ffuf
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Download nuclei templates
RUN nuclei -update-templates

# Set up Python environment
WORKDIR /pipeline
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# Copy pipeline code
COPY . .

# Create results directory
RUN mkdir -p /pipeline/results

# Default command — run the pipeline
ENTRYPOINT ["python3", "pipeline.py"]
CMD ["--help"]
