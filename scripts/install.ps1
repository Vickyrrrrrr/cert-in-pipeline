# CERT-In Pipeline — Windows Installer (PowerShell + uv)
# Installs: uv, Python deps, Go, nuclei, subfinder, httpx, ffuf, nmap, sqlmap
# Usage: .\scripts\install.ps1

$ErrorActionPreference = "Stop"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CERT-In Pipeline — Installer (Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ─── 1. Install uv ─────────────────────────────────────────────
Write-Host "`n[1/8] Installing uv (Python package manager)..." -ForegroundColor Cyan
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
} else {
    Write-Host "  uv already installed — skipping" -ForegroundColor Green
}

# ─── 2. Install Python dependencies ────────────────────────────
Write-Host "`n[2/8] Installing Python dependencies..." -ForegroundColor Cyan
uv sync
Write-Host "  Python deps installed" -ForegroundColor Green

# ─── 3. Install Go ─────────────────────────────────────────────
Write-Host "`n[3/8] Installing Go..." -ForegroundColor Cyan
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    winget install GoLang.Go --accept-package-agreements --accept-source-agreements 2>$null
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
} else {
    Write-Host "  Go already installed — skipping" -ForegroundColor Green
}

# ─── 4. Install nmap ───────────────────────────────────────────
Write-Host "`n[4/8] Installing Nmap..." -ForegroundColor Cyan
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    winget install Insecure.Nmap --accept-package-agreements --accept-source-agreements 2>$null
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
} else {
    Write-Host "  Nmap already installed — skipping" -ForegroundColor Green
}

# ─── 5. Install nuclei ─────────────────────────────────────────
Write-Host "`n[5/8] Installing nuclei..." -ForegroundColor Cyan
if (-not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>$null
} else {
    Write-Host "  nuclei already installed — skipping" -ForegroundColor Green
}

# ─── 6. Install subfinder ──────────────────────────────────────
Write-Host "`n[6/8] Installing subfinder..." -ForegroundColor Cyan
if (-not (Get-Command subfinder -ErrorAction SilentlyContinue)) {
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>$null
} else {
    Write-Host "  subfinder already installed — skipping" -ForegroundColor Green
}

# ─── 7. Install httpx + ffuf ───────────────────────────────────
Write-Host "`n[7/8] Installing httpx + ffuf..." -ForegroundColor Cyan
if (-not (Get-Command httpx -ErrorAction SilentlyContinue)) {
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>$null
} else {
    Write-Host "  httpx already installed — skipping" -ForegroundColor Green
}
if (-not (Get-Command ffuf -ErrorAction SilentlyContinue)) {
    go install -v github.com/ffuf/ffuf/v2@latest 2>$null
} else {
    Write-Host "  ffuf already installed — skipping" -ForegroundColor Green
}

# ─── 8. Install sqlmap + nuclei templates ──────────────────────
Write-Host "`n[8/8] Installing sqlmap + nuclei templates..." -ForegroundColor Cyan
uv pip install sqlmap 2>$null
if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    nuclei -update-templates 2>$null
    Write-Host "  Nuclei templates updated" -ForegroundColor Green
}

# ─── Add Go bin to PATH ────────────────────────────────────────
$goBin = "$env:USERPROFILE\go\bin"
if (($env:Path -split ";") -notcontains $goBin) {
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";$goBin", "User")
    $env:Path += ";$goBin"
}

# ─── Summary ───────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nInstalled tools:" -ForegroundColor Yellow
$tools = @{
    "uv"      = "uv"
    "python"  = "python"
    "go"      = "go"
    "nmap"    = "nmap"
    "nuclei"  = "nuclei"
    "subfinder" = "subfinder"
    "httpx"   = "httpx"
    "ffuf"    = "ffuf"
    "sqlmap"  = "sqlmap"
}

foreach ($name in $tools.Keys | Sort-Object) {
    $cmd = $tools[$name]
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  [OK] $name" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $name" -ForegroundColor Red
    }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Restart your terminal (to pick up new PATH entries)"
Write-Host "  2. Set your API key:"
Write-Host "     `$env:GLM_API_KEY = 'your-key'" -ForegroundColor White
Write-Host "  3. Run benchmark:"
Write-Host "     uv run pipeline.py benchmark --provider glm --model glm-5.2" -ForegroundColor White
Write-Host "  4. Run live scan:"
Write-Host "     uv run pipeline.py live --target example.com --provider glm --model glm-5.2" -ForegroundColor White
