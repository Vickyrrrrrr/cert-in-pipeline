# Install security tools for CERT-In Pipeline (Windows)

Write-Host "Installing CERT-In Pipeline tools..." -ForegroundColor Green

# Check for winget
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget not found. Please install from Microsoft Store." -ForegroundColor Red
    exit 1
}

# Install Go
Write-Host "`n[1/6] Installing Go..." -ForegroundColor Cyan
winget install GoLang.Go --accept-package-agreements --accept-source-agreements 2>$null
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# Install nmap
Write-Host "`n[2/6] Installing Nmap..." -ForegroundColor Cyan
winget install Insecure.Nmap --accept-package-agreements --accept-source-agreements 2>$null

# Install Python deps
Write-Host "`n[3/6] Installing Python dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt

# Install nuclei
Write-Host "`n[4/6] Installing nuclei..." -ForegroundColor Cyan
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>$null

# Install subfinder
Write-Host "`n[5/6] Installing subfinder..." -ForegroundColor Cyan
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>$null

# Install httpx (ProjectDiscovery)
Write-Host "`n[6/6] Installing httpx..." -ForegroundColor Cyan
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>$null

# Add Go bin to PATH
$goBin = "$env:USERPROFILE\go\bin"
if (($env:Path -split ";") -notcontains $goBin) {
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";$goBin", "User")
    $env:Path += ";$goBin"
}

# Install nuclei templates
Write-Host "`nDownloading nuclei templates..." -ForegroundColor Cyan
nuclei -update-templates 2>$null

Write-Host "`n=== Installation Complete ===" -ForegroundColor Green
Write-Host "`nInstalled tools:" -ForegroundColor Yellow
foreach ($tool in @("go", "nmap", "nuclei", "subfinder", "httpx", "python")) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  [OK] $tool -> $($found.Source)" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $tool" -ForegroundColor Red
    }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Restart your terminal (to pick up new PATH entries)"
Write-Host "  2. Run: python pipeline.py benchmark --model ollama/qwen2.5:7b"
