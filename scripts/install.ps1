# CERT-In Pipeline - Windows Installer (pre-compiled binaries, no Go needed)
# Usage: .\scripts\install.ps1

$ErrorActionPreference = "Stop"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CERT-In Pipeline - Installer (Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$binDir = Join-Path $env:USERPROFILE 'bin'
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = $machinePath + ';' + $userPath + ';' + $binDir
}

function Download-Tool($repo, $name, $pattern) {
    $exePath = Join-Path $binDir ($name + '.exe')
    if (Test-Path $exePath) {
        Write-Host "  $name already installed" -ForegroundColor Green
        return
    }
    Write-Host "  Fetching latest $name..." -ForegroundColor Yellow
    $apiUrl = 'https://api.github.com/repos/' + $repo + '/releases/latest'
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'cert-in-pipeline' } -TimeoutSec 30
    $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) {
        Write-Host "  Could not find $name binary for Windows" -ForegroundColor Red
        return
    }
    Write-Host "  Downloading $name..." -ForegroundColor Yellow
    $zipPath = Join-Path $env:TEMP ($name + '.zip')
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    Expand-Archive -Path $zipPath -DestinationPath $binDir -Force
    Remove-Item $zipPath -Force
    if (Test-Path $exePath) {
        Write-Host "  [OK] $name installed" -ForegroundColor Green
    }
}

# 1. Install uv
Write-Host ""
Write-Host "[1/5] Installing uv..." -ForegroundColor Cyan
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    Refresh-Path
} else {
    Write-Host "  uv already installed" -ForegroundColor Green
}

# 2. Install Python dependencies
Write-Host ""
Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor Cyan
uv sync
Write-Host "  Done" -ForegroundColor Green

# 3. Install nmap
Write-Host ""
Write-Host "[3/5] Installing Nmap..." -ForegroundColor Cyan
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    winget install Insecure.Nmap --accept-package-agreements --accept-source-agreements 2>$null
    Refresh-Path
} else {
    Write-Host "  Nmap already installed" -ForegroundColor Green
}

# 4. Download pre-compiled security tools (fast - no Go compilation needed)
Write-Host ""
Write-Host "[4/5] Downloading nuclei, subfinder, httpx, ffuf..." -ForegroundColor Cyan
Download-Tool 'projectdiscovery/nuclei' 'nuclei' 'windows_amd64'
Download-Tool 'projectdiscovery/subfinder' 'subfinder' 'windows_amd64'
Download-Tool 'projectdiscovery/httpx' 'httpx' 'windows_amd64'
Download-Tool 'ffuf/ffuf' 'ffuf' 'windows_amd64'

# Add bin dir to PATH
if (($env:Path -split ';') -notcontains $binDir) {
    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    [Environment]::SetEnvironmentVariable('Path', $currentPath + ';' + $binDir, 'User')
    $env:Path = $env:Path + ';' + $binDir
}

# 5. Update nuclei templates + install sqlmap
Write-Host ""
Write-Host "[5/5] Updating nuclei templates + installing sqlmap..." -ForegroundColor Cyan
$nucleiExe = Join-Path $binDir 'nuclei.exe'
if (Test-Path $nucleiExe) {
    & $nucleiExe -update-templates 2>$null
    Write-Host "  Nuclei templates updated" -ForegroundColor Green
}
uv pip install sqlmap --system 2>$null
Write-Host "  sqlmap installed" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Installed tools:" -ForegroundColor Yellow
$checkTools = @('uv', 'nmap', 'nuclei', 'subfinder', 'httpx', 'ffuf')
foreach ($t in $checkTools) {
    $found = Get-Command $t -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  [OK] $t" -ForegroundColor Green
    } else {
        $exePath = Join-Path $binDir ($t + '.exe')
        if (Test-Path $exePath) {
            Write-Host "  [OK] $t (in ~/bin)" -ForegroundColor Green
        } else {
            Write-Host "  [MISSING] $t" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Restart your terminal"
Write-Host '  2. $env:GLM_API_KEY = "your-key"'
Write-Host '  3. uv run pipeline.py live --target example.com --provider glm --model glm-5.2'
