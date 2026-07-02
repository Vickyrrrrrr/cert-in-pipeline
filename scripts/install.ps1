# Argus Installer (Windows) — all tools, no manual setup needed
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/Vickyrrrrrr/argus/master/scripts/install.ps1 | powershell -c -

$ErrorActionPreference = "Stop"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Argus - Installer (Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Ensure we're in the repo directory
$repoDir = Join-Path $env:USERPROFILE 'argus'
if (-not (Test-Path (Join-Path $repoDir 'pipeline.py'))) {
    Write-Host "Cloning argus to $repoDir ..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/Vickyrrrrrr/argus.git $repoDir 2>$null
    if (-not (Test-Path (Join-Path $repoDir 'pipeline.py'))) {
        Write-Host "  Failed to clone repo" -ForegroundColor Red
        exit 1
    }
}
Set-Location $repoDir

$binDir = Join-Path $env:USERPROFILE 'bin'
$toolsDir = Join-Path $env:USERPROFILE 'tools'
foreach ($d in @($binDir, $toolsDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = $machinePath + ';' + $userPath + ';' + $binDir + ';' + $toolsDir
}

function Download-Tool($repo, $name, $pattern) {
    $exePath = Join-Path $binDir ($name + '.exe')
    if (Test-Path $exePath) { Write-Host "  $name already installed" -ForegroundColor Green; return }
    Write-Host "  Fetching $name..." -ForegroundColor Yellow
    $apiUrl = 'https://api.github.com/repos/' + $repo + '/releases/latest'
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'argus' } -TimeoutSec 30
    $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { Write-Host "  Could not find $name for Windows" -ForegroundColor Red; return }
    $zipPath = Join-Path $env:TEMP ($name + '.zip')
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    Expand-Archive -Path $zipPath -DestinationPath $binDir -Force
    Remove-Item $zipPath -Force
    if (Test-Path $exePath) { Write-Host "  [OK] $name" -ForegroundColor Green }
}

function Clone-Tool($repo, $dest, $name) {
    $destPath = Join-Path $toolsDir $dest
    if (Test-Path $destPath) { Write-Host "  $name already cloned" -ForegroundColor Green; return }
    Write-Host "  Cloning $name..." -ForegroundColor Yellow
    git clone --depth 1 "https://github.com/$repo.git" $destPath 2>$null
    if (Test-Path $destPath) { Write-Host "  [OK] $name" -ForegroundColor Green }
}

# ─── 1. uv ──────────────────────────────────────────────────────────
Write-Host "`n[1/8] uv (Python package manager)..." -ForegroundColor Cyan
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    Refresh-Path
} else { Write-Host "  uv already installed" -ForegroundColor Green }

# ─── 2. Python deps ─────────────────────────────────────────────────
Write-Host "`n[2/8] Python dependencies..." -ForegroundColor Cyan
uv sync
Write-Host "  Done" -ForegroundColor Green

# ─── 3. nmap ────────────────────────────────────────────────────────
Write-Host "`n[3/8] Nmap..." -ForegroundColor Cyan
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    winget install Insecure.Nmap --accept-package-agreements --accept-source-agreements 2>$null
    Refresh-Path
} else { Write-Host "  Nmap already installed" -ForegroundColor Green }

# ─── 4. Pre-compiled Go tools ───────────────────────────────────────
Write-Host "`n[4/8] nuclei, subfinder, httpx, ffuf..." -ForegroundColor Cyan
Download-Tool 'projectdiscovery/nuclei' 'nuclei' 'windows_amd64'
Download-Tool 'projectdiscovery/subfinder' 'subfinder' 'windows_amd64'
Download-Tool 'projectdiscovery/httpx' 'httpx' 'windows_amd64'
Download-Tool 'ffuf/ffuf' 'ffuf' 'windows_amd64'

# ─── 5. sqlmap (Python) ─────────────────────────────────────────────
Write-Host "`n[5/8] sqlmap..." -ForegroundColor Cyan
uv pip install sqlmap 2>$null
if (Get-Command sqlmap -ErrorAction SilentlyContinue) {
    Write-Host "  [OK] sqlmap" -ForegroundColor Green
} else {
    Clone-Tool 'sqlmapproject/sqlmap' 'sqlmap' 'sqlmap'
    $sqlmapDir = Join-Path $toolsDir 'sqlmap'
    if (Test-Path (Join-Path $sqlmapDir 'sqlmap.py')) {
        Write-Host "  [OK] sqlmap (run: python ~/tools/sqlmap/sqlmap.py)" -ForegroundColor Green
    }
}

# ─── 6. nikto (Perl) ────────────────────────────────────────────────
Write-Host "`n[6/8] nikto..." -ForegroundColor Cyan
Clone-Tool 'sullo/nikto' 'nikto' 'nikto'
$niktoDir = Join-Path $toolsDir 'nikto'
if (Test-Path (Join-Path $niktoDir 'program.pl')) {
    Write-Host "  [OK] nikto (needs Perl: perl ~/tools/nikto/program.pl)" -ForegroundColor Green
}

# ─── 7. ExploitDB / searchsploit ────────────────────────────────────
Write-Host "`n[7/8] ExploitDB (searchsploit)..." -ForegroundColor Cyan
Clone-Tool 'offensive-security/exploitdb' 'exploitdb' 'ExploitDB'
$exploitdbDir = Join-Path $toolsDir 'exploitdb'
if (Test-Path (Join-Path $exploitdbDir 'searchsploit.ps1')) {
    Write-Host "  [OK] searchsploit" -ForegroundColor Green
} elseif (Test-Path (Join-Path $exploitdbDir 'searchsploit')) {
    Write-Host "  [OK] searchsploit (bash script)" -ForegroundColor Green
}

# ─── 8. whatweb + wpscan (Ruby) ─────────────────────────────────────
Write-Host "`n[8/8] whatweb + wpscan (need Ruby)..." -ForegroundColor Cyan
$hasRuby = Get-Command ruby -ErrorAction SilentlyContinue
if ($hasRuby) {
    Clone-Tool 'urbanadventurer/WhatWeb' 'whatweb' 'WhatWeb'
    & gem install wpscan 2>$null
    if (Get-Command wpscan -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] wpscan" -ForegroundColor Green
    }
    Write-Host "  [OK] whatweb (cloned)" -ForegroundColor Green
} else {
    Clone-Tool 'urbanadventurer/WhatWeb' 'whatweb' 'WhatWeb'
    Write-Host "  whatweb cloned (install Ruby to use: ruby ~/tools/whatweb/whatweb.rb)" -ForegroundColor Yellow
    Write-Host "  wpscan skipped (needs Ruby: gem install wpscan)" -ForegroundColor Yellow
}

# ─── Add to PATH ────────────────────────────────────────────────────
foreach ($d in @($binDir, $toolsDir)) {
    if (($env:Path -split ';') -notcontains $d) {
        $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        [Environment]::SetEnvironmentVariable('Path', $currentPath + ';' + $d, 'User')
        $env:Path = $env:Path + ';' + $d
    }
}

# ─── Update nuclei templates ────────────────────────────────────────
$nucleiExe = Join-Path $binDir 'nuclei.exe'
if (Test-Path $nucleiExe) {
    & $nucleiExe -update-templates 2>$null
    Write-Host "`n  Nuclei templates updated" -ForegroundColor Green
}

# ─── Summary ────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nInstalled tools:" -ForegroundColor Yellow
$checkTools = @('uv', 'nmap', 'nuclei', 'subfinder', 'httpx', 'ffuf', 'sqlmap')
foreach ($t in $checkTools) {
    $found = Get-Command $t -ErrorAction SilentlyContinue
    if ($found) { Write-Host "  [OK] $t" -ForegroundColor Green }
    else {
        $exePath = Join-Path $binDir ($t + '.exe')
        if (Test-Path $exePath) { Write-Host "  [OK] $t (~/bin)" -ForegroundColor Green }
        else { Write-Host "  [MISSING] $t" -ForegroundColor Red }
    }
}

# Check cloned tools
$clonedTools = @{
    'nikto' = Join-Path $toolsDir 'nikto\program.pl'
    'exploitdb' = Join-Path $toolsDir 'exploitdb\searchsploit'
    'whatweb' = Join-Path $toolsDir 'whatweb\whatweb.rb'
}
foreach ($name in $clonedTools.Keys) {
    if (Test-Path $clonedTools[$name]) { Write-Host "  [OK] $name (~/tools)" -ForegroundColor Green }
    else { Write-Host "  [MISSING] $name" -ForegroundColor Red }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Restart your terminal"
Write-Host '  2. $env:GLM_API_KEY = "your-key"'
Write-Host '  3. uv run python knowledge/seed.py  (build RAG knowledge base)'
Write-Host '  4. uv run python pipeline.py swarm --target example.com --provider glm --model glm-5-turbo'
