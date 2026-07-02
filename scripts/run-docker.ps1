# Run the CERT-In Pipeline in Docker Sandbox (Windows)

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [string]$Model = "glm-5.2",
    
    [string]$Provider = "glm",
    
    [string]$ApiKey = $env:GLM_API_KEY,
    
    [string]$ApiBase = "https://api.z.ai/api/paas/v4"
)

if (-not $ApiKey -and $Provider -ne "ollama") {
    Write-Host "Error: API key not set." -ForegroundColor Red
    Write-Host "Set it: `$env:GLM_API_KEY = 'your-key'" -ForegroundColor Yellow
    Write-Host "Or pass: .\scripts\run-docker.ps1 -Target example.com -ApiKey your-key" -ForegroundColor Yellow
    exit 1
}

Write-Host "Building Docker image..." -ForegroundColor Cyan
docker build -t cert-in-pipeline .

Write-Host "`nRunning pipeline in sandbox..." -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Provider: $Provider" -ForegroundColor Yellow
Write-Host "Model: $Model" -ForegroundColor Yellow
Write-Host ""

docker run --rm `
    -v "${PWD}\results:/pipeline/results" `
    -v "${PWD}\config.yaml:/pipeline/config.yaml:ro" `
    -v "${PWD}\skills:/pipeline/skills:ro" `
    -e "GLM_API_KEY=$ApiKey" `
    -e "OPENAI_API_KEY=$ApiKey" `
    --add-host=host.docker.internal:host-gateway `
    cert-in-pipeline `
    live --target $Target --provider $Provider --model $Model --api-base $ApiBase --api-key $ApiKey --output /pipeline/results

Write-Host "`nResults saved to .\results\" -ForegroundColor Green
