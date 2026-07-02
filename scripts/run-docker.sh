#!/bin/bash
# Run the CERT-In Pipeline in Docker Sandbox (Linux/macOS)

set -e

TARGET=${1:?"Usage: ./run-docker.sh <target-domain> [model] [api-key] [api-base]"}
MODEL=${2:-"openai/glm-4-flash"}
API_KEY=${3:-$GLM_API_KEY}
API_BASE=${4:-"https://api.z.ai/api/paas/v4"}

if [ -z "$API_KEY" ]; then
    echo "Error: API key not set."
    echo "Set GLM_API_KEY env var or pass as 3rd argument."
    exit 1
fi

echo "Building Docker image..."
docker build -t cert-in-pipeline .

echo ""
echo "Running pipeline in sandbox..."
echo "Target: $TARGET"
echo "Model: $MODEL"
echo ""

docker run --rm \
    -v "$(pwd)/results:/pipeline/results" \
    -v "$(pwd)/config.yaml:/pipeline/config.yaml:ro" \
    -v "$(pwd)/skills:/pipeline/skills:ro" \
    -e "OPENAI_API_KEY=$API_KEY" \
    -e "OPENAI_API_BASE=$API_BASE" \
    --add-host=host.docker.internal:host-gateway \
    cert-in-pipeline \
    live --target "$TARGET" --model "$MODEL" --api-base "$API_BASE" --api-key "$API_KEY" --output /pipeline/results

echo ""
echo "Results saved to ./results/"
echo "CERT-In report: ./results/cert-in-report-$(echo $TARGET | tr '.' '-').json"
