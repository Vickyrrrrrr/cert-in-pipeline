#!/bin/bash
# Run the CERT-In Pipeline in Docker Sandbox (Linux/macOS)

set -e

TARGET=${1:?"Usage: ./run-docker.sh <target> [provider] [model] [api-key] [api-base]"}
PROVIDER=${2:-"glm"}
MODEL=${3:-"glm-5.2"}
API_KEY=${4:-$GLM_API_KEY}
API_BASE=${5:-"https://api.z.ai/api/paas/v4"}

if [ -z "$API_KEY" ] && [ "$PROVIDER" != "ollama" ]; then
    echo "Error: API key not set."
    echo "Set GLM_API_KEY env var or pass as 4th argument."
    exit 1
fi

echo "Building Docker image..."
docker build -t cert-in-pipeline .

echo ""
echo "Running pipeline in sandbox..."
echo "Target: $TARGET"
echo "Provider: $PROVIDER"
echo "Model: $MODEL"
echo ""

docker run --rm \
    -v "$(pwd)/results:/pipeline/results" \
    -v "$(pwd)/config.yaml:/pipeline/config.yaml:ro" \
    -v "$(pwd)/skills:/pipeline/skills:ro" \
    -e "GLM_API_KEY=$API_KEY" \
    -e "OPENAI_API_KEY=$API_KEY" \
    --add-host=host.docker.internal:host-gateway \
    cert-in-pipeline \
    live --target "$TARGET" --provider "$PROVIDER" --model "$MODEL" --api-base "$API_BASE" --api-key "$API_KEY" --output /pipeline/results

echo ""
echo "Results saved to ./results/"
