#!/bin/bash

# Quick start script for OAuth Kit + Keycloak
set -e

echo "🚀 Starting Keycloak for OAuth Kit..."

# Auto-detect container runtime
if command -v podman > /dev/null 2>&1 && podman info > /dev/null 2>&1; then
    COMPOSE_CMD="podman-compose"
    if ! command -v podman-compose > /dev/null 2>&1; then
        COMPOSE_CMD="podman compose"
    fi
elif command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
    if ! command -v docker-compose > /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    fi
else
    echo "❌ Docker or Podman required"
    exit 1
fi

cd "$(dirname "$0")"

# Start Keycloak
$COMPOSE_CMD -f dev-docker-compose.yaml up -d

# Wait and setup
echo "⏳ Waiting for Keycloak..."
until curl -s http://localhost:8080 > /dev/null 2>&1; do
    sleep 3
done

echo "🔧 Setting up test realm..."
./setup-keycloak.sh

echo ""
echo "✅ Ready! Keycloak running at http://localhost:8080"
echo "📋 Test realm: test"
echo "🔑 Client ID: example-app"
echo "👤 Test user: admin/password"
echo ""
echo "🧪 Run tests: cd .. && swift test"
echo "🛑 Stop: $COMPOSE_CMD -f infra/dev-docker-compose.yaml down"