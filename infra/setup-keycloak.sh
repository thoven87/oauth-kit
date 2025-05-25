#!/bin/bash

# Simple Keycloak setup script - imports keycloak-realm.json
set -e

KEYCLOAK_URL=${KEYCLOAK_URL:-"http://localhost:8080"}

echo "Setting up Keycloak at $KEYCLOAK_URL..."

# Wait for Keycloak to be ready
echo "Waiting for Keycloak..."
until curl -s "$KEYCLOAK_URL" > /dev/null 2>&1; do
    echo "..."
    sleep 3
done

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" | \
    grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Import realm
curl -X POST "$KEYCLOAK_URL/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d @keycloak-realm.json

# Verify
curl -f "$KEYCLOAK_URL/realms/test/.well-known/openid-configuration" > /dev/null

echo "✅ Keycloak ready!"
echo "Test realm: http://localhost:8080/realms/test"