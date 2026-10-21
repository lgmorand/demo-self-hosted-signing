#!/usr/bin/env bash
# Deletes the demo resource group and purges the soft-deleted Key Vault so the name is released.
set -euo pipefail

RESOURCE_GROUP="${1:-rg-skr-demo}"
VAULT="$(az keyvault list --resource-group "$RESOURCE_GROUP" --query '[0].name' -o tsv 2>/dev/null || true)"
LOCATION="$(az keyvault list --resource-group "$RESOURCE_GROUP" --query '[0].location' -o tsv 2>/dev/null || true)"

echo "Deleting resource group $RESOURCE_GROUP..."
az group delete --name "$RESOURCE_GROUP" --yes

if [ -n "$VAULT" ]; then
  echo "Purging soft-deleted vault $VAULT..."
  az keyvault purge --name "$VAULT" --location "$LOCATION" 2>/dev/null || true
fi
rm -f "$(cd "$(dirname "$0")/.." && pwd)/.demo/deployment.json"
echo "Done."
