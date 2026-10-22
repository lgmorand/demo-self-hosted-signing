#!/usr/bin/env bash
# Deploys the Secure Key Release demo (Key Vault + exportable key + Confidential VM running the token service).
# Usage: ./scripts/deploy.sh [resource-group] [location]
set -euo pipefail

echo "WARNING: DEMO ONLY - no support, not for production. This creates billable Azure resources; delete them with scripts/destroy.sh." >&2

RESOURCE_GROUP="${1:-rg-skr-demo}"
LOCATION="${2:-westeurope}"
VM_SIZE="${VM_SIZE:-Standard_DC2as_v5}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="$ROOT/.demo"
mkdir -p "$STATE_DIR"

KEY_PATH="$STATE_DIR/id_ed25519"
[ -f "$KEY_PATH" ] || ssh-keygen -t ed25519 -N '' -f "$KEY_PATH" -C skr-demo >/dev/null
SSH_PUBLIC_KEY="$(cat "$KEY_PATH.pub")"

ALLOWED_SOURCE_IP="${ALLOWED_SOURCE_IP:-$(curl -fsS https://api.ipify.org)}"
echo "Allowing inbound traffic from your public IP: $ALLOWED_SOURCE_IP"

READER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"

echo "Creating resource group $RESOURCE_GROUP in $LOCATION..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

echo "Deploying infrastructure (about 5 minutes)..."
OUTPUTS="$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file "$ROOT/infra/main.bicep" \
  --parameters location="$LOCATION" vmSize="$VM_SIZE" sshPublicKey="$SSH_PUBLIC_KEY" \
               allowedSourceIp="$ALLOWED_SOURCE_IP" readerObjectId="$READER_OBJECT_ID" \
  --query properties.outputs -o json)"

field() { echo "$OUTPUTS" | python3 -c "import json,sys; print(json.load(sys.stdin)['$1']['value'])" 2>/dev/null \
  || echo "$OUTPUTS" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s)['$1'].value))"; }

VAULT="$(field vaultName)"; KEY="$(field keyName)"; URL="$(field serviceUrl)"; IP="$(field vmPublicIp)"
cat > "$STATE_DIR/deployment.json" <<EOF
{ "resourceGroup": "$RESOURCE_GROUP", "vaultName": "$VAULT", "keyName": "$KEY", "serviceUrl": "$URL", "sshCommand": "ssh -i $KEY_PATH azureuser@$IP" }
EOF

echo
echo "Deployed."
echo "  Key Vault : $VAULT (key '$KEY')"
echo "  Service   : $URL"
echo "  SSH       : ssh -i $KEY_PATH azureuser@$IP"
echo
echo "The VM is still installing Node.js and building the attestation helper (about 5 more minutes)."
echo "Then run:  node client/demo.js $URL --vault $VAULT --key $KEY"
echo "Or open the web UI in a browser: $URL/"
