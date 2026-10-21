<#
.SYNOPSIS
  Deploys the Secure Key Release demo (Key Vault + exportable key + Confidential VM running the token service).
.EXAMPLE
  ./scripts/deploy.ps1
  ./scripts/deploy.ps1 -Location northeurope -ResourceGroup my-skr-demo
#>
[CmdletBinding()]
param(
  [string]$ResourceGroup = 'rg-skr-demo',
  [string]$Location = 'westeurope',
  [string]$VmSize = 'Standard_DC2as_v5',
  [string]$AllowedSourceIp
)

$ErrorActionPreference = 'Stop'
Write-Warning 'DEMO ONLY: no support, not for production. This creates billable Azure resources; delete them with scripts/destroy.ps1.'
$root = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $root '.demo'
New-Item -ItemType Directory -Force $stateDir | Out-Null

# SSH key dedicated to the demo (kept in the git-ignored .demo folder).
$keyPath = Join-Path $stateDir 'id_ed25519'
if (-not (Test-Path $keyPath)) {
  ssh-keygen -t ed25519 -N '""' -f $keyPath -C 'skr-demo' | Out-Null
}
$sshPublicKey = (Get-Content "$keyPath.pub" -Raw).Trim()

if (-not $AllowedSourceIp) {
  $AllowedSourceIp = (Invoke-RestMethod 'https://api.ipify.org').Trim()
  Write-Host "Allowing inbound traffic from your public IP: $AllowedSourceIp"
}

$readerObjectId = az ad signed-in-user show --query id -o tsv 2>$null

Write-Host "Creating resource group $ResourceGroup in $Location..."
az group create --name $ResourceGroup --location $Location --output none

Write-Host 'Deploying infrastructure (about 5 minutes)...'
$outputs = az deployment group create `
  --resource-group $ResourceGroup `
  --template-file (Join-Path $root 'infra/main.bicep') `
  --parameters location=$Location vmSize=$VmSize sshPublicKey="$sshPublicKey" allowedSourceIp=$AllowedSourceIp readerObjectId=$readerObjectId `
  --query properties.outputs -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Deployment failed.' }

$state = [ordered]@{
  resourceGroup = $ResourceGroup
  vaultName     = $outputs.vaultName.value
  keyName       = $outputs.keyName.value
  serviceUrl    = $outputs.serviceUrl.value
  sshCommand    = "ssh -i `"$keyPath`" azureuser@$($outputs.vmPublicIp.value)"
}
$state | ConvertTo-Json | Set-Content (Join-Path $stateDir 'deployment.json')

Write-Host ''
Write-Host 'Deployed.' -ForegroundColor Green
Write-Host "  Key Vault : $($state.vaultName) (key '$($state.keyName)')"
Write-Host "  Service   : $($state.serviceUrl)"
Write-Host "  SSH       : $($state.sshCommand)"
Write-Host ''
Write-Host 'The VM is still installing Node.js and building the attestation helper (about 5 more minutes).'
Write-Host "Then run:  node client/demo.js $($state.serviceUrl) --vault $($state.vaultName) --key $($state.keyName)"
