<#
.SYNOPSIS
  Deletes the demo resource group and purges the soft-deleted Key Vault so the name is released.
#>
[CmdletBinding()]
param([string]$ResourceGroup = 'rg-skr-demo')

$ErrorActionPreference = 'Stop'
$vault = az keyvault list --resource-group $ResourceGroup --query '[0].{name:name,location:location}' -o json 2>$null | ConvertFrom-Json

Write-Host "Deleting resource group $ResourceGroup..."
az group delete --name $ResourceGroup --yes

if ($vault) {
  Write-Host "Purging soft-deleted vault $($vault.name)..."
  az keyvault purge --name $vault.name --location $vault.location 2>$null
}
Remove-Item (Join-Path (Split-Path -Parent $PSScriptRoot) '.demo/deployment.json') -ErrorAction SilentlyContinue
Write-Host 'Done.' -ForegroundColor Green
