// Secure Key Release demo: a Confidential VM exports a Key Vault key, caches it in memory and signs JWTs.
targetScope = 'resourceGroup'

@description('Azure region. It must offer AMD SEV-SNP confidential VMs (DCasv5) and you need quota for them.')
param location string = resourceGroup().location

@description('Prefix used to name resources.')
@minLength(2)
@maxLength(10)
param namePrefix string = 'skrdemo'

@description('VM size. Must be an AMD SEV-SNP confidential VM size (DCasv5 / DCadsv5).')
param vmSize string = 'Standard_DC2as_v5'

@description('SSH public key for the "azureuser" admin account.')
param sshPublicKey string

@description('Public IP (or CIDR) allowed to reach SSH (22) and the token service (8080). Use your own address, never "*".')
param allowedSourceIp string

@description('Optional. Object id of the user running the demo; grants read access to the key metadata so the client can compare thumbprints. Leave empty to skip.')
param readerObjectId string = ''

@description('Name of the exportable key.')
param keyName string = 'token-signing-key'

@description('Admin user created on the VM (SSH key authentication only).')
param adminUsername string = 'azureuser'

var suffix = uniqueString(resourceGroup().id)
var vaultName = 'kv-${namePrefix}-${take(suffix, 8)}'
var attestationName = take('att${namePrefix}${suffix}', 24)
var vmName = '${namePrefix}-vm'

// Role definition ids (built-in).
var keyVaultCryptoServiceReleaseUser = '08bbd89e-9f13-488c-ac41-acfcb10c90ab' // only keys/release/action
var keyVaultCryptoUser = '12338af0-0e69-4776-bea7-57ae8d297424'

// ---------------------------------------------------------------- identity
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id'
  location: location
}

// ------------------------------------------------------------- attestation
// Microsoft Azure Attestation (MAA) provider. The release policy trusts tokens issued by THIS provider.
resource attestation 'Microsoft.Attestation/attestationProviders@2021-06-01' = {
  name: attestationName
  location: location
  properties: {}
}

// --------------------------------------------------------------- key vault
// Secure Key Release requires Key Vault Premium (HSM-backed keys) or Managed HSM.
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'premium'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    // Left off so the demo can be fully removed (scripts/destroy purges the vault). Enable it in production.
    enablePurgeProtection: null
  }
}

// The release policy: the key can only leave Key Vault toward a caller that presents an attestation token,
// issued by our attestation provider, proving it runs inside an AMD SEV-SNP Azure confidential VM.
var releasePolicy = {
  version: '1.0.0'
  anyOf: [
    {
      authority: attestation.properties.attestUri
      allOf: [
        {
          claim: 'x-ms-isolation-tee.x-ms-attestation-type'
          equals: 'sevsnpvm'
        }
        {
          claim: 'x-ms-isolation-tee.x-ms-compliance-status'
          equals: 'azure-compliant-cvm'
        }
      ]
    }
  ]
}

resource signingKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: keyName
  properties: {
    kty: 'EC-HSM'
    curveName: 'P-256'
    attributes: {
      enabled: true
      exportable: true // required for release; also requires a release policy
    }
    release_policy: {
      contentType: 'application/json; charset=utf-8'
      data: base64(string(releasePolicy))
    }
  }
}

// The VM identity may do exactly one thing on exactly one key: release it (and only if the policy is satisfied).
resource releaseRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: signingKey
  name: guid(signingKey.id, identity.id, keyVaultCryptoServiceReleaseUser)
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultCryptoServiceReleaseUser)
  }
}

resource readerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(readerObjectId)) {
  scope: signingKey
  name: guid(signingKey.id, readerObjectId, keyVaultCryptoUser)
  properties: {
    principalId: readerObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultCryptoUser)
  }
}

// ----------------------------------------------------------------- network
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${namePrefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-and-service'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: allowedSourceIp
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '22'
            '8080'
          ]
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.10.0.0/24'
      ]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: '10.10.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${namePrefix}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${namePrefix}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------- VM
// Files embedded in cloud-init (the app is shipped with the template, no repo clone is needed on the VM).
var cloudInitTemplate = loadTextContent('cloud-init.yaml')
var cloudInitReplacements = [
  { token: '@@SERVER_JS@@', value: loadFileAsBase64('../app/server.js') }
  { token: '@@JWT_JS@@', value: loadFileAsBase64('../app/lib/jwt.js') }
  { token: '@@KEY_CACHE_JS@@', value: loadFileAsBase64('../app/lib/key-cache.js') }
  { token: '@@LOGGER_JS@@', value: loadFileAsBase64('../app/lib/logger.js') }
  { token: '@@SKR_PROVIDER_JS@@', value: loadFileAsBase64('../app/lib/skr-key-provider.js') }
  { token: '@@PACKAGE_JSON@@', value: loadFileAsBase64('../app/package.json') }
  { token: '@@INDEX_HTML@@', value: loadFileAsBase64('../app/public/index.html') }
  { token: '@@BUILD_SKR_SH@@', value: loadFileAsBase64('../tools/build-skr.sh') }
  { token: '@@KEY_URL@@', value: signingKey.properties.keyUriWithVersion }
  { token: '@@ATTESTATION_URL@@', value: attestation.properties.attestUri }
  { token: '@@IDENTITY_CLIENT_ID@@', value: identity.properties.clientId }
]
var cloudInit = reduce(cloudInitReplacements, cloudInitTemplate, (current, item) => replace(current, item.token, item.value))

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  dependsOn: [
    releaseRole // make sure the VM never starts before it is allowed to release the key
  ]
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'ConfidentialVM'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-confidential-vm-jammy'
        sku: '22_04-lts-cvm'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: {
            securityEncryptionType: 'DiskWithVMGuestState'
          }
        }
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
  }
}

output vaultName string = vault.name
output keyName string = signingKey.name
output keyUrl string = signingKey.properties.keyUriWithVersion
output attestationUrl string = attestation.properties.attestUri
output vmPublicIp string = publicIp.properties.ipAddress
output serviceUrl string = 'http://${publicIp.properties.ipAddress}:8080'
output sshCommand string = 'ssh ${adminUsername}@${publicIp.properties.ipAddress}'
