#!/usr/bin/env node
'use strict';

/**
 * Runs from your workstation against the deployed service.
 *
 *   node client/demo.js http://<vm-ip>:8080 [--vault <name> --key <name>] [--tokens 200]
 *
 * It requests tokens, verifies them locally with the PUBLIC key only (JWKS from the service, optionally
 * cross-checked against the public key Key Vault holds), proves that a forged token is rejected, and
 * shows how many Key Vault key releases were needed for all those tokens.
 */

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const { verify, thumbprint, JwtError } = require('../app/lib/jwt');

function parseArgs(argv) {
  const args = { service: undefined, tokens: 100 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--vault') args.vault = argv[++i];
    else if (arg === '--key') args.key = argv[++i];
    else if (arg === '--tokens') args.tokens = Number(argv[++i]);
    else if (!arg.startsWith('--')) args.service = arg.replace(/\/$/, '');
  }
  if (!args.service) {
    console.error('usage: node client/demo.js <service-url> [--vault <name> --key <name>] [--tokens <n>]');
    process.exit(2);
  }
  return args;
}

const step = (message) => console.log(`\n\u25B6 ${message}`);
const ok = (message) => console.log(`  \u2714 ${message}`);

async function http(method, url, { body, token } = {}) {
  const response = await fetch(url, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, json: await response.json() };
}

function keyVaultPublicJwk(vault, key) {
  const az = process.platform === 'win32' ? 'az.cmd' : 'az';
  const out = execFileSync(az, ['keyvault', 'key', 'show', '--vault-name', vault, '--name', key, '--query', 'key', '-o', 'json'], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  const jwk = JSON.parse(out);
  // Key Vault reports the HSM key type ("EC-HSM"); the public parameters are standard EC.
  return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
}

async function main() {
  const { service, tokens, vault, key } = parseArgs(process.argv.slice(2));

  step('Fetching the public key set from the service');
  const { json: jwks } = await http('GET', `${service}/.well-known/jwks.json`);
  const jwk = jwks.keys[0];
  ok(`kid ${jwk.kid} (${jwk.kty} ${jwk.crv}) - no private material: ${!('d' in jwk)}`);
  if (thumbprint(jwk) !== jwk.kid) throw new Error('kid does not match the JWK thumbprint');

  if (vault && key) {
    step('Cross-checking with the public key stored in Key Vault');
    const vaultJwk = keyVaultPublicJwk(vault, key);
    if (thumbprint(vaultJwk) !== jwk.kid) throw new Error('the service signs with a key that is NOT the Key Vault key');
    ok(`the service key is the Key Vault key '${key}' (same thumbprint)`);
  }

  step(`Requesting ${tokens} tokens`);
  const started = Date.now();
  const issued = await Promise.all(
    Array.from({ length: tokens }, (_, i) => http('POST', `${service}/token`, { body: { sub: `user-${i}`, claims: { role: 'reader' } } })),
  );
  ok(`${issued.length} tokens issued in ${Date.now() - started} ms`);

  step('Verifying every token locally with the public key only');
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  issued.forEach(({ json }) => verify(json.token, publicKey, { issuer: 'https://token-service.demo', audience: 'demo-api' }));
  ok(`${issued.length}/${issued.length} signatures valid`);
  const sample = verify(issued[0].json.token, publicKey).claims;
  console.log(`  sample claims: ${JSON.stringify(sample)}`);

  step('Tampering with a token (changing sub to "admin")');
  const [header, , signature] = issued[0].json.token.split('.');
  const forged = `${header}.${Buffer.from(JSON.stringify({ ...sample, sub: 'admin' })).toString('base64url')}.${signature}`;
  try {
    verify(forged, publicKey);
    throw new Error('forged token was accepted!');
  } catch (error) {
    if (!(error instanceof JwtError)) throw error;
    ok(`rejected locally: ${error.message}`);
  }
  const remote = await http('GET', `${service}/protected`, { token: forged });
  ok(`rejected by the service: HTTP ${remote.status}`);
  const accepted = await http('GET', `${service}/protected`, { token: issued[0].json.token });
  ok(`genuine token accepted by the service: "${accepted.json.message}"`);

  step('Key Vault usage');
  const { json: stats } = await http('GET', `${service}/stats`);
  console.log(JSON.stringify(stats, null, 2).replace(/^/gm, '  '));
  ok(`${stats.tokensIssued} tokens signed, ${stats.keyCache.keyReleaseCalls} key release call(s) to Key Vault`);
}

main().catch((error) => {
  console.error(`\n\u2716 ${error.message}`);
  process.exit(1);
});
