'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createApp } = require('../server');
const { KeyCache } = require('../lib/key-cache');
const { verify } = require('../lib/jwt');
const { Logger } = require('../lib/logger');

const config = { issuer: 'https://issuer.test', audience: 'demo-api', tokenTtlSeconds: 60 };

async function start() {
  let loads = 0;
  const logger = new Logger({ sink: () => {} });
  const keyCache = new KeyCache({
    ttlMs: 60_000,
    log: (event, fields) => logger.log(event, fields),
    loadKey: async () => {
      loads += 1;
      return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
    },
  });
  const server = createApp({ keyCache, config, logger });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, { body, token } = {}) => {
    const response = await fetch(base + path, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: response.status, json: await response.json() };
  };
  return { call, loads: () => loads, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('issues tokens that verify against the published JWKS, with one key load', async (t) => {
  const app = await start();
  t.after(app.close);

  const issued = await Promise.all(
    Array.from({ length: 10 }, (_, i) => app.call('POST', '/token', { body: { sub: `user-${i}`, claims: { role: 'reader', iss: 'evil' } } })),
  );
  const { json: jwks } = await app.call('GET', '/.well-known/jwks.json');

  for (const { status, json } of issued) {
    assert.equal(status, 200);
    const { claims, header } = verify(json.token, jwks.keys[0], { issuer: config.issuer, audience: config.audience });
    assert.equal(claims.role, 'reader');
    assert.equal(claims.iss, config.issuer, 'reserved claims cannot be overridden');
    assert.equal(header.kid, jwks.keys[0].kid);
  }
  assert.equal(app.loads(), 1);
  assert.equal((await app.call('GET', '/stats')).json.tokensIssued, 10);
  assert.ok(!('d' in jwks.keys[0]), 'the JWKS never exposes private material');
});

test('/protected accepts valid tokens and rejects forged ones', async (t) => {
  const app = await start();
  t.after(app.close);

  const { json } = await app.call('POST', '/token', { body: { sub: 'alice' } });
  const ok = await app.call('GET', '/protected', { token: json.token });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.message, 'hello alice');

  const [header, payload, signature] = json.token.split('.');
  const forged = `${header}.${Buffer.from(JSON.stringify({ sub: 'admin' })).toString('base64url')}.${signature}`;
  assert.equal((await app.call('GET', '/protected', { token: forged })).status, 401);
  assert.equal((await app.call('GET', '/protected')).status, 401);

  const verdict = await app.call('POST', '/verify', { body: { token: forged } });
  assert.deepEqual(verdict.json, { valid: false, reason: 'invalid signature' });
});

test('GET /logs shows requests, key cache activity and token events, without secrets', async (t) => {
  const app = await start();
  t.after(app.close);

  const { json: issued } = await app.call('POST', '/token', { body: { sub: 'alice', claims: { role: 'reader' } } });
  await app.call('POST', '/token', { body: { sub: 'bob' } });
  await app.call('GET', '/protected', { token: issued.token });
  await app.call('POST', '/verify', { body: { token: `${issued.token}x` } });

  const { status, json } = await app.call('GET', '/logs?limit=500');
  assert.equal(status, 200);
  const events = json.entries.map((entry) => entry.event);
  for (const expected of ['key_cache_miss', 'key_loaded', 'key_cache_hit', 'token_issued', 'token_verified', 'token_rejected', 'http_request']) {
    assert.ok(events.includes(expected), `missing ${expected}`);
  }
  assert.equal(events.filter((event) => event === 'key_loaded').length, 1);

  const issuedEntry = json.entries.find((entry) => entry.event === 'token_issued');
  assert.deepEqual([issuedEntry.sub, issuedEntry.extraClaims], ['alice', ['role']]);
  const request = json.entries.find((entry) => entry.event === 'http_request' && entry.path === '/token');
  assert.deepEqual([request.method, request.status], ['POST', 200]);

  const serialized = JSON.stringify(json);
  assert.ok(!serialized.includes(issued.token), 'tokens are never logged');
  assert.ok(!serialized.includes('PRIVATE KEY'), 'key material is never logged');

  const filtered = (await app.call('GET', '/logs?event=token_issued')).json;
  assert.equal(filtered.count, 2);
  const newer = (await app.call('GET', `/logs?after=${json.entries.at(-1).seq}`)).json;
  assert.ok(newer.entries.every((entry) => entry.seq > json.entries.at(-1).seq));
  assert.ok(!newer.entries.some((entry) => entry.path === '/logs'), '/logs requests are not logged');
});

test('unknown routes return 404', async (t) => {
  const app = await start();
  t.after(app.close);
  assert.equal((await app.call('GET', '/nope')).status, 404);
});
