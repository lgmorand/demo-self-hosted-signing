'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { sign, verify, JwtError } = require('../lib/jwt');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const claims = (overrides = {}) => ({
  iss: 'issuer',
  aud: 'api',
  exp: Math.floor(Date.now() / 1000) + 60,
  ...overrides,
});

test('a signed token verifies with the public key (KeyObject and JWK)', () => {
  const token = sign(claims({ sub: 'alice' }), { privateKey, kid: 'k1' });
  const viaKeyObject = verify(token, publicKey, { issuer: 'issuer', audience: 'api' });
  const viaJwk = verify(token, publicKey.export({ format: 'jwk' }), { issuer: 'issuer', audience: 'api' });
  assert.equal(viaKeyObject.claims.sub, 'alice');
  assert.equal(viaKeyObject.header.kid, 'k1');
  assert.deepEqual(viaJwk.claims, viaKeyObject.claims);
});

test('a tampered payload is rejected', () => {
  const [header, , signature] = sign(claims({ sub: 'alice' }), { privateKey, kid: 'k1' }).split('.');
  const forgedPayload = Buffer.from(JSON.stringify(claims({ sub: 'admin' }))).toString('base64url');
  assert.throws(() => verify(`${header}.${forgedPayload}.${signature}`, publicKey), /invalid signature/);
});

test('a token signed by another key is rejected', () => {
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const token = sign(claims(), { privateKey: other.privateKey, kid: 'k1' });
  assert.throws(() => verify(token, publicKey), /invalid signature/);
});

test('expired tokens, wrong issuer and wrong audience are rejected', () => {
  const token = sign(claims({ exp: Math.floor(Date.now() / 1000) - 120 }), { privateKey, kid: 'k1' });
  assert.throws(() => verify(token, publicKey), /expired/);

  const valid = sign(claims(), { privateKey, kid: 'k1' });
  assert.throws(() => verify(valid, publicKey, { issuer: 'someone-else' }), /issuer/);
  assert.throws(() => verify(valid, publicKey, { audience: 'other-api' }), /audience/);
});

test('alg "none" and other algorithms are refused', () => {
  const b64u = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u(claims())}.`;
  assert.throws(() => verify(unsigned, publicKey), /unsupported alg/);
});

test('malformed input raises JwtError', () => {
  for (const input of [undefined, '', 'a.b', 'a.b.c', 'not a token']) {
    assert.throws(() => verify(input, publicKey), JwtError);
  }
});
