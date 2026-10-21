'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { KeyCache } = require('../lib/key-cache');

const newPem = () =>
  crypto
    .generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .privateKey.export({ format: 'pem', type: 'pkcs8' });

function setup({ ttlMs = 1000 } = {}) {
  let clock = 0;
  const state = { calls: 0, fail: false };
  const cache = new KeyCache({
    ttlMs,
    staleRetryMs: 100,
    now: () => clock,
    loadKey: async () => {
      state.calls += 1;
      await new Promise((resolve) => setImmediate(resolve));
      if (state.fail) throw new Error('vault unavailable');
      return newPem();
    },
  });
  return { cache, state, advance: (ms) => (clock += ms) };
}

test('the key is loaded once and then served from memory', async () => {
  const { cache, state } = setup();
  const first = await cache.get();
  for (let i = 0; i < 50; i += 1) assert.equal((await cache.get()).kid, first.kid);
  assert.equal(state.calls, 1);
  assert.equal(cache.stats().cacheHits, 50);
  assert.equal(cache.stats().keyReleaseCalls, 1);
});

test('concurrent callers share a single release call', async () => {
  const { cache, state } = setup();
  const entries = await Promise.all(Array.from({ length: 20 }, () => cache.get()));
  assert.equal(state.calls, 1);
  assert.ok(entries.every((entry) => entry === entries[0]));
});

test('the key is reloaded once the TTL has elapsed', async () => {
  const { cache, state, advance } = setup({ ttlMs: 1000 });
  await cache.get();
  advance(999);
  await cache.get();
  assert.equal(state.calls, 1);
  advance(2);
  await cache.get();
  assert.equal(state.calls, 2);
});

test('a failed refresh keeps serving the cached key and retries later', async () => {
  const { cache, state, advance } = setup({ ttlMs: 1000 });
  const original = await cache.get();
  state.fail = true;
  advance(1001);
  assert.equal((await cache.get()).kid, original.kid);
  assert.equal(state.calls, 2);
  await cache.get();
  assert.equal(state.calls, 2, 'no retry before staleRetryMs');
  advance(101);
  await cache.get();
  assert.equal(state.calls, 3);
});

test('the very first load failing is reported to the caller', async () => {
  const { cache, state } = setup();
  state.fail = true;
  await assert.rejects(cache.get(), /vault unavailable/);
  state.fail = false;
  assert.ok((await cache.get()).kid);
});

test('non P-256 keys are rejected', async () => {
  const cache = new KeyCache({
    ttlMs: 1000,
    loadKey: async () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }),
  });
  await assert.rejects(cache.get(), /expected an EC P-256 key/);
});
