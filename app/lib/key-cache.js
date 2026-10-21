'use strict';

const crypto = require('node:crypto');
const { thumbprint } = require('./jwt');

/**
 * Keeps the signing key in process memory.
 *
 * `loadKey` returns the PEM of the private key (in this demo: the key released by Key Vault).
 * It is only called when nothing is cached or when the cached copy is older than `ttlMs`,
 * so signing a token never costs a Key Vault round trip.
 */
class KeyCache {
  constructor({ loadKey, ttlMs, staleRetryMs = 30_000, now = Date.now, log = () => {} }) {
    this.loadKey = loadKey;
    this.ttlMs = ttlMs;
    this.staleRetryMs = staleRetryMs;
    this.now = now;
    this.log = log;
    this.entry = null;
    this.inflight = null;
    this.loads = 0;
    this.hits = 0;
  }

  async get() {
    if (this.entry && this.now() < this.entry.expiresAt) {
      this.hits += 1;
      return this.entry;
    }
    // Concurrent callers share a single release call.
    this.inflight ??= this.#refresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  async #refresh() {
    try {
      const pem = await this.loadKey();
      const privateKey = crypto.createPrivateKey(pem);
      const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new Error(`expected an EC P-256 key, got ${jwk.kty}/${jwk.crv}`);
      }
      const kid = thumbprint(jwk);
      const loadedAt = this.now();
      this.loads += 1;
      this.entry = {
        privateKey,
        kid,
        publicJwk: { ...jwk, kid, use: 'sig', alg: 'ES256' },
        loadedAt,
        expiresAt: loadedAt + this.ttlMs,
      };
      this.log('key_loaded', { kid, ttlSeconds: this.ttlMs / 1000 });
      return this.entry;
    } catch (error) {
      if (!this.entry) throw error;
      // Keep serving the previous key rather than failing every request during a Key Vault blip.
      this.entry.expiresAt = this.now() + this.staleRetryMs;
      this.log('key_refresh_failed_using_cached_key', { error: error.message });
      return this.entry;
    }
  }

  stats() {
    return {
      keyLoaded: Boolean(this.entry),
      kid: this.entry?.kid ?? null,
      keyReleaseCalls: this.loads,
      cacheHits: this.hits,
      keyAgeSeconds: this.entry ? Math.round((this.now() - this.entry.loadedAt) / 1000) : null,
      cacheTtlSeconds: this.ttlMs / 1000,
    };
  }
}

module.exports = { KeyCache };
