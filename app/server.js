'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { sign, verify, JwtError } = require('./lib/jwt');
const { KeyCache } = require('./lib/key-cache');
const { createSkrKeyProvider } = require('./lib/skr-key-provider');

const RESERVED_CLAIMS = new Set(['iss', 'aud', 'sub', 'exp', 'iat', 'nbf', 'jti']);
const MAX_BODY_BYTES = 16 * 1024;

const log = (event, fields = {}) => console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }));

function readConfig(env = process.env) {
  const required = (name) => {
    if (!env[name]) throw new Error(`missing environment variable ${name}`);
    return env[name];
  };
  return {
    port: Number(env.PORT ?? 8080),
    issuer: env.TOKEN_ISSUER ?? 'https://token-service.demo',
    audience: env.TOKEN_AUDIENCE ?? 'demo-api',
    tokenTtlSeconds: Number(env.TOKEN_TTL_SECONDS ?? 300),
    keyCacheTtlSeconds: Number(env.KEY_CACHE_TTL_SECONDS ?? 3600),
    skr: {
      binary: env.SKR_BINARY ?? '/opt/skr/AzureAttestSKR',
      attestationUrl: required('ATTESTATION_URL'),
      keyUrl: required('KEY_URL'),
      imdsClientId: env.IMDS_CLIENT_ID,
      cwd: env.SKR_WORKDIR,
    },
  };
}

function createApp({ keyCache, config }) {
  const counters = { tokensIssued: 0, tokensVerified: 0, verificationFailures: 0 };
  const startedAt = Date.now();

  const sendJson = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body, null, 2));
  };

  const readJson = (req) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(Object.assign(new Error('request body too large'), { status: 413 }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        try {
          resolve(size === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(Object.assign(new Error('invalid JSON body'), { status: 400 }));
        }
      });
      req.on('error', reject);
    });

  const bearer = (req) => /^Bearer (.+)$/i.exec(req.headers.authorization ?? '')?.[1];

  const verifyToken = async (token) => {
    const { publicJwk } = await keyCache.get();
    return verify(token, publicJwk, { issuer: config.issuer, audience: config.audience });
  };

  const routes = {
    'GET /healthz': async (req, res) => sendJson(res, 200, { status: 'ok' }),

    'GET /stats': async (req, res) =>
      sendJson(res, 200, {
        uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
        ...counters,
        keyCache: keyCache.stats(),
      }),

    // Public key set: anyone can verify tokens without ever touching Key Vault or the private key.
    'GET /.well-known/jwks.json': async (req, res) => {
      const { publicJwk } = await keyCache.get();
      sendJson(res, 200, { keys: [publicJwk] });
    },

    'POST /token': async (req, res) => {
      const body = await readJson(req);
      const subject = typeof body.sub === 'string' && body.sub ? body.sub : 'demo-user';
      const extra = Object.fromEntries(
        Object.entries(body.claims ?? {}).filter(([name]) => !RESERVED_CLAIMS.has(name)),
      );
      const { privateKey, kid } = await keyCache.get();
      const now = Math.floor(Date.now() / 1000);
      const token = sign(
        {
          ...extra,
          iss: config.issuer,
          aud: config.audience,
          sub: subject,
          iat: now,
          nbf: now,
          exp: now + config.tokenTtlSeconds,
          jti: crypto.randomUUID(),
        },
        { privateKey, kid },
      );
      counters.tokensIssued += 1;
      sendJson(res, 200, { token, tokenType: 'Bearer', expiresIn: config.tokenTtlSeconds, kid });
    },

    'POST /verify': async (req, res) => {
      const body = await readJson(req);
      try {
        const { claims } = await verifyToken(body.token);
        counters.tokensVerified += 1;
        sendJson(res, 200, { valid: true, claims });
      } catch (error) {
        if (!(error instanceof JwtError)) throw error;
        counters.verificationFailures += 1;
        sendJson(res, 200, { valid: false, reason: error.message });
      }
    },

    // Example of a protected API: requires a valid bearer token issued by this service.
    'GET /protected': async (req, res) => {
      try {
        const { claims } = await verifyToken(bearer(req));
        counters.tokensVerified += 1;
        sendJson(res, 200, { message: `hello ${claims.sub}`, claims });
      } catch (error) {
        if (!(error instanceof JwtError)) throw error;
        counters.verificationFailures += 1;
        res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
        sendJson(res, 401, { error: error.message });
      }
    },
  };

  return http.createServer(async (req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname;
    const handler = routes[`${req.method} ${path}`];
    if (!handler) return sendJson(res, 404, { error: 'not found' });
    try {
      await handler(req, res);
    } catch (error) {
      const status = error.status ?? 500;
      if (status >= 500) log('request_failed', { path, error: error.message });
      if (!res.headersSent) sendJson(res, status, { error: status >= 500 ? 'internal error' : error.message });
    }
  });
}

async function main() {
  const config = readConfig();
  const keyCache = new KeyCache({
    loadKey: createSkrKeyProvider(config.skr),
    ttlMs: config.keyCacheTtlSeconds * 1000,
    log,
  });
  const server = createApp({ keyCache, config });
  server.listen(config.port, () => log('listening', { port: config.port }));

  // Warm the cache so the first request does not pay for attestation + key release.
  keyCache.get().catch((error) => log('warmup_failed', { error: error.message }));
}

if (require.main === module) {
  main().catch((error) => {
    log('fatal', { error: error.message });
    process.exit(1);
  });
}

module.exports = { createApp, readConfig };
