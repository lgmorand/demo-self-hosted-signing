'use strict';

const http = require('node:http');
const fs = require('node:fs');
const nodePath = require('node:path');
const crypto = require('node:crypto');
const { sign, verify, JwtError } = require('./lib/jwt');
const { KeyCache } = require('./lib/key-cache');
const { createSkrKeyProvider } = require('./lib/skr-key-provider');
const { Logger } = require('./lib/logger');

const RESERVED_CLAIMS = new Set(['iss', 'aud', 'sub', 'exp', 'iat', 'nbf', 'jti']);
const MAX_BODY_BYTES = 16 * 1024;
const UI_PATH = nodePath.join(__dirname, 'public', 'index.html');

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

function createApp({ keyCache, config, logger = new Logger(), uiPath = UI_PATH }) {
  const uiHtml = fs.readFileSync(uiPath);
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

  const verifyToken = async (token, via) => {
    const { publicJwk } = await keyCache.get();
    try {
      const result = verify(token, publicJwk, { issuer: config.issuer, audience: config.audience });
      logger.log('token_verified', { via, sub: result.claims.sub, kid: result.header.kid, jti: result.claims.jti });
      return result;
    } catch (error) {
      if (error instanceof JwtError) logger.log('token_rejected', { via, reason: error.message });
      throw error;
    }
  };

  const routes = {
    // Demo web UI (single static page, same origin as the API so no CORS is needed).
    'GET /': async (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
      });
      res.end(uiHtml);
    },
    'GET /healthz': async (req, res) => sendJson(res, 200, { status: 'ok' }),

    // Recent log entries (secrets are never logged). ?limit=100&event=token_issued,key_loaded&after=<seq>
    'GET /logs': async (req, res) => {
      const query = new URL(req.url, 'http://localhost').searchParams;
      const limit = Number(query.get('limit') ?? 100);
      const entries = logger.entries({
        limit: Number.isFinite(limit) ? limit : 100,
        event: query.get('event') || undefined,
        after: Number(query.get('after') ?? 0) || 0,
      });
      sendJson(res, 200, { count: entries.length, entries });
    },
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
      const jti = crypto.randomUUID();
      const token = sign(
        {
          ...extra,
          iss: config.issuer,
          aud: config.audience,
          sub: subject,
          iat: now,
          nbf: now,
          exp: now + config.tokenTtlSeconds,
          jti,
        },
        { privateKey, kid },
      );
      counters.tokensIssued += 1;
      logger.log('token_issued', {
        sub: subject,
        kid,
        jti,
        alg: 'ES256',
        expiresIn: config.tokenTtlSeconds,
        extraClaims: Object.keys(extra),
        signedWith: 'in-memory key (no Key Vault call)',
      });
      sendJson(res, 200, { token, tokenType: 'Bearer', expiresIn: config.tokenTtlSeconds, kid });
    },

    'POST /verify': async (req, res) => {
      const body = await readJson(req);
      try {
        const { claims } = await verifyToken(body.token, 'POST /verify');
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
        const { claims } = await verifyToken(bearer(req), 'GET /protected');
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
    const startedAt = Date.now();
    // Polling /logs would flood the log with its own requests.
    if (path !== '/logs') {
      res.on('finish', () =>
        logger.log('http_request', {
          method: req.method,
          path,
          status: res.statusCode,
          durationMs: Date.now() - startedAt,
          remote: req.socket.remoteAddress,
        }),
      );
    }
    const handler = routes[`${req.method} ${path}`];
    if (!handler) return sendJson(res, 404, { error: 'not found' });
    try {
      await handler(req, res);
    } catch (error) {
      const status = error.status ?? 500;
      if (status >= 500) logger.log('request_failed', { path, error: error.message });
      if (!res.headersSent) sendJson(res, status, { error: status >= 500 ? 'internal error' : error.message });
    }
  });
}

async function main() {
  const config = readConfig();
  const logger = new Logger();
  const keyCache = new KeyCache({
    loadKey: createSkrKeyProvider({ ...config.skr, log: (event, fields) => logger.log(event, fields) }),
    ttlMs: config.keyCacheTtlSeconds * 1000,
    log: (event, fields) => logger.log(event, fields),
  });
  const server = createApp({ keyCache, config, logger });
  server.listen(config.port, () =>
    logger.log('listening', { port: config.port, issuer: config.issuer, audience: config.audience, keyCacheTtlSeconds: config.keyCacheTtlSeconds }),
  );

  // Warm the cache so the first request does not pay for attestation + key release.
  keyCache.get().catch((error) => logger.log('warmup_failed', { error: error.message }));
}

if (require.main === module) {
  main().catch((error) => {
    console.error(JSON.stringify({ event: 'fatal', error: error.message }));
    process.exit(1);
  });
}

module.exports = { createApp, readConfig };
