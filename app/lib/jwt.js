'use strict';

const crypto = require('node:crypto');

const b64u = (input) => Buffer.from(input).toString('base64url');
const parseJson = (b64) => JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));

class JwtError extends Error {}

/** Signs a compact JWT with ES256 (ECDSA P-256 + SHA-256, raw r||s signature). */
function sign(payload, { privateKey, kid }) {
  const header = { alg: 'ES256', typ: 'JWT', kid };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${b64u(signature)}`;
}

/**
 * Verifies an ES256 JWT with a public key (KeyObject or JWK) and returns its claims.
 * Throws JwtError when the token is malformed, forged, expired or addressed to someone else.
 */
function verify(token, publicKey, { issuer, audience, now = Date.now(), clockSkewSeconds = 30 } = {}) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) throw new JwtError('malformed token');

  let header;
  let claims;
  try {
    header = parseJson(parts[0]);
    claims = parseJson(parts[1]);
  } catch {
    throw new JwtError('malformed token');
  }
  // Pin the algorithm: never trust the algorithm announced by the token itself.
  if (header.alg !== 'ES256') throw new JwtError(`unsupported alg: ${header.alg}`);

  const key = publicKey.type === 'public' ? publicKey : crypto.createPublicKey({ key: publicKey, format: 'jwk' });
  const valid = crypto.verify(
    'sha256',
    Buffer.from(`${parts[0]}.${parts[1]}`),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(parts[2], 'base64url'),
  );
  if (!valid) throw new JwtError('invalid signature');

  const nowSeconds = Math.floor(now / 1000);
  if (typeof claims.exp !== 'number' || nowSeconds > claims.exp + clockSkewSeconds) throw new JwtError('token expired');
  if (typeof claims.nbf === 'number' && nowSeconds + clockSkewSeconds < claims.nbf) throw new JwtError('token not yet valid');
  if (issuer && claims.iss !== issuer) throw new JwtError('unexpected issuer');
  if (audience && claims.aud !== audience) throw new JwtError('unexpected audience');

  return { header, claims };
}

/** RFC 7638 JWK thumbprint, used as the `kid` so it is derived from the key itself. */
function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

module.exports = { sign, verify, thumbprint, JwtError };
