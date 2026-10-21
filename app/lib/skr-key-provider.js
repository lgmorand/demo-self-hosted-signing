'use strict';

const { execFile } = require('node:child_process');

const PEM_PATTERN = /-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]+?-----END \1-----/;

/**
 * Returns a `loadKey()` function that performs Secure Key Release through the AzureAttestSKR helper:
 *   1. the helper attests the VM with Microsoft Azure Attestation (MAA),
 *   2. calls Key Vault `release` with the managed identity and the MAA token,
 *   3. decrypts the released key with the vTPM and prints it (PEM) on stdout.
 * The key only ever travels over a pipe into this process; it is never written to disk.
 */
function createSkrKeyProvider({ binary, attestationUrl, keyUrl, imdsClientId, timeoutMs = 60_000, cwd, log = () => {} }) {
  return () =>
    new Promise((resolve, reject) => {
      const env = { ...process.env, SKR_PRINT_KEY: '1' };
      if (imdsClientId) env.IMDS_CLIENT_ID = imdsClientId;
      const startedAt = Date.now();
      log('skr_release_started', {
        steps: ['attest VM with MAA', 'call Key Vault release with managed identity', 'decrypt with vTPM'],
        attestationUrl,
        keyUrl,
      });

      execFile(
        binary,
        ['-a', attestationUrl, '-k', keyUrl, '-c', 'imds', '-r'],
        { env, cwd, timeout: timeoutMs, maxBuffer: 256 * 1024 },
        (error, stdout, stderr) => {
          const pem = PEM_PATTERN.exec(stdout)?.[0];
          // The helper reports its progress on stderr; it never contains the key.
          const helperOutput = (stderr || '').trim().split('\n').slice(-5).map((line) => line.trim().slice(0, 200));
          if (error || !pem) {
            const detail = (stderr || error?.message || 'no private key in helper output').trim().slice(-500);
            log('skr_release_failed', { durationMs: Date.now() - startedAt, error: detail });
            reject(new Error(`secure key release failed: ${detail}`));
            return;
          }
          log('skr_release_succeeded', { durationMs: Date.now() - startedAt, helperOutput });
          resolve(pem);
        },
      );
    });
}

module.exports = { createSkrKeyProvider };
