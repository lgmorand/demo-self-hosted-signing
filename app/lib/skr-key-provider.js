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
function createSkrKeyProvider({ binary, attestationUrl, keyUrl, imdsClientId, timeoutMs = 60_000, cwd }) {
  return () =>
    new Promise((resolve, reject) => {
      const env = { ...process.env, SKR_PRINT_KEY: '1' };
      if (imdsClientId) env.IMDS_CLIENT_ID = imdsClientId;

      execFile(
        binary,
        ['-a', attestationUrl, '-k', keyUrl, '-c', 'imds', '-r'],
        { env, cwd, timeout: timeoutMs, maxBuffer: 256 * 1024 },
        (error, stdout, stderr) => {
          const pem = PEM_PATTERN.exec(stdout)?.[0];
          if (error || !pem) {
            const detail = (stderr || error?.message || 'no private key in helper output').trim().slice(-500);
            reject(new Error(`secure key release failed: ${detail}`));
            return;
          }
          resolve(pem);
        },
      );
    });
}

module.exports = { createSkrKeyProvider };
