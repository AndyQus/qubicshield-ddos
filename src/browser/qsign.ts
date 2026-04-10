/**
 * QubicShield — Browser-side Request Signing
 *
 * Bundled by esbuild into public/qsign.js and exposed as window.QSign.
 * Loaded by public/index.html for client-side request signing.
 *
 * Usage in browser:
 *   await QSign.init(seed);
 *   const headers = await QSign.signedHeaders(tokenHex);
 *   fetch('/api/protected', { headers });
 *
 * The seed is kept only in memory (never sent to the server).
 * Each call to signedHeaders() generates a fresh nonce and timestamp.
 */

import cryptoPromise from '@qubic-lib/qubic-ts-library/dist/crypto';
import { KeyHelper } from '@qubic-lib/qubic-ts-library/dist/keyHelper';
import {
  privateKeyFromSeed,
  publicKeyFromPrivate,
  buildRawMessage,
  buildDigest,
  bytesToHex,
} from '../requestSigner';

interface QSignState {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

let state: QSignState | null = null;

/**
 * Initialize the signer with the user's seed.
 * Derives and caches private + public key.
 * Call once after the user enters their seed.
 *
 * @param seed  55-char Qubic seed
 * @returns     publicKeyHex — send this to /api/deposit alongside walletAddress
 */
export async function init(seed: string): Promise<string> {
  const privateKey = await privateKeyFromSeed(seed);
  const publicKey  = await publicKeyFromPrivate(privateKey);
  state = { privateKey, publicKey, publicKeyHex: bytesToHex(publicKey) };
  return state.publicKeyHex;
}

/**
 * Returns true if the signer has been initialized with a seed.
 */
export function isReady(): boolean {
  return state !== null;
}

/**
 * Clear the cached key material from memory.
 * Call on logout / session end.
 */
export function clear(): void {
  if (state) {
    // Overwrite key bytes before clearing reference
    state.privateKey.fill(0);
    state.publicKey.fill(0);
    state = null;
  }
}

/**
 * Build signed HTTP headers for a request to /api/protected.
 *
 * @param tokenHex  64 hex chars (32-byte session token from /api/deposit response)
 * @returns         Headers object ready for fetch()
 */
export async function signedHeaders(tokenHex: string): Promise<Record<string, string>> {
  if (!state) throw new Error('QSign not initialized — call QSign.init(seed) first');

  const { schnorrq } = await cryptoPromise;

  const nonce       = generateNonce();
  const timestampMs = Date.now();
  const raw         = buildRawMessage(tokenHex, nonce, timestampMs);
  const digest      = await buildDigest(raw);
  const signature   = schnorrq.sign(state.privateKey, state.publicKey, digest);

  return {
    'Authorization':  `Bearer ${tokenHex}`,
    'X-QS-Nonce':     nonce,
    'X-QS-Timestamp': String(timestampMs),
    'X-QS-Signature': bytesToHex(signature),
  };
}

/**
 * Generate 8 cryptographically random bytes as a hex string.
 * Falls back to Math.random() in environments without crypto.getRandomValues().
 */
function generateNonce(): string {
  const bytes = new Uint8Array(8);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 8; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytesToHex(bytes);
}
