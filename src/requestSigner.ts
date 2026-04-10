/**
 * QubicShield — Request Signing & Verification
 *
 * Implements per-request authentication using Qubic's SchnorrQ signature scheme.
 *
 * Protocol:
 *   1. At deposit time, the client derives their publicKey from their seed and sends it.
 *   2. For each request to /api/protected, the client signs a message:
 *        digest = K12( token_bytes(32) + nonce_bytes(8) + ts_bytes(8) )
 *        signature = schnorrq.sign(privateKey, publicKey, digest)
 *   3. The server verifies the signature against the stored publicKey.
 *
 * Why this fixes open point #7:
 *   A stolen Bearer token alone is worthless — the attacker also needs the
 *   private key that signed the request. Without the seed, signatures cannot
 *   be forged. Each nonce is single-use, preventing replay attacks.
 *
 * HTTP Headers (client → server):
 *   Authorization:  Bearer <token_hex>       (64 hex chars, 32 bytes)
 *   X-QS-Nonce:     <nonce_hex>              (16 hex chars, 8 random bytes)
 *   X-QS-Timestamp: <unix_ms>               (milliseconds since epoch)
 *   X-QS-Signature: <signature_hex>         (128 hex chars, 64 bytes)
 */

import cryptoPromise from '@qubic-lib/qubic-ts-library/dist/crypto';
import { KeyHelper } from '@qubic-lib/qubic-ts-library/dist/keyHelper';

// Maximum clock skew accepted between client and server (milliseconds).
// Requests with a timestamp outside this window are rejected.
export const TIMESTAMP_TOLERANCE_MS = 30_000; // 30 seconds

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * Derive the 32-byte private key from a Qubic seed (55-char string).
 * Uses the same derivation as qubicHelper — index 0, K12-based.
 */
export async function privateKeyFromSeed(seed: string): Promise<Uint8Array> {
  const { K12 } = await cryptoPromise;
  const kh = new KeyHelper();
  return kh.privateKey(seed, 0, K12);
}

/**
 * Derive the 32-byte public key from a private key.
 */
export async function publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  const { schnorrq } = await cryptoPromise;
  return schnorrq.generatePublicKey(privateKey);
}

/**
 * Convenience: derive publicKey directly from seed.
 */
export async function publicKeyFromSeed(seed: string): Promise<Uint8Array> {
  const priv = await privateKeyFromSeed(seed);
  return publicKeyFromPrivate(priv);
}

// ---------------------------------------------------------------------------
// Message construction
// ---------------------------------------------------------------------------

/**
 * Build the 48-byte raw message that is hashed before signing.
 *
 *   [0..31]  token bytes (32)
 *   [32..39] nonce bytes (8)
 *   [40..47] timestamp as uint64 little-endian (8)
 */
export function buildRawMessage(
  tokenHex: string,
  nonceHex: string,
  timestampMs: number,
): Uint8Array {
  const raw = new Uint8Array(48);
  const tokenBytes = hexToBytes(tokenHex.padEnd(64, '0').slice(0, 64));
  const nonceBytes = hexToBytes(nonceHex.padEnd(16, '0').slice(0, 16));
  const tsBytes   = uint64LEBytes(BigInt(timestampMs));

  raw.set(tokenBytes, 0);
  raw.set(nonceBytes, 32);
  raw.set(tsBytes, 40);
  return raw;
}

/**
 * Hash the raw message with K12 to produce a 32-byte digest.
 * schnorrq.sign() operates on arbitrary-length messages — we K12-hash
 * for a fixed-size input consistent with Qubic conventions.
 */
export async function buildDigest(raw: Uint8Array): Promise<Uint8Array> {
  const { K12 } = await cryptoPromise;
  const digest = new Uint8Array(32);
  K12(raw, digest, 32);
  return digest;
}

// ---------------------------------------------------------------------------
// Signing (client side — needs seed)
// ---------------------------------------------------------------------------

/**
 * Sign a request message.
 * Returns the 64-byte signature as a Uint8Array.
 *
 * @param seed      55-char Qubic seed
 * @param tokenHex  64 hex chars (32-byte session token)
 * @param nonceHex  16 hex chars (8 random bytes, single-use)
 * @param timestampMs  current time in milliseconds
 */
export async function signRequest(
  seed: string,
  tokenHex: string,
  nonceHex: string,
  timestampMs: number,
): Promise<Uint8Array> {
  const { schnorrq } = await cryptoPromise;
  const privateKey = await privateKeyFromSeed(seed);
  const publicKey  = await publicKeyFromPrivate(privateKey);
  const raw    = buildRawMessage(tokenHex, nonceHex, timestampMs);
  const digest = await buildDigest(raw);
  return schnorrq.sign(privateKey, publicKey, digest);
}

// ---------------------------------------------------------------------------
// Verification (server side — needs stored publicKey)
// ---------------------------------------------------------------------------

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify an incoming signed request.
 *
 * @param storedPublicKey  32-byte publicKey stored at deposit time
 * @param tokenHex         from Authorization: Bearer header
 * @param nonceHex         from X-QS-Nonce header
 * @param timestampMs      from X-QS-Timestamp header (parsed to number)
 * @param signatureHex     from X-QS-Signature header
 * @param usedNonces       Set of already-seen nonces for this session (mutated)
 */
export async function verifyRequest(
  storedPublicKey: Uint8Array,
  tokenHex: string,
  nonceHex: string,
  timestampMs: number,
  signatureHex: string,
  usedNonces: Set<string>,
): Promise<VerifyResult> {
  // 1. Timestamp freshness
  const skew = Math.abs(Date.now() - timestampMs);
  if (skew > TIMESTAMP_TOLERANCE_MS) {
    return { ok: false, reason: `Timestamp too old or in the future (skew: ${skew}ms)` };
  }

  // 2. Nonce replay prevention
  if (usedNonces.has(nonceHex)) {
    return { ok: false, reason: 'Nonce already used (replay attack)' };
  }

  // 3. Signature format
  if (signatureHex.length !== 128) {
    return { ok: false, reason: 'X-QS-Signature must be 128 hex chars (64 bytes)' };
  }

  // 4. Cryptographic verification
  const { schnorrq } = await cryptoPromise;
  const raw       = buildRawMessage(tokenHex, nonceHex, timestampMs);
  const digest    = await buildDigest(raw);
  const signature = hexToBytes(signatureHex);
  const valid     = schnorrq.verify(storedPublicKey, digest, signature);

  if (valid !== 1) {
    return { ok: false, reason: 'Invalid signature' };
  }

  // 5. Consume the nonce — must be done AFTER verification to prevent DoS via nonce-flooding
  usedNonces.add(nonceHex);

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const len = hex.length;
  const out = new Uint8Array(len / 2);
  for (let i = 0; i < len; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function uint64LEBytes(value: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}
