/**
 * QubicShield — Request Signature Verification Middleware
 *
 * Applied to /api/protected. Verifies that each request carries a valid
 * SchnorrQ signature produced by the depositor's Qubic private key.
 *
 * Requires these headers:
 *   Authorization:  Bearer <token_hex>
 *   X-QS-Nonce:     <nonce_hex>       (8 random bytes, hex, single-use per session)
 *   X-QS-Timestamp: <unix_ms>
 *   X-QS-Signature: <signature_hex>   (64 bytes, hex)
 *
 * If REQUIRE_SIGNING=false (default in mock mode), the middleware logs a warning
 * but passes through — allowing the existing mock flow without a seed.
 * Set REQUIRE_SIGNING=true in production to enforce signing on every request.
 */

import { Request, Response, NextFunction } from 'express';
import depositManager from '../depositManager';
import { verifyRequest } from '../requestSigner';

const REQUIRE_SIGNING = process.env.REQUIRE_SIGNING === 'true';

export async function requestVerifier(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    // No token at all — let requireValidToken handle the 401
    next();
    return;
  }

  const tokenHex    = auth.slice(7);
  const nonceHex    = req.headers['x-qs-nonce'] as string | undefined;
  const tsRaw       = req.headers['x-qs-timestamp'] as string | undefined;
  const signatureHex = req.headers['x-qs-signature'] as string | undefined;

  // If signing headers are absent and signing is not required, pass through
  if (!nonceHex || !tsRaw || !signatureHex) {
    if (REQUIRE_SIGNING) {
      res.status(401).json({
        error: 'Missing signing headers. Required: X-QS-Nonce, X-QS-Timestamp, X-QS-Signature.',
      });
      return;
    }
    // Soft mode: warn and continue (backwards-compatible with PoC clients)
    console.warn('[requestVerifier] Signing headers missing — REQUIRE_SIGNING=false, passing through.');
    next();
    return;
  }

  const timestampMs = parseInt(tsRaw, 10);
  if (isNaN(timestampMs)) {
    res.status(400).json({ error: 'X-QS-Timestamp must be a numeric Unix millisecond value.' });
    return;
  }

  // Look up the stored publicKey for this session token
  const deposit = depositManager.getDepositByToken(tokenHex);
  if (!deposit || !deposit.publicKey) {
    if (REQUIRE_SIGNING) {
      res.status(401).json({ error: 'No publicKey on file for this token. Re-deposit with publicKey.' });
      return;
    }
    console.warn('[requestVerifier] No publicKey stored for token — REQUIRE_SIGNING=false, passing through.');
    next();
    return;
  }

  const usedNonces = depositManager.getNonceSet(deposit.sessionId);

  try {
    const result = await verifyRequest(
      deposit.publicKey,
      tokenHex,
      nonceHex,
      timestampMs,
      signatureHex,
      usedNonces,
    );

    if (!result.ok) {
      res.status(401).json({ error: `Request signature invalid: ${result.reason}` });
      return;
    }
  } catch (err) {
    res.status(500).json({ error: `Signature verification error: ${(err as Error).message}` });
    return;
  }

  next();
}
