import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { ProxyLog } from '../proxy/ProxyLog.js';
import { Organization } from '../organization/Organization.js';
import { keyVaultService } from '../keyVault/keyVaultService.js';

// ---------------------------------------------------------------------------
// Rate limiter: 30 req / min per IP (Req 18.1)
// ---------------------------------------------------------------------------
const verifyLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification requests. Try again in 1 minute.' },
});

export const verifyRouter = Router();

// ---------------------------------------------------------------------------
// GET /verify/:requestId
//
// Public, unauthenticated endpoint.
// Returns verification status for a proxied request.
//
// Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.7
//
// NEVER returns: private key material, encrypted blobs, targetUrl, or any
// internal IDs beyond what is explicitly listed below.
//
// Returns 404 for:
//   - requestId not found
//   - org has publicVerificationEnabled: false
//   (same response in both cases — avoids information leakage)
// ---------------------------------------------------------------------------
verifyRouter.get('/:requestId', verifyLimiter, async (req: Request, res: Response): Promise<void> => {
  const { requestId } = req.params;

  // Look up the ProxyLog by requestId
  const log = await ProxyLog.findOne({ requestId }).lean();

  if (!log) {
    res.status(404).json({ error: 'Not found' });
    return;
  }

  // Check that the org has public verification enabled (Req 18.7)
  const org = await Organization.findById(log.orgId)
    .select('publicVerificationEnabled')
    .lean();

  if (!org || !org.publicVerificationEnabled) {
    // Same 404 response — do not reveal whether the org exists (Req 18.5)
    res.status(404).json({ error: 'Not found' });
    return;
  }

  // Fetch public keys for the key version used in this request (Req 18.3)
  // If the vault version is unavailable (e.g. expired), return null keys rather than 500
  let ecdsaPublicKey: string | null = null;
  let dilithiumPublicKey: string | null = null;

  try {
    const keys = await keyVaultService.getPublicKeys(log.orgId.toString(), log.keyVersion || undefined);
    ecdsaPublicKey = keys.ecdsaPublicKey;
    dilithiumPublicKey = keys.dilithiumPublicKey;
  } catch {
    // Key version may have expired — still return the log data without keys
  }

  // Return only the explicitly allowed fields (Req 18.2, 18.4)
  res.json({
    requestId:          log.requestId,
    orgId:              log.orgId.toString(),
    timestamp:          log.timestamp,
    ecdsaVerified:      log.ecdsaVerified,
    dilithiumVerified:  log.dilithiumVerified,
    threatFlag:         log.threatFlag,
    ecdsaPublicKey,
    dilithiumPublicKey,
  });
});
