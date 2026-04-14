import { randomUUID, createDecipheriv } from 'node:crypto';
import express from 'express';
import cors from 'cors';
import { Types } from 'mongoose';
import { env } from './config/env.js';
import { healthLimiter } from './middleware/rateLimiter.js';
import { getEndpoint } from './modules/proxy/endpointCache.js';
import { ProxyLog } from './modules/proxy/ProxyLog.js';
import { verifyApiKey } from './modules/endpoint/apiKey.js';
import { keyVaultService, type DualSignature } from './modules/keyVault/keyVaultService.js';
import { redis, duplicate } from './config/redis.js';
import logger from './utils/logger.js';
import { connectWithRetry } from './config/database.js';

const app = express();

// Req 10.6 — Proxy_Engine uses wildcard CORS (not ALLOWED_ORIGIN)
app.use(cors());

// No size limit on proxy — legacy APIs may have larger payloads
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Health endpoint with dedicated rate limiter (Req 17.5)
app.get('/health', healthLimiter, (_req, res) => {
  res.json({ status: 'ok' });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildTargetUrl(targetUrl: string, req: express.Request): string {
  // req.params[0] captures the wildcard path after /:orgSlug/:proxySlug/
  const remainingPath = req.params[0] ?? '';
  const queryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  const base = targetUrl.endsWith('/') ? targetUrl.slice(0, -1) : targetUrl;
  return `${base}/${remainingPath}${queryString}`;
}

function stripQBHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!key.toLowerCase().startsWith('x-qb-') && value !== undefined) {
      result[key] = Array.isArray(value) ? value.join(', ') : value;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// AES-256-GCM request body decryption (Step 5)
// The session key is derived the same way as the KeyVault key: PBKDF2 from
// orgId + pepper + the org's stored salt.  The client sends:
//   QB-Encrypted: 1
//   X-QB-IV: <base64 12-byte IV>
//   Body: base64-encoded ciphertext (encrypted_data || 16-byte auth tag)
// ---------------------------------------------------------------------------

async function decryptRequestBody(
  encryptedBase64: string,
  ivBase64: string,
  sessionKey: Buffer,
): Promise<Buffer> {
  const ciphertext = Buffer.from(encryptedBase64, 'base64');
  const iv = Buffer.from(ivBase64, 'base64');
  const authTag = ciphertext.subarray(-16);
  const data = ciphertext.subarray(0, -16);
  const decipher = createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}



interface ProxyLogEntry {
  requestId: string;
  orgId: string;
  endpointId: string;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
  keyVersion: number;
  forwardedToLegacy: boolean;
  clientIp: string;
}

async function writeProxyLog(entry: ProxyLogEntry): Promise<void> {
  try {
    await ProxyLog.create({
      requestId: entry.requestId,
      orgId: new Types.ObjectId(entry.orgId),
      endpointId: new Types.ObjectId(entry.endpointId),
      timestamp: new Date(),
      method: entry.method,
      path: entry.path,
      statusCode: entry.statusCode,
      latencyMs: entry.latencyMs,
      ecdsaVerified: entry.ecdsaVerified,
      dilithiumVerified: entry.dilithiumVerified,
      threatFlag: entry.threatFlag,
      keyVersion: entry.keyVersion,
      forwardedToLegacy: entry.forwardedToLegacy,
      clientIp: entry.clientIp,
    });
  } catch (err) {
    // Never let a log write failure crash the proxy
    logger.error('proxy_log_write_failed', { requestId: entry.requestId, err });
  }
}

// ---------------------------------------------------------------------------
// Proxy handler — Steps 1–4, 7–9 (Steps 5–6 crypto added in task 4.1)
// ---------------------------------------------------------------------------

async function proxyHandler(req: express.Request, res: express.Response): Promise<void> {
  const requestId = randomUUID();
  const startMs = Date.now();

  let statusCode = 500;
  let threatFlag = false;
  let forwardedToLegacy = false;
  let endpointId = '';
  let orgId = '';
  let ecdsaVerified = false;
  let dilithiumVerified = false;
  let keyVersion = 0;

  const clientIp =
    (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ??
    req.socket.remoteAddress ??
    'unknown';

  try {
    // Step 1 — Route extraction (Req 6.1)
    const { orgSlug, proxySlug } = req.params;

    if (!orgSlug || !proxySlug) {
      res.status(404).json({ error: 'Not found' });
      statusCode = 404;
      return;
    }

    // Step 2 — Endpoint lookup (Req 6.2)
    const endpoint = await getEndpoint(orgSlug, proxySlug);

    if (!endpoint) {
      statusCode = 404;
      res.status(404).json({ error: 'Endpoint not found' });
      return;
    }

    endpointId = String(endpoint._id);
    orgId = String(endpoint.orgId);

    // Step 3 — API key validation (Req 6.3, 6.4)
    const authHeader = req.headers['authorization'];
    const rawKey = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : authHeader ?? '';

    const keyValid = rawKey.length > 0 && verifyApiKey(rawKey, endpoint.apiKeyHash);

    if (!keyValid) {
      threatFlag = true;
      statusCode = 401;
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Step 4 — IP allowlist check (Req 6.4)
    if (endpoint.ipAllowlist.length > 0 && !endpoint.ipAllowlist.includes(clientIp)) {
      statusCode = 403;
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    // Steps 5 & 6 — PQC crypto (Req 6.5, 6.6, 6.7)

    // Step 5 — Decrypt request body if QB-Encrypted header is present (Req 6.5)
    if (req.headers['qb-encrypted'] === '1') {
      const ivBase64 = req.headers['x-qb-iv'] as string | undefined;
      if (!ivBase64) {
        statusCode = 400;
        res.status(400).json({ error: 'Missing X-QB-IV header for encrypted request' });
        return;
      }

      try {
        // Derive the org's session key using the same PBKDF2 path as KeyVault
        const { deriveKey } = await import('./modules/keyVault/keyVaultService.js');
        const { KeyVault } = await import('./modules/keyVault/KeyVault.js');
        const vault = await KeyVault.findOne({ orgId, isActive: true });
        if (!vault) {
          statusCode = 500;
          res.status(500).json({ error: 'Internal error' });
          return;
        }
        const sessionKey = await deriveKey(orgId, vault.salt);
        const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        const decrypted = await decryptRequestBody(rawBody, ivBase64, sessionKey);
        sessionKey.fill(0);
        // Replace req.body with the decrypted payload for forwarding
        req.body = JSON.parse(decrypted.toString('utf8'));
      } catch (err) {
        logger.warn('request_decryption_failed', { requestId, orgId });
        statusCode = 400;
        res.status(400).json({ error: 'Failed to decrypt request body' });
        return;
      }
    }

    // Step 6 — Verify dual-signature if X-QB-ECDSA-Sig header is present (Req 6.6, 6.7)
    const ecdsaSigHeader = req.headers['x-qb-ecdsa-sig'] as string | undefined;
    const dilithiumSigHeader = req.headers['x-qb-dilithium-sig'] as string | undefined;
    const keyVersionHeader = req.headers['x-qb-key-version'] as string | undefined;

    if (ecdsaSigHeader || dilithiumSigHeader) {
      if (!ecdsaSigHeader || !dilithiumSigHeader || !keyVersionHeader) {
        threatFlag = true;
        statusCode = 400;
        res.status(400).json({ error: 'Incomplete dual-signature headers' });
        return;
      }

      const sigKeyVersion = parseInt(keyVersionHeader, 10);
      if (isNaN(sigKeyVersion)) {
        threatFlag = true;
        statusCode = 400;
        res.status(400).json({ error: 'Invalid X-QB-Key-Version header' });
        return;
      }

      const dualSig: DualSignature = {
        ecdsaSignature: ecdsaSigHeader,
        dilithiumSignature: dilithiumSigHeader,
        keyVersion: sigKeyVersion,
      };

      // Build the canonical payload that was signed: method + path + body
      const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? '');
      const sigPayload = Buffer.from(`${req.method}:${req.path}:${bodyStr}`);

      try {
        const verifyResult = await keyVaultService.verify(orgId, sigPayload, dualSig, sigKeyVersion);
        ecdsaVerified = verifyResult.ecdsaVerified;
        dilithiumVerified = verifyResult.dilithiumVerified;
        keyVersion = sigKeyVersion;

        if (verifyResult.threatFlag) {
          // Req 6.7 — set threatFlag, return 400, DO NOT forward
          threatFlag = true;
          statusCode = 400;
          res.status(400).json({ error: 'Signature verification failed' });
          return;
        }
      } catch (err) {
        // Vault not found or expired — treat as verification failure
        logger.warn('signature_verification_error', { requestId, orgId, err });
        threatFlag = true;
        statusCode = 400;
        res.status(400).json({ error: 'Signature verification failed' });
        return;
      }
    }

    // Step 7 — Strip QB headers (Req 6.8)
    const forwardHeaders = stripQBHeaders(req.headers as Record<string, string | string[] | undefined>);

    // Step 8 — Forward to legacy API (Req 6.9, 6.14, 6.15)
    const targetUrl = buildTargetUrl(endpoint.targetUrl, req);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30_000);

    try {
      forwardedToLegacy = true;

      const fetchOptions: RequestInit = {
        method: req.method,
        headers: forwardHeaders,
        signal: controller.signal,
      };

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        fetchOptions.body = JSON.stringify(req.body);
      }

      const legacyResponse = await fetch(targetUrl, fetchOptions);
      clearTimeout(timeoutId);

      statusCode = legacyResponse.status;

      // Step 9 — Return response (Req 6.9)
      const contentType = legacyResponse.headers.get('content-type');
      if (contentType) res.setHeader('content-type', contentType);

      const body = await legacyResponse.text();
      res.status(statusCode).send(body);
    } catch (err: unknown) {
      clearTimeout(timeoutId);
      const isAbort = err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError');
      if (isAbort) {
        statusCode = 504;
        res.status(504).json({ error: 'Gateway Timeout' });
      } else {
        statusCode = 502;
        res.status(502).json({ error: 'Bad Gateway' }); // never expose targetUrl
      }
    }
  } finally {
    // Req 6.13, 3.9 — write ProxyLog after every pipeline completion, including failures
    // Skip if we never resolved an endpoint (no orgId/endpointId to log against)
    if (orgId && endpointId) {
      await writeProxyLog({
        requestId,
        orgId,
        endpointId,
        method: req.method,
        path: req.path,
        statusCode,
        latencyMs: Date.now() - startMs,
        ecdsaVerified,
        dilithiumVerified,
        threatFlag,
        keyVersion,
        forwardedToLegacy,
        clientIp,
      });
    }
  }
}

// Catch-all proxy routes
app.all('/:orgSlug/:proxySlug/*', proxyHandler);
app.all('/:orgSlug/:proxySlug', proxyHandler);

// ---------------------------------------------------------------------------
// Redis pub/sub cache invalidation subscriber
// ---------------------------------------------------------------------------

async function initCacheInvalidationSubscriber(): Promise<void> {
  const subscriber = duplicate();
  await subscriber.connect();

  // ioredis subscribe() returns a Promise when no callback is passed.
  // The actual messages arrive via the 'message' event (channel, message).
  subscriber.on('message', async (_channel: string, message: string) => {
    const { orgSlug, proxySlug } = JSON.parse(message) as { orgSlug: string; proxySlug: string };
    const cacheKey = `endpoint:${orgSlug}:${proxySlug}`;
    await redis.del(cacheKey);
    logger.info('cache_invalidated', { cacheKey });
  });

  await subscriber.subscribe('endpoint:invalidate');
  logger.info('Redis pub/sub subscriber initialized on channel: endpoint:invalidate');
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

async function start(): Promise<void> {
  await connectWithRetry();
  await initCacheInvalidationSubscriber();
  app.listen(env.PROXY_PORT, () => {
    logger.info(`Proxy_Engine listening on port ${env.PROXY_PORT}`);
  });
}

start().catch((err) => {
  logger.error('Proxy_Engine failed to start', { err });
  process.exit(1);
});

export { app };
export default app;
