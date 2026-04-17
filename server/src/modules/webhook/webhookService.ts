import { createHmac, randomBytes } from 'node:crypto';
import { Types } from 'mongoose';
import { WebhookConfig, type IWebhookConfig } from './WebhookConfig.js';
import { WebhookDelivery, type DeliveryStatus } from './WebhookDelivery.js';
import { writeAuditLog } from '../../utils/auditLog.js';
import logger from '../../utils/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatEvent {
  orgId: string;
  endpointId: string;
  requestId: string;
  timestamp: Date;
  threatType: 'signature_failure' | 'invalid_api_key';
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
}

export class WebhookError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'WebhookError';
    this.statusCode = statusCode;
  }
}

// ---------------------------------------------------------------------------
// Retry delays: attempt 1 → 2s, attempt 2 → 4s (Req 9.4)
// ---------------------------------------------------------------------------
const RETRY_DELAYS_MS = [0, 2_000, 4_000]; // index = attempt - 1
const MAX_ATTEMPTS = 3;
const DELIVERY_TIMEOUT_MS = 10_000; // 10s per attempt

// ---------------------------------------------------------------------------
// register (Req 9.1)
//
// Validates the URL is HTTPS and reachable, saves WebhookConfig, writes AuditLog.
// ---------------------------------------------------------------------------
export async function register(
  orgId: string,
  url: string,
  actorId: string,
  ipAddress: string
): Promise<IWebhookConfig> {
  // Must be HTTPS
  if (!isHttpsUrl(url)) {
    throw new WebhookError('Webhook URL must use HTTPS', 422);
  }

  // Validate reachability with a HEAD request (Req 9.1)
  await assertUrlReachable(url);

  // Generate a per-webhook HMAC secret (32 random bytes, hex-encoded)
  const secret = randomBytes(32).toString('hex');

  const config = await WebhookConfig.create({
    orgId: new Types.ObjectId(orgId),
    url,
    secret,
    isActive: true,
  });

  await writeAuditLog({
    actorUserId: new Types.ObjectId(actorId),
    orgId: new Types.ObjectId(orgId),
    action: 'webhook.registered',
    targetResourceType: 'webhook',
    targetResourceId: config._id.toString(),
    metadata: { url },
    ipAddress,
    timestamp: new Date(),
  });

  logger.info('webhook_registered', { orgId, webhookId: config._id.toString(), url });

  return config;
}

// ---------------------------------------------------------------------------
// deliver (Req 9.2, 9.3, 9.4, 9.5)
//
// POSTs a signed JSON payload to all active webhook URLs for the org.
// Retries with exponential backoff (2s, 4s) for up to 3 attempts.
// Marks permanently_failed after the 3rd failure.
// Writes a WebhookDelivery log for every attempt.
// ---------------------------------------------------------------------------
export async function deliver(orgId: string, event: ThreatEvent): Promise<void> {
  const configs = await WebhookConfig.find({ orgId, isActive: true });

  if (configs.length === 0) return;

  // Fire deliveries concurrently per webhook URL (each has its own retry loop)
  await Promise.allSettled(configs.map((config) => deliverToOne(config, event)));
}

async function deliverToOne(
  config: IWebhookConfig,
  event: ThreatEvent
): Promise<void> {
  const payload = buildPayload(event);
  const payloadJson = JSON.stringify(payload);
  const signature = signPayload(payloadJson, config.secret);

  let lastError: string | undefined;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    // Wait before retry (no delay on first attempt)
    if (attempt > 1) {
      await sleep(RETRY_DELAYS_MS[attempt - 1]);
    }

    const startTime = Date.now();
    let httpStatus: number | undefined;
    let deliveryStatus: DeliveryStatus;
    let errorMsg: string | undefined;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

      const response = await fetch(config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-QB-Signature': signature,
          'X-QB-Timestamp': String(payload.timestamp),
        },
        body: payloadJson,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      httpStatus = response.status;

      if (response.ok) {
        deliveryStatus = 'delivered';
      } else {
        deliveryStatus = attempt === MAX_ATTEMPTS ? 'permanently_failed' : 'failed';
        errorMsg = `HTTP ${response.status}`;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errorMsg = msg;
      deliveryStatus = attempt === MAX_ATTEMPTS ? 'permanently_failed' : 'failed';
    }

    const responseTimeMs = Date.now() - startTime;

    // Write delivery log for this attempt (Req 9.5)
    await WebhookDelivery.create({
      webhookId: config._id,
      orgId:     config.orgId,
      requestId: event.requestId,
      attempt,
      status:    deliveryStatus,
      httpStatus,
      responseTimeMs,
      error: errorMsg,
    });

    logger.info('webhook_delivery_attempt', {
      webhookId: config._id.toString(),
      orgId: config.orgId.toString(),
      requestId: event.requestId,
      attempt,
      status: deliveryStatus,
      httpStatus,
      responseTimeMs,
    });

    if (deliveryStatus === 'delivered') return;

    lastError = errorMsg;

    if (deliveryStatus === 'permanently_failed') {
      logger.warn('webhook_permanently_failed', {
        webhookId: config._id.toString(),
        orgId: config.orgId.toString(),
        requestId: event.requestId,
        error: lastError,
      });
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// getDeliveryLog (Req 9.5)
// ---------------------------------------------------------------------------
export async function getDeliveryLog(
  orgId: string,
  webhookId: string
): Promise<InstanceType<typeof WebhookDelivery>[]> {
  return WebhookDelivery.find({ webhookId, orgId })
    .sort({ createdAt: -1 })
    .limit(100)
    .lean() as unknown as InstanceType<typeof WebhookDelivery>[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build the required payload fields (Req 9.3) */
function buildPayload(event: ThreatEvent): Record<string, unknown> {
  return {
    orgId:            event.orgId,
    endpointId:       event.endpointId,
    requestId:        event.requestId,
    timestamp:        event.timestamp.getTime(),
    threatType:       event.threatType,
    ecdsaVerified:    event.ecdsaVerified,
    dilithiumVerified: event.dilithiumVerified,
  };
}

/** HMAC-SHA256 signature over the JSON payload using the webhook secret */
function signPayload(payloadJson: string, secret: string): string {
  return createHmac('sha256', secret).update(payloadJson).digest('hex');
}

function isHttpsUrl(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

/** HEAD request to verify the URL is reachable before saving (Req 9.1) */
async function assertUrlReachable(url: string): Promise<void> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5_000);
    const response = await fetch(url, { method: 'HEAD', signal: controller.signal });
    clearTimeout(timeoutId);
    // Accept any HTTP response — even 4xx means the server is reachable
    void response;
  } catch {
    throw new WebhookError(
      `Webhook URL "${url}" is not reachable. Ensure the endpoint is accessible over HTTPS.`,
      422
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
