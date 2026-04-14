import { randomBytes } from 'node:crypto';
import { Types } from 'mongoose';
import { redis } from '../../config/redis.js';
import logger from '../../utils/logger.js';
import { writeAuditLog } from '../../utils/auditLog.js';
import { Organization } from '../organization/Organization.js';
import { OrgMember } from '../organization/OrgMember.js';
import { Endpoint, type IEndpoint } from './Endpoint.js';
import { hashApiKey } from './apiKey.js';

// ---------------------------------------------------------------------------
// Plan limits (Req 5.2, 8.1)
// ---------------------------------------------------------------------------
const PLAN_LIMITS: Record<string, number> = {
  free: 1,
  pro: 10,
  enterprise: Infinity,
};

// ---------------------------------------------------------------------------
// Custom errors
// ---------------------------------------------------------------------------
export class NotFoundError extends Error {
  readonly statusCode = 404;
  constructor(message = 'Not found') { super(message); this.name = 'NotFoundError'; }
}

export class ForbiddenError extends Error {
  readonly statusCode = 403;
  constructor(message = 'Forbidden') { super(message); this.name = 'ForbiddenError'; }
}

export class PaymentRequiredError extends Error {
  readonly statusCode = 402;
  constructor(message = 'Plan limit reached') { super(message); this.name = 'PaymentRequiredError'; }
}

export class ValidationError extends Error {
  readonly statusCode = 422;
  constructor(message = 'Validation failed') { super(message); this.name = 'ValidationError'; }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Asserts actor is owner or admin — viewers cannot write. */
async function assertNotViewer(orgId: string, actorId: string): Promise<void> {
  const membership = await OrgMember.findOne({ orgId, userId: actorId, status: 'active' });
  if (!membership) throw new ForbiddenError('You are not a member of this organization');
  if (membership.role === 'viewer') throw new ForbiddenError('Viewers cannot perform write operations');
}

/** Generates a URL-safe random proxy slug (8 hex chars). */
function generateProxySlug(): string {
  return randomBytes(4).toString('hex'); // e.g. "a3f2c1b0"
}

/** Generates a 32-byte cryptographically random API key (64 hex chars). */
function generateRawApiKey(): string {
  return randomBytes(32).toString('hex');
}

/** Validates that a URL is HTTPS. Throws ValidationError if not. */
function assertHttpsUrl(url: string): void {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      throw new ValidationError('Target URL must use HTTPS');
    }
  } catch (err) {
    if (err instanceof ValidationError) throw err;
    throw new ValidationError('Target URL is not a valid URL');
  }
}

// ---------------------------------------------------------------------------
// EndpointService
// ---------------------------------------------------------------------------

export interface CreateEndpointInput {
  name: string;
  targetUrl: string;       // must be HTTPS
  ipAllowlist?: string[];
}

/**
 * create
 *
 * Req 5.1 — create endpoint with unique proxySlug, generate API key, return proxy URL.
 * Req 5.2 — enforce plan endpoint limits (402 if at limit).
 * Req 5.6 — validate target URL is HTTPS.
 */
export async function create(
  orgId: string,
  actorId: string,
  input: CreateEndpointInput,
  ipAddress: string
): Promise<{ endpoint: IEndpoint; apiKey: string; proxyUrl: string }> {
  await assertNotViewer(orgId, actorId);

  // Validate HTTPS target URL (Req 5.6)
  assertHttpsUrl(input.targetUrl);

  // Enforce plan endpoint limit (Req 5.2, 5.3)
  const org = await Organization.findById(orgId);
  if (!org) throw new NotFoundError('Organization not found');

  const currentCount = await Endpoint.countDocuments({ orgId, isActive: true });
  const limit = PLAN_LIMITS[org.plan] ?? 1;
  if (currentCount >= limit) {
    throw new PaymentRequiredError(
      `Your ${org.plan} plan allows a maximum of ${limit} endpoint(s). Upgrade to add more.`
    );
  }

  // Generate API key and proxy slug
  const rawApiKey = generateRawApiKey();
  const apiKeyHash = hashApiKey(rawApiKey);
  const proxySlug = generateProxySlug();

  const endpoint = await Endpoint.create({
    orgId: new Types.ObjectId(orgId),
    name: input.name,
    targetUrl: input.targetUrl,
    proxySlug,
    apiKeyHash,
    ipAllowlist: input.ipAllowlist ?? [],
    isActive: true,
    requestCount: 0,
  });

  // Write audit log (Req 11.7)
  await writeAuditLog({
    actorUserId: new Types.ObjectId(actorId),
    orgId: new Types.ObjectId(orgId),
    action: 'endpoint.created',
    targetResourceType: 'endpoint',
    targetResourceId: endpoint._id.toString(),
    metadata: { name: input.name, proxySlug },
    ipAddress,
    timestamp: new Date(),
  });

  const proxyUrl = `https://proxy.quantumbridge.io/${org.slug}/${proxySlug}/`;

  logger.info('endpoint_created', {
    orgId,
    endpointId: endpoint._id.toString(),
    proxySlug,
    actorId,
  });

  // Return raw key once — it is never stored, only the hash is persisted
  return { endpoint, apiKey: rawApiKey, proxyUrl };
}

/**
 * deleteEndpoint
 *
 * Req 5.5 — soft-delete, publish cache invalidation to Redis, write AuditLog.
 */
export async function deleteEndpoint(
  orgId: string,
  endpointId: string,
  actorId: string,
  ipAddress: string
): Promise<void> {
  await assertNotViewer(orgId, actorId);

  const endpoint = await Endpoint.findOne({ _id: endpointId, orgId });
  if (!endpoint) throw new NotFoundError('Endpoint not found');

  // Soft-delete
  endpoint.isActive = false;
  endpoint.deletedAt = new Date();
  await endpoint.save();

  // Publish cache invalidation so Proxy_Engine evicts immediately (Req 5.5)
  const org = await Organization.findById(orgId).select('slug');
  if (org) {
    await redis.publish(
      'endpoint:invalidate',
      JSON.stringify({ orgSlug: org.slug, proxySlug: endpoint.proxySlug })
    );
  }

  await writeAuditLog({
    actorUserId: new Types.ObjectId(actorId),
    orgId: new Types.ObjectId(orgId),
    action: 'endpoint.deleted',
    targetResourceType: 'endpoint',
    targetResourceId: endpointId,
    ipAddress,
    timestamp: new Date(),
  });

  logger.info('endpoint_deleted', { orgId, endpointId, actorId });
}

/**
 * regenerateApiKey
 *
 * Req 5.7 — generate new key, invalidate old immediately, return new key once.
 */
export async function regenerateApiKey(
  orgId: string,
  endpointId: string,
  actorId: string,
  ipAddress: string
): Promise<{ apiKey: string }> {
  await assertNotViewer(orgId, actorId);

  const endpoint = await Endpoint.findOne({ _id: endpointId, orgId, isActive: true });
  if (!endpoint) throw new NotFoundError('Endpoint not found');

  const rawApiKey = generateRawApiKey();
  endpoint.apiKeyHash = hashApiKey(rawApiKey);
  await endpoint.save();

  // Invalidate cached endpoint record so Proxy_Engine picks up the new hash
  const org = await Organization.findById(orgId).select('slug');
  if (org) {
    await redis.publish(
      'endpoint:invalidate',
      JSON.stringify({ orgSlug: org.slug, proxySlug: endpoint.proxySlug })
    );
  }

  await writeAuditLog({
    actorUserId: new Types.ObjectId(actorId),
    orgId: new Types.ObjectId(orgId),
    action: 'api_key.regenerated',
    targetResourceType: 'endpoint',
    targetResourceId: endpointId,
    ipAddress,
    timestamp: new Date(),
  });

  logger.info('api_key_regenerated', { orgId, endpointId, actorId });

  return { apiKey: rawApiKey };
}

/**
 * list
 *
 * Returns all active endpoints for an organization.
 */
export async function list(orgId: string): Promise<IEndpoint[]> {
  return Endpoint.find({ orgId, isActive: true }).sort({ createdAt: -1 });
}

/**
 * getBySlug
 *
 * Used by the Proxy_Engine to look up an endpoint by org slug + proxy slug.
 * Returns null if not found or inactive.
 */
export async function getBySlug(
  orgSlug: string,
  proxySlug: string
): Promise<IEndpoint | null> {
  const org = await Organization.findOne({ slug: orgSlug }).select('_id');
  if (!org) return null;
  return Endpoint.findOne({ orgId: org._id, proxySlug, isActive: true });
}
