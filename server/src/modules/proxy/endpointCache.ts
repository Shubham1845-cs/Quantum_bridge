import { redis } from '../../config/redis.js';
import { Endpoint, type IEndpoint } from '../endpoint/Endpoint.js';
import { Organization } from '../organization/Organization.js';

/**
 * Retrieves an endpoint by org slug and proxy slug.
 * Redis GET → MongoDB fallback → setex 300s
 *
 * Requirement: 5.5
 */
export async function getEndpoint(orgSlug: string, proxySlug: string): Promise<IEndpoint | null> {
  const cacheKey = `endpoint:${orgSlug}:${proxySlug}`;

  const cached = await redis.get(cacheKey);
  if (cached !== null) {
    return JSON.parse(cached) as IEndpoint;
  }

  const org = await Organization.findOne({ slug: orgSlug }).select('_id').lean();
  if (!org) return null;

  const endpoint = await Endpoint.findOne({ orgId: org._id, proxySlug, isActive: true }).lean();
  if (!endpoint) return null;

  await redis.setex(cacheKey, 300, JSON.stringify(endpoint));
  return endpoint as unknown as IEndpoint;
}
