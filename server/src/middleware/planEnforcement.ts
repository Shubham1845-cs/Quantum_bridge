import { Request, Response, NextFunction } from 'express';
import { Organization } from '../modules/organization/Organization.js';
import { Endpoint } from '../modules/endpoint/Endpoint.js';

/**
 * Plan endpoint limits (Req 5.2, 8.1, 8.9)
 *
 * Free       → 1 endpoint
 * Pro        → 10 endpoints
 * Enterprise → unlimited
 */
const PLAN_ENDPOINT_LIMITS: Record<string, number> = {
  free: 1,
  pro: 10,
  enterprise: Infinity,
};

/**
 * enforceEndpointLimit
 *
 * Express middleware applied to POST /orgs/:orgId/endpoints.
 * Checks the org's current active endpoint count against its plan limit.
 * Returns 402 Payment Required with an upgrade prompt if the limit is reached.
 *
 * Req 5.2, 5.3, 8.1, 8.9
 */
export async function enforceEndpointLimit(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const { orgId } = req.params;

  if (!orgId) {
    res.status(400).json({ error: 'Missing orgId' });
    return;
  }

  const org = await Organization.findById(orgId).select('plan').lean();
  if (!org) {
    res.status(404).json({ error: 'Organization not found' });
    return;
  }

  const limit = PLAN_ENDPOINT_LIMITS[org.plan] ?? 1;

  // Unlimited plans skip the count query entirely
  if (limit === Infinity) {
    next();
    return;
  }

  const currentCount = await Endpoint.countDocuments({ orgId, isActive: true });

  if (currentCount >= limit) {
    res.status(402).json({
      error: 'Plan limit reached',
      message: `Your ${org.plan} plan allows a maximum of ${limit} endpoint(s). Upgrade your plan to add more.`,
      upgradeUrl: 'https://quantumbridge.io/billing',
    });
    return;
  }

  next();
}
