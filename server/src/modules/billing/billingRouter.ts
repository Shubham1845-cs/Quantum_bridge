import { Router, Request, Response } from 'express';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { createCheckoutSession, createPortalSession, BillingError } from './billingService.js';
import { validateAndActivateCustomDomain, CustomDomainError } from './customDomainService.js';
import { z } from 'zod';

export const billingRouter = Router({ mergeParams: true });

const checkoutBodySchema = z.object({
  plan: z.enum(['pro', 'enterprise']),
});

// ---------------------------------------------------------------------------
// POST /billing/checkout — initiate Stripe Checkout (owner only, Req 8.4)
// ---------------------------------------------------------------------------
billingRouter.post(
  '/checkout',
  authenticate,
  requireRole('owner'),
  async (req: Request, res: Response): Promise<void> => {
    const parsed = checkoutBodySchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(422).json({ error: 'plan must be "pro" or "enterprise"' });
      return;
    }

    try {
      const { url } = await createCheckoutSession(req.params.orgId, parsed.data.plan);
      res.status(200).json({ url });
    } catch (err) {
      if (err instanceof BillingError) {
        res.status(err.statusCode).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// ---------------------------------------------------------------------------
// GET /billing/portal — Stripe Customer Portal redirect (owner only, Req 8.8)
// ---------------------------------------------------------------------------
billingRouter.get(
  '/portal',
  authenticate,
  requireRole('owner'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { url } = await createPortalSession(req.params.orgId);
      res.status(200).json({ url });
    } catch (err) {
      if (err instanceof BillingError) {
        res.status(err.statusCode).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// ---------------------------------------------------------------------------
// POST /billing/custom-domain — validate DNS CNAME and activate custom domain
// (owner only, Pro/Enterprise plan required, Req 8.10)
// ---------------------------------------------------------------------------
billingRouter.post(
  '/custom-domain',
  authenticate,
  requireRole('owner'),
  async (req: Request, res: Response): Promise<void> => {
    const { domain } = req.body as { domain?: string };
    if (!domain || typeof domain !== 'string' || !domain.trim()) {
      res.status(422).json({ error: 'domain is required' });
      return;
    }

    try {
      await validateAndActivateCustomDomain(req.params.orgId, domain.trim().toLowerCase());
      res.status(200).json({ message: 'Custom domain verified and activated', domain: domain.trim().toLowerCase() });
    } catch (err) {
      if (err instanceof CustomDomainError) {
        res.status(err.statusCode).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);
