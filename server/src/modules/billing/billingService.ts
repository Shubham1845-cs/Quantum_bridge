import Stripe from 'stripe';
import { env } from '../../config/env.js';
import { Organization } from '../organization/Organization.js';
import logger from '../../utils/logger.js';

const stripe = new Stripe(env.STRIPE_SECRET_KEY);

// ---------------------------------------------------------------------------
// Plan → Stripe price ID mapping
// These should match the price IDs configured in your Stripe dashboard.
// Override via environment variables for flexibility across environments.
// ---------------------------------------------------------------------------
const PLAN_PRICE_IDS: Record<'pro' | 'enterprise', string> = {
  pro:        process.env.STRIPE_PRICE_PRO        ?? 'price_pro_placeholder',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE ?? 'price_enterprise_placeholder',
};

export class BillingError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'BillingError';
    this.statusCode = statusCode;
  }
}

// ---------------------------------------------------------------------------
// createCheckoutSession (Req 8.4)
//
// Creates a Stripe Checkout session for the given org and plan.
// Returns the redirect URL for the client.
// ---------------------------------------------------------------------------
export async function createCheckoutSession(
  orgId: string,
  plan: 'pro' | 'enterprise'
): Promise<{ url: string }> {
  const org = await Organization.findById(orgId).select('name stripeCustomerId').lean();
  if (!org) {
    throw new BillingError('Organization not found', 404);
  }

  const sessionParams: Stripe.Checkout.SessionCreateParams = {
    mode: 'subscription',
    line_items: [{ price: PLAN_PRICE_IDS[plan], quantity: 1 }],
    success_url: `${env.ALLOWED_ORIGIN}/dashboard/billing?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${env.ALLOWED_ORIGIN}/dashboard/billing`,
    metadata: { orgId, plan },
    // Attach to existing Stripe customer if available
    ...(org.stripeCustomerId ? { customer: org.stripeCustomerId } : {}),
  };

  const session = await stripe.checkout.sessions.create(sessionParams);

  logger.info('stripe_checkout_session_created', { orgId, plan, sessionId: session.id });

  if (!session.url) {
    throw new BillingError('Stripe did not return a checkout URL');
  }

  return { url: session.url };
}

// ---------------------------------------------------------------------------
// createPortalSession (Req 8.8)
//
// Creates a Stripe Customer Portal session so the org owner can manage
// payment methods and view invoices.
// ---------------------------------------------------------------------------
export async function createPortalSession(orgId: string): Promise<{ url: string }> {
  const org = await Organization.findById(orgId).select('stripeCustomerId').lean();
  if (!org) {
    throw new BillingError('Organization not found', 404);
  }

  if (!org.stripeCustomerId) {
    throw new BillingError(
      'No Stripe customer found for this organization. Complete a checkout first.',
      402
    );
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: org.stripeCustomerId,
    return_url: `${env.ALLOWED_ORIGIN}/dashboard/billing`,
  });

  logger.info('stripe_portal_session_created', { orgId });

  return { url: session.url };
}
