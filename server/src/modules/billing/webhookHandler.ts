import Stripe from 'stripe';
import { env } from '../../config/env.js';
import { Organization } from '../organization/Organization.js';
import { Endpoint } from '../endpoint/Endpoint.js';
import { redis } from '../../config/redis.js';
import logger from '../../utils/logger.js';

const stripe = new Stripe(env.STRIPE_SECRET_KEY);

// ---------------------------------------------------------------------------
// handleWebhookEvent (Req 8.5, 8.6, 8.7)
//
// Verifies the Stripe-Signature header and processes the event.
// Rejects unverified requests with a thrown error (caller returns 400).
//
// Idempotency: each event ID is stored in Redis with a 24h TTL.
// Duplicate deliveries are silently acknowledged (return without processing).
//
// Handled events:
//   checkout.session.completed  → update org plan + reset quota (Req 8.6)
//   customer.subscription.deleted → downgrade to free + enforce limits (Req 8.7)
// ---------------------------------------------------------------------------
export async function handleWebhookEvent(
  rawBody: Buffer,
  signature: string
): Promise<void> {
  // Req 8.5 — verify signature; throws StripeSignatureVerificationError on failure
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Invalid signature';
    logger.warn('stripe_webhook_signature_invalid', { msg });
    throw Object.assign(new Error(`Webhook signature verification failed: ${msg}`), {
      statusCode: 400,
    });
  }

  // Idempotency — skip already-processed events (Req 8.6, 8.7)
  const idempotencyKey = `stripe:event:${event.id}`;
  const alreadyProcessed = await redis.get(idempotencyKey);
  if (alreadyProcessed) {
    logger.info('stripe_webhook_duplicate_skipped', { eventId: event.id, type: event.type });
    return;
  }

  logger.info('stripe_webhook_received', { eventId: event.id, type: event.type });

  switch (event.type) {
    case 'checkout.session.completed':
      await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
      break;

    case 'customer.subscription.deleted':
      await handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
      break;

    default:
      // Unhandled event types — acknowledge without processing
      logger.info('stripe_webhook_unhandled_event', { type: event.type });
  }

  // Mark event as processed — TTL 24h (86400s)
  await redis.set(idempotencyKey, '1', 'EX', 86_400);
}

// ---------------------------------------------------------------------------
// handleCheckoutCompleted (Req 8.6)
//
// Fired when a Stripe Checkout session completes successfully.
// Updates the org's plan and resets the monthly request quota.
// ---------------------------------------------------------------------------
async function handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
  const orgId = session.metadata?.orgId;
  const plan  = session.metadata?.plan as 'pro' | 'enterprise' | undefined;

  if (!orgId || !plan) {
    logger.warn('stripe_checkout_completed_missing_metadata', {
      sessionId: session.id,
      metadata: session.metadata,
    });
    return;
  }

  // Compute next quota reset (1st of next month, UTC midnight)
  const now = new Date();
  const nextReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  const updated = await Organization.findByIdAndUpdate(
    orgId,
    {
      plan,
      monthlyRequestCount: 0,
      quotaResetAt: nextReset,
      // Store Stripe IDs for portal access
      ...(session.customer        ? { stripeCustomerId:      String(session.customer) }       : {}),
      ...(session.subscription    ? { stripeSubscriptionId:  String(session.subscription) }   : {}),
    },
    { new: true, select: 'name plan' }
  );

  if (!updated) {
    logger.warn('stripe_checkout_org_not_found', { orgId, sessionId: session.id });
    return;
  }

  logger.info('stripe_plan_upgraded', {
    orgId,
    plan,
    sessionId: session.id,
    orgName: updated.name,
  });
}

// ---------------------------------------------------------------------------
// handleSubscriptionDeleted (Req 8.7)
//
// Fired when a Stripe subscription is cancelled/deleted.
// Downgrades the org to the Free plan and enforces Free plan limits
// immediately by soft-deleting endpoints beyond the Free limit (1 endpoint).
// ---------------------------------------------------------------------------
async function handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
  // Find the org by stripeSubscriptionId
  const org = await Organization.findOne({
    stripeSubscriptionId: subscription.id,
  }).select('_id name plan');

  if (!org) {
    logger.warn('stripe_subscription_deleted_org_not_found', {
      subscriptionId: subscription.id,
    });
    return;
  }

  const orgId = org._id.toString();

  // Compute next quota reset
  const now = new Date();
  const nextReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  await Organization.findByIdAndUpdate(orgId, {
    plan: 'free',
    monthlyRequestCount: 0,
    quotaResetAt: nextReset,
    stripeSubscriptionId: undefined,
  });

  // Enforce Free plan endpoint limit (1 endpoint) immediately —
  // soft-delete all active endpoints beyond the first one (ordered by createdAt asc)
  const activeEndpoints = await Endpoint.find({ orgId, isActive: true })
    .sort({ createdAt: 1 })
    .select('_id')
    .lean();

  if (activeEndpoints.length > 1) {
    const toDisable = activeEndpoints.slice(1).map((e) => e._id);
    await Endpoint.updateMany(
      { _id: { $in: toDisable } },
      { isActive: false, deletedAt: now }
    );
    logger.info('stripe_downgrade_endpoints_disabled', {
      orgId,
      disabledCount: toDisable.length,
    });
  }

  logger.info('stripe_plan_downgraded_to_free', {
    orgId,
    orgName: org.name,
    subscriptionId: subscription.id,
  });
}
