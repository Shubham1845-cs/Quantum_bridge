/**
 * Property 24: Quota Enforcement
 * Feature: quantum-bridge, Property 24
 *
 * Requirements: 8.3
 *
 * Verifies that atomicQuotaCheckAndIncrement:
 *   - throws QuotaExceededError when count > plan limit
 *   - undoes the increment on quota exceeded
 *   - never throws for enterprise orgs regardless of count
 *   - resolves without error when count is within limit
 *   - plan limits are correctly ordered (free < pro < enterprise)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockOrgFindOneAndUpdate,
  mockOrgUpdateOne,
  mockOrgMemberFindOne,
  mockUserFindById,
  mockRedisGet,
  mockRedisSet,
  mockSendEmail,
} = vi.hoisted(() => ({
  mockOrgFindOneAndUpdate: vi.fn(),
  mockOrgUpdateOne:        vi.fn().mockResolvedValue({ modifiedCount: 1 }),
  mockOrgMemberFindOne:    vi.fn().mockResolvedValue(null),
  mockUserFindById:        vi.fn().mockReturnValue({ select: vi.fn().mockResolvedValue(null) }),
  mockRedisGet:            vi.fn().mockResolvedValue(null),
  mockRedisSet:            vi.fn().mockResolvedValue('OK'),
  mockSendEmail:           vi.fn().mockResolvedValue({ id: 'email-id' }),
}));

vi.mock('../../config/env.js', () => ({
  env: {
    RESEND_API_KEY: 're_test',
    ALLOWED_ORIGIN: 'https://app.quantumbridge.io',
    NODE_ENV: 'test',
  },
}));

vi.mock('../../utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('resend', () => ({
  Resend: vi.fn().mockImplementation(() => ({
    emails: { send: mockSendEmail },
  })),
}));

vi.mock('../organization/Organization.js', () => ({
  Organization: {
    findOneAndUpdate: mockOrgFindOneAndUpdate,
    updateOne:        mockOrgUpdateOne,
  },
}));

vi.mock('../organization/OrgMember.js', () => ({
  OrgMember: { findOne: mockOrgMemberFindOne },
}));

vi.mock('../auth/User.js', () => ({
  User: { findById: mockUserFindById },
}));

vi.mock('../../config/redis.js', () => ({
  redis: { get: mockRedisGet, set: mockRedisSet },
}));

import {
  atomicQuotaCheckAndIncrement,
  QuotaExceededError,
  PLAN_QUOTA,
} from './quotaService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_ORG_ID = 'aabbccddeeff001122334455';

function makeUpdatedOrg(
  plan: 'free' | 'pro' | 'enterprise',
  monthlyRequestCount: number,
  quotaResetAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
) {
  return {
    _id: VALID_ORG_ID,
    name: 'Test Org',
    plan,
    monthlyRequestCount,
    quotaResetAt,
  };
}

// ---------------------------------------------------------------------------
// Property 24: Quota Enforcement
// Feature: quantum-bridge, Property 24
// ---------------------------------------------------------------------------

describe('Property 24: Quota Enforcement (Req 8.3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockOrgUpdateOne.mockResolvedValue({ modifiedCount: 1 });
    mockRedisGet.mockResolvedValue(null);
  });

  // -------------------------------------------------------------------------
  // P24-a: QuotaExceededError is thrown when count > plan limit
  // -------------------------------------------------------------------------
  it('throws QuotaExceededError when free plan count exceeds 10 000', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 10_001, max: 20_000 }),
        async (count) => {
          vi.clearAllMocks();
          mockOrgUpdateOne.mockResolvedValue({ modifiedCount: 1 });
          mockOrgFindOneAndUpdate.mockResolvedValue(makeUpdatedOrg('free', count));

          await expect(
            atomicQuotaCheckAndIncrement(VALID_ORG_ID)
          ).rejects.toThrow(QuotaExceededError);
        }
      ),
      { numRuns: 30 }
    );
  });

  it('throws QuotaExceededError when pro plan count exceeds 1 000 000', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1_000_001, max: 1_100_000 }),
        async (count) => {
          vi.clearAllMocks();
          mockOrgUpdateOne.mockResolvedValue({ modifiedCount: 1 });
          mockOrgFindOneAndUpdate.mockResolvedValue(makeUpdatedOrg('pro', count));

          await expect(
            atomicQuotaCheckAndIncrement(VALID_ORG_ID)
          ).rejects.toThrow(QuotaExceededError);
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-b: Increment is undone when quota is exceeded
  // -------------------------------------------------------------------------
  it('undoes the increment (updateOne $inc -1) when quota is exceeded', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('free' as const, 'pro' as const),
        async (plan) => {
          vi.clearAllMocks();
          const limit = PLAN_QUOTA[plan];
          const count = limit + 1;
          mockOrgFindOneAndUpdate.mockResolvedValue(makeUpdatedOrg(plan, count));
          mockOrgUpdateOne.mockResolvedValue({ modifiedCount: 1 });

          await expect(
            atomicQuotaCheckAndIncrement(VALID_ORG_ID)
          ).rejects.toThrow(QuotaExceededError);

          // The undo increment must have been called
          expect(mockOrgUpdateOne).toHaveBeenCalledTimes(1);
          expect(mockOrgUpdateOne).toHaveBeenCalledWith(
            { _id: VALID_ORG_ID },
            { $inc: { monthlyRequestCount: -1 } }
          );
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-c: Enterprise orgs never hit a quota limit
  // -------------------------------------------------------------------------
  it('enterprise plan never throws QuotaExceededError regardless of count', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 100_000_000 }),
        async (count) => {
          vi.clearAllMocks();
          mockOrgFindOneAndUpdate.mockResolvedValue(makeUpdatedOrg('enterprise', count));

          await expect(
            atomicQuotaCheckAndIncrement(VALID_ORG_ID)
          ).resolves.toBeUndefined();

          // No undo increment for enterprise
          expect(mockOrgUpdateOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-d: Resolves without error when count is within limit
  // -------------------------------------------------------------------------
  it('resolves without error when count is within the plan limit', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('free' as const, 'pro' as const),
        async (plan) => {
          vi.clearAllMocks();
          const limit = PLAN_QUOTA[plan];
          // Pick a count safely below the 90% threshold to avoid warning email side-effects
          const count = Math.floor(limit * 0.5);
          mockOrgFindOneAndUpdate.mockResolvedValue(makeUpdatedOrg(plan, count));

          await expect(
            atomicQuotaCheckAndIncrement(VALID_ORG_ID)
          ).resolves.toBeUndefined();

          // No undo increment
          expect(mockOrgUpdateOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-e: Plan limits are correctly ordered
  // -------------------------------------------------------------------------
  it('plan quota limits are ordered: free < pro < enterprise', () => {
    fc.assert(
      fc.property(fc.constant(undefined), () => {
        expect(PLAN_QUOTA.free).toBeLessThan(PLAN_QUOTA.pro);
        expect(PLAN_QUOTA.pro).toBeLessThan(PLAN_QUOTA.enterprise);
        expect(PLAN_QUOTA.enterprise).toBe(Infinity);
        expect(PLAN_QUOTA.free).toBe(10_000);
        expect(PLAN_QUOTA.pro).toBe(1_000_000);
      }),
      { numRuns: 1 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-f: Org not found is a no-op (never throws)
  // -------------------------------------------------------------------------
  it('resolves without error when org is not found (no-op)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (orgId) => {
          vi.clearAllMocks();
          mockOrgFindOneAndUpdate.mockResolvedValue(null);

          await expect(
            atomicQuotaCheckAndIncrement(orgId)
          ).resolves.toBeUndefined();

          expect(mockOrgUpdateOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P24-g: QuotaExceededError has statusCode 429
  // -------------------------------------------------------------------------
  it('QuotaExceededError always carries statusCode 429', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 128 }),
        (msg) => {
          const err = msg ? new QuotaExceededError(msg) : new QuotaExceededError();
          expect(err.statusCode).toBe(429);
          expect(err).toBeInstanceOf(Error);
          expect(err.name).toBe('QuotaExceededError');
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ===========================================================================
// Property 25: Stripe Webhook Signature Enforcement
// Feature: quantum-bridge, Property 25
// Requirements: 8.5
//
// FOR ALL webhook requests, handleWebhookEvent SHALL reject any request
// where stripe.webhooks.constructEvent throws (invalid/missing signature)
// by throwing an error with statusCode 400.
// Valid signatures SHALL be accepted and processed without throwing.
// ===========================================================================

// ---------------------------------------------------------------------------
// Additional mocks for P25 / P26
// ---------------------------------------------------------------------------
const {
  mockConstructEvent,
  mockRedisGetP25,
  mockRedisSetP25,
  mockOrgFindByIdAndUpdate,
  mockOrgFindOne,
  mockEndpointFind,
  mockEndpointUpdateMany,
} = vi.hoisted(() => ({
  mockConstructEvent:      vi.fn(),
  mockRedisGetP25:         vi.fn(),
  mockRedisSetP25:         vi.fn(),
  mockOrgFindByIdAndUpdate: vi.fn(),
  mockOrgFindOne:          vi.fn(),
  mockEndpointFind:        vi.fn(),
  mockEndpointUpdateMany:  vi.fn(),
}));

vi.mock('stripe', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      webhooks: {
        constructEvent: mockConstructEvent,
      },
    })),
  };
});

vi.mock('../endpoint/Endpoint.js', () => ({
  Endpoint: {
    find:        mockEndpointFind,
    updateMany:  mockEndpointUpdateMany,
  },
}));

// Re-import handleWebhookEvent after mocks are set up
// (vi.mock is hoisted so this import picks up the mocked stripe)
import { handleWebhookEvent } from './webhookHandler.js';

// ---------------------------------------------------------------------------
// Helpers for P25 / P26
// ---------------------------------------------------------------------------

/** Build a minimal Stripe event object */
function makeStripeEvent(
  id: string,
  type: string,
  dataObject: Record<string, unknown> = {}
): Record<string, unknown> {
  return { id, type, data: { object: dataObject } };
}

/** Reset all P25/P26 mocks to clean state */
function resetWebhookMocks() {
  vi.clearAllMocks();
  mockRedisGetP25.mockResolvedValue(null);
  mockRedisSetP25.mockResolvedValue('OK');
  mockOrgFindByIdAndUpdate.mockResolvedValue({ name: 'Test Org', plan: 'pro' });
  mockOrgFindOne.mockResolvedValue(null);
  mockEndpointFind.mockReturnValue({ sort: vi.fn().mockReturnValue({ select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue([]) }) }) });
  mockEndpointUpdateMany.mockResolvedValue({ modifiedCount: 0 });
}

// Override the redis mock for webhook tests
vi.mock('../../config/redis.js', () => ({
  redis: {
    get: mockRedisGetP25,
    set: mockRedisSetP25,
  },
}));

// Override Organization mock for webhook tests
vi.mock('../organization/Organization.js', () => ({
  Organization: {
    findOneAndUpdate:    mockOrgFindOneAndUpdate,
    updateOne:           mockOrgUpdateOne,
    findByIdAndUpdate:   mockOrgFindByIdAndUpdate,
    findOne:             mockOrgFindOne,
  },
}));

describe('Property 25: Stripe Webhook Signature Enforcement (Req 8.5)', () => {
  beforeEach(() => resetWebhookMocks());

  // -------------------------------------------------------------------------
  // P25-a: Any invalid signature always throws with statusCode 400
  // -------------------------------------------------------------------------
  it('throws with statusCode 400 for any invalid Stripe signature', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 256 }), // arbitrary invalid signature
        fc.string({ minLength: 1, maxLength: 64 }),  // arbitrary raw body content
        async (invalidSig, bodyContent) => {
          resetWebhookMocks();

          // Simulate Stripe rejecting the signature
          mockConstructEvent.mockImplementation(() => {
            throw new Error('No signatures found matching the expected signature for payload');
          });

          const rawBody = Buffer.from(bodyContent);

          await expect(
            handleWebhookEvent(rawBody, invalidSig)
          ).rejects.toMatchObject({ statusCode: 400 });

          // constructEvent must have been called with the raw body and signature
          expect(mockConstructEvent).toHaveBeenCalledTimes(1);
          const [calledBody, calledSig] = mockConstructEvent.mock.calls[0];
          expect(calledBody).toEqual(rawBody);
          expect(calledSig).toBe(invalidSig);
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P25-b: Signature verification is always called before any processing
  // -------------------------------------------------------------------------
  it('constructEvent is always called before any DB or Redis operations', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 128 }),
        async (sig) => {
          resetWebhookMocks();

          // Reject immediately — no DB/Redis calls should happen
          mockConstructEvent.mockImplementation(() => {
            throw new Error('Invalid signature');
          });

          await expect(
            handleWebhookEvent(Buffer.from('body'), sig)
          ).rejects.toMatchObject({ statusCode: 400 });

          // Redis and DB must NOT have been touched
          expect(mockRedisGetP25).not.toHaveBeenCalled();
          expect(mockRedisSetP25).not.toHaveBeenCalled();
          expect(mockOrgFindByIdAndUpdate).not.toHaveBeenCalled();
          expect(mockOrgFindOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P25-c: Valid signature allows processing to proceed (no throw)
  // -------------------------------------------------------------------------
  it('does not throw when constructEvent succeeds (valid signature)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),                                    // event ID
        fc.constantFrom('payment_intent.created', 'invoice.paid', 'charge.succeeded'),
        async (eventId, eventType) => {
          resetWebhookMocks();

          // Use an unhandled event type so no DB calls are needed
          const event = makeStripeEvent(eventId, eventType, {});

          mockConstructEvent.mockReturnValue(event);
          mockRedisGetP25.mockResolvedValue(null); // not yet processed

          await expect(
            handleWebhookEvent(Buffer.from('{}'), 't=123,v1=abc')
          ).resolves.toBeUndefined();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P25-d: Error message always contains signature failure context
  // -------------------------------------------------------------------------
  it('thrown error message always references signature verification failure', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 128 }),
        async (stripeErrMsg) => {
          resetWebhookMocks();

          mockConstructEvent.mockImplementation(() => {
            throw new Error(stripeErrMsg);
          });

          let caughtError: Error | null = null;
          try {
            await handleWebhookEvent(Buffer.from('body'), 'bad-sig');
          } catch (err) {
            caughtError = err as Error;
          }

          expect(caughtError).not.toBeNull();
          expect(caughtError!.message).toContain('Webhook signature verification failed');
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ===========================================================================
// Property 26: Stripe Webhook Idempotency
// Feature: quantum-bridge, Property 26
// Requirements: 8.5, 8.6, 8.7
//
// FOR ALL valid webhook events, processing the same event ID a second time
// SHALL be a no-op — no DB writes or state changes SHALL occur.
// The first delivery SHALL be processed normally.
// The idempotency key SHALL be stored in Redis with a 24h TTL.
// ===========================================================================

describe('Property 26: Stripe Webhook Idempotency (Req 8.5, 8.6, 8.7)', () => {
  beforeEach(() => resetWebhookMocks());

  // -------------------------------------------------------------------------
  // P26-a: Duplicate event IDs are silently skipped (no DB writes)
  // -------------------------------------------------------------------------
  it('duplicate event delivery causes no DB writes', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(), // event ID
        async (eventId) => {
          resetWebhookMocks();

          const event = makeStripeEvent(eventId, 'checkout.session.completed', {
            id: 'cs_test',
            metadata: { orgId: 'aabbccddeeff001122334455', plan: 'pro' },
          });

          mockConstructEvent.mockReturnValue(event);

          // Simulate: event already processed (Redis key exists)
          mockRedisGetP25.mockResolvedValue('1');

          await handleWebhookEvent(Buffer.from('{}'), 'valid-sig');

          // No DB writes should have occurred
          expect(mockOrgFindByIdAndUpdate).not.toHaveBeenCalled();
          expect(mockOrgFindOne).not.toHaveBeenCalled();
          expect(mockEndpointUpdateMany).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P26-b: Idempotency key is set in Redis after first successful processing
  // -------------------------------------------------------------------------
  it('idempotency key is stored in Redis with 24h TTL after first processing', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (eventId) => {
          resetWebhookMocks();

          const event = makeStripeEvent(eventId, 'payment_intent.created', {});
          mockConstructEvent.mockReturnValue(event);
          mockRedisGetP25.mockResolvedValue(null); // first delivery

          await handleWebhookEvent(Buffer.from('{}'), 'valid-sig');

          // Redis SET must have been called with the correct key and 24h TTL
          expect(mockRedisSetP25).toHaveBeenCalledWith(
            `stripe:event:${eventId}`,
            '1',
            'EX',
            86_400
          );
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P26-c: Idempotency key format is always `stripe:event:{eventId}`
  // -------------------------------------------------------------------------
  it('idempotency key always follows the stripe:event:{id} format', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (eventId) => {
          resetWebhookMocks();

          const event = makeStripeEvent(eventId, 'payment_intent.created', {});
          mockConstructEvent.mockReturnValue(event);
          mockRedisGetP25.mockResolvedValue(null);

          await handleWebhookEvent(Buffer.from('{}'), 'valid-sig');

          // The GET call must use the correct key format
          expect(mockRedisGetP25).toHaveBeenCalledWith(`stripe:event:${eventId}`);
          // The SET call must use the same key
          expect(mockRedisSetP25).toHaveBeenCalledWith(
            `stripe:event:${eventId}`,
            '1',
            'EX',
            86_400
          );
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P26-d: Idempotency key is NOT set when signature verification fails
  // -------------------------------------------------------------------------
  it('idempotency key is never stored when signature verification fails', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (eventId) => {
          resetWebhookMocks();

          mockConstructEvent.mockImplementation(() => {
            throw new Error('Invalid signature');
          });

          await expect(
            handleWebhookEvent(Buffer.from('{}'), 'bad-sig')
          ).rejects.toMatchObject({ statusCode: 400 });

          // Redis SET must NOT have been called
          expect(mockRedisSetP25).not.toHaveBeenCalled();

          void eventId;
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P26-e: First delivery is always processed (Redis key absent → DB write occurs)
  // -------------------------------------------------------------------------
  it('first delivery of checkout.session.completed always triggers a DB update', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.constantFrom('pro' as const, 'enterprise' as const),
        async (eventId, plan) => {
          resetWebhookMocks();

          const orgId = 'aabbccddeeff001122334455';
          const event = makeStripeEvent(eventId, 'checkout.session.completed', {
            id: 'cs_test',
            metadata: { orgId, plan },
            customer: 'cus_test',
            subscription: 'sub_test',
          });

          mockConstructEvent.mockReturnValue(event);
          mockRedisGetP25.mockResolvedValue(null); // first delivery
          mockOrgFindByIdAndUpdate.mockResolvedValue({ name: 'Test Org', plan });

          await handleWebhookEvent(Buffer.from('{}'), 'valid-sig');

          // DB update must have been called with the correct orgId and plan
          expect(mockOrgFindByIdAndUpdate).toHaveBeenCalledTimes(1);
          expect(mockOrgFindByIdAndUpdate).toHaveBeenCalledWith(
            orgId,
            expect.objectContaining({ plan, monthlyRequestCount: 0 }),
            expect.any(Object)
          );
        }
      ),
      { numRuns: 20 }
    );
  });
});
