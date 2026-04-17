/**
 * Property 27: Webhook URL HTTPS Enforcement
 * Property 28: Webhook Payload Completeness
 * Property 29: Webhook Retry Bound
 * Feature: quantum-bridge, Property 27, 28, 29
 *
 * Requirements: 9.1, 9.3, 9.4
 *
 * Property 27: FOR ALL webhook registration attempts with a non-HTTPS URL,
 *   the register function SHALL throw a WebhookError with statusCode 422.
 *   FOR ALL HTTPS URLs that are reachable, registration SHALL succeed.
 *
 * Property 28: FOR ALL ThreatEvent inputs, the delivered payload SHALL contain
 *   all required fields: orgId, endpointId, requestId, timestamp, threatType,
 *   ecdsaVerified, dilithiumVerified — and SHALL be signed with HMAC-SHA256.
 *
 * Property 29: FOR ALL failure scenarios, the delivery system SHALL make at
 *   most MAX_ATTEMPTS (3) delivery attempts per webhook URL — never more.
 *   After 3 failures the status SHALL be permanently_failed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fc from 'fast-check';
import { createHmac } from 'node:crypto';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockWebhookConfigCreate,
  mockWebhookConfigFind,
  mockWebhookDeliveryCreate,
  mockAuditLogCreate,
  mockFetch,
} = vi.hoisted(() => ({
  mockWebhookConfigCreate:   vi.fn(),
  mockWebhookConfigFind:     vi.fn(),
  mockWebhookDeliveryCreate: vi.fn(),
  mockAuditLogCreate:        vi.fn(),
  mockFetch:                 vi.fn(),
}));

vi.mock('./WebhookConfig.js', () => ({
  WebhookConfig: {
    create: mockWebhookConfigCreate,
    find:   mockWebhookConfigFind,
  },
}));

vi.mock('./WebhookDelivery.js', () => ({
  WebhookDelivery: {
    create: mockWebhookDeliveryCreate,
    find:   vi.fn().mockReturnValue({
      sort:  vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      lean:  vi.fn().mockResolvedValue([]),
    }),
  },
}));

vi.mock('../../utils/auditLog.js', () => ({
  writeAuditLog: mockAuditLogCreate,
}));

vi.mock('../../utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// Mock global fetch
vi.stubGlobal('fetch', mockFetch);

import { register, deliver, WebhookError, type ThreatEvent } from './webhookService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_ORG_ID  = 'aabbccddeeff001122334455';
const VALID_ACTOR   = 'bbccddeeff001122334455aa';
const VALID_IP      = '127.0.0.1';
const WEBHOOK_SECRET = 'a'.repeat(64); // 32 bytes hex

function makeConfig(url = 'https://example.com/hook') {
  return {
    _id:      { toString: () => 'webhookid123' },
    orgId:    { toString: () => VALID_ORG_ID },
    url,
    secret:   WEBHOOK_SECRET,
    isActive: true,
  };
}

function makeThreatEvent(overrides: Partial<ThreatEvent> = {}): ThreatEvent {
  return {
    orgId:            VALID_ORG_ID,
    endpointId:       'endpointid123',
    requestId:        'req-uuid-1234',
    timestamp:        new Date('2025-01-01T00:00:00Z'),
    threatType:       'signature_failure',
    ecdsaVerified:    false,
    dilithiumVerified: false,
    ...overrides,
  };
}

function resetMocks() {
  vi.clearAllMocks();
  mockWebhookDeliveryCreate.mockResolvedValue({});
  mockAuditLogCreate.mockResolvedValue(undefined);
}

// ===========================================================================
// Property 27: Webhook URL HTTPS Enforcement
// Feature: quantum-bridge, Property 27
// Requirements: 9.1
// ===========================================================================

describe('Property 27: Webhook URL HTTPS Enforcement (Req 9.1)', () => {
  beforeEach(() => resetMocks());

  // -------------------------------------------------------------------------
  // P27-a: Any non-HTTPS URL always throws WebhookError with statusCode 422
  // -------------------------------------------------------------------------
  it('throws WebhookError(422) for any non-HTTPS URL', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          // http:// URLs
          fc.webUrl().map((u) => u.replace(/^https?:\/\//, 'http://')),
          // ftp, ws, etc.
          fc.constantFrom(
            'ftp://example.com/hook',
            'ws://example.com/hook',
            'http://localhost/hook',
            'http://192.168.1.1/hook',
          ),
          // plain hostnames (no protocol)
          fc.domain().map((d) => `${d}/hook`),
        ),
        async (url) => {
          resetMocks();

          await expect(
            register(VALID_ORG_ID, url, VALID_ACTOR, VALID_IP)
          ).rejects.toMatchObject({ statusCode: 422 });

          // WebhookConfig.create must NOT have been called
          expect(mockWebhookConfigCreate).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P27-b: HTTPS URLs that are reachable succeed (no throw)
  // -------------------------------------------------------------------------
  it('does not throw for reachable HTTPS URLs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.domain().map((d) => `https://${d}/webhook`),
        async (url) => {
          resetMocks();

          // Mock fetch to simulate a reachable endpoint
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          const configId = 'cfg123';
          mockWebhookConfigCreate.mockResolvedValueOnce({
            _id: { toString: () => configId },
            orgId: { toString: () => VALID_ORG_ID },
            url,
            secret: WEBHOOK_SECRET,
            isActive: true,
          });

          await expect(
            register(VALID_ORG_ID, url, VALID_ACTOR, VALID_IP)
          ).resolves.toBeDefined();

          expect(mockWebhookConfigCreate).toHaveBeenCalledTimes(1);
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P27-c: Unreachable HTTPS URLs throw WebhookError(422)
  // -------------------------------------------------------------------------
  it('throws WebhookError(422) when the HTTPS URL is unreachable', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.domain().map((d) => `https://${d}/webhook`),
        async (url) => {
          resetMocks();

          // Simulate network failure
          mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

          await expect(
            register(VALID_ORG_ID, url, VALID_ACTOR, VALID_IP)
          ).rejects.toMatchObject({ statusCode: 422 });

          expect(mockWebhookConfigCreate).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P27-d: WebhookError always has the correct name and is an Error instance
  // -------------------------------------------------------------------------
  it('WebhookError is always an Error with name WebhookError', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 128 }),
        fc.integer({ min: 400, max: 599 }),
        (msg, code) => {
          const err = new WebhookError(msg, code);
          expect(err).toBeInstanceOf(Error);
          expect(err.name).toBe('WebhookError');
          expect(err.statusCode).toBe(code);
          expect(err.message).toBe(msg);
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ===========================================================================
// Property 28: Webhook Payload Completeness
// Feature: quantum-bridge, Property 28
// Requirements: 9.3
//
// Tests that the payload POSTed to the webhook URL contains all required
// fields and is correctly HMAC-SHA256 signed.
// We capture the fetch call arguments to inspect the payload.
// ===========================================================================

const REQUIRED_PAYLOAD_FIELDS = [
  'orgId', 'endpointId', 'requestId', 'timestamp',
  'threatType', 'ecdsaVerified', 'dilithiumVerified',
] as const;

describe('Property 28: Webhook Payload Completeness (Req 9.3)', () => {
  beforeEach(() => resetMocks());

  // -------------------------------------------------------------------------
  // P28-a: Payload always contains all required fields
  // -------------------------------------------------------------------------
  it('delivered payload always contains all required fields', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.uuid(),
        fc.constantFrom('signature_failure' as const, 'invalid_api_key' as const),
        fc.boolean(),
        fc.boolean(),
        async (orgId, endpointId, requestId, threatType, ecdsaVerified, dilithiumVerified) => {
          resetMocks();

          const event = makeThreatEvent({ orgId, endpointId, requestId, threatType, ecdsaVerified, dilithiumVerified });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          // Simulate successful delivery on first attempt
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(orgId, event);

          expect(mockFetch).toHaveBeenCalledTimes(1);

          const [, fetchOptions] = mockFetch.mock.calls[0] as [string, RequestInit];
          const body = JSON.parse(fetchOptions.body as string) as Record<string, unknown>;

          for (const field of REQUIRED_PAYLOAD_FIELDS) {
            expect(body).toHaveProperty(field);
          }
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P28-b: Payload field values match the ThreatEvent input exactly
  // -------------------------------------------------------------------------
  it('payload field values always match the ThreatEvent input', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.uuid(),
        fc.constantFrom('signature_failure' as const, 'invalid_api_key' as const),
        fc.boolean(),
        fc.boolean(),
        async (orgId, endpointId, requestId, threatType, ecdsaVerified, dilithiumVerified) => {
          resetMocks();

          const timestamp = new Date('2025-06-01T12:00:00Z');
          const event = makeThreatEvent({ orgId, endpointId, requestId, threatType, ecdsaVerified, dilithiumVerified, timestamp });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(orgId, event);

          const [, fetchOptions] = mockFetch.mock.calls[0] as [string, RequestInit];
          const body = JSON.parse(fetchOptions.body as string) as Record<string, unknown>;

          expect(body.orgId).toBe(orgId);
          expect(body.endpointId).toBe(endpointId);
          expect(body.requestId).toBe(requestId);
          expect(body.threatType).toBe(threatType);
          expect(body.ecdsaVerified).toBe(ecdsaVerified);
          expect(body.dilithiumVerified).toBe(dilithiumVerified);
          expect(body.timestamp).toBe(timestamp.getTime());
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P28-c: Payload is always signed with HMAC-SHA256 using the webhook secret
  // -------------------------------------------------------------------------
  it('X-QB-Signature header always matches HMAC-SHA256 of the payload body', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.boolean(),
        fc.boolean(),
        async (requestId, ecdsaVerified, dilithiumVerified) => {
          resetMocks();

          const event = makeThreatEvent({ requestId, ecdsaVerified, dilithiumVerified });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(VALID_ORG_ID, event);

          const [, fetchOptions] = mockFetch.mock.calls[0] as [string, RequestInit];
          const headers = fetchOptions.headers as Record<string, string>;
          const bodyStr = fetchOptions.body as string;

          // Recompute expected signature
          const expectedSig = createHmac('sha256', WEBHOOK_SECRET)
            .update(bodyStr)
            .digest('hex');

          expect(headers['X-QB-Signature']).toBe(expectedSig);
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P28-d: Payload is sent as JSON with Content-Type: application/json
  // -------------------------------------------------------------------------
  it('payload is always sent as JSON with correct Content-Type header', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (requestId) => {
          resetMocks();

          const event = makeThreatEvent({ requestId });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(VALID_ORG_ID, event);

          const [, fetchOptions] = mockFetch.mock.calls[0] as [string, RequestInit];
          const headers = fetchOptions.headers as Record<string, string>;

          expect(headers['Content-Type']).toBe('application/json');
          // Body must be valid JSON
          expect(() => JSON.parse(fetchOptions.body as string)).not.toThrow();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P28-e: No delivery occurs when there are no registered webhooks
  // -------------------------------------------------------------------------
  it('no fetch calls are made when there are no active webhook configs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (orgId) => {
          resetMocks();

          mockWebhookConfigFind.mockResolvedValueOnce([]); // no webhooks

          await deliver(orgId, makeThreatEvent({ orgId }));

          expect(mockFetch).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ===========================================================================
// Property 29: Webhook Retry Bound
// Feature: quantum-bridge, Property 29
// Requirements: 9.4
//
// FOR ALL failure scenarios, the delivery system makes at most 3 attempts.
// After 3 consecutive failures the final status is permanently_failed.
// A success on any attempt stops further retries.
// ===========================================================================

describe('Property 29: Webhook Retry Bound (Req 9.4)', () => {
  beforeEach(() => {
    resetMocks();
    // Make setTimeout fire immediately so retry delays don't block tests.
    // The real sleep() in webhookService uses setTimeout — we replace it with
    // a version that resolves instantly, keeping the retry logic intact.
    vi.spyOn(global, 'setTimeout').mockImplementation((fn: TimerHandler) => {
      if (typeof fn === 'function') fn();
      return 0 as unknown as ReturnType<typeof setTimeout>;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // P29-a: Exactly 3 fetch attempts are made when all fail
  // -------------------------------------------------------------------------
  it('makes exactly 3 fetch attempts when all deliveries fail', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        // Non-2xx status codes
        fc.integer({ min: 400, max: 599 }),
        async (requestId, failStatus) => {
          resetMocks();

          const event = makeThreatEvent({ requestId });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          // All 3 attempts fail with non-2xx
          mockFetch
            .mockResolvedValueOnce({ status: failStatus, ok: false })
            .mockResolvedValueOnce({ status: failStatus, ok: false })
            .mockResolvedValueOnce({ status: failStatus, ok: false });

          await deliver(VALID_ORG_ID, event);

          expect(mockFetch).toHaveBeenCalledTimes(3);
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P29-b: Final delivery record is permanently_failed after 3 failures
  // -------------------------------------------------------------------------
  it('final WebhookDelivery record has status permanently_failed after 3 failures', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (requestId) => {
          resetMocks();

          const event = makeThreatEvent({ requestId });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          mockFetch
            .mockResolvedValueOnce({ status: 500, ok: false })
            .mockResolvedValueOnce({ status: 500, ok: false })
            .mockResolvedValueOnce({ status: 500, ok: false });

          await deliver(VALID_ORG_ID, event);

          // 3 WebhookDelivery records should have been created
          expect(mockWebhookDeliveryCreate).toHaveBeenCalledTimes(3);

          // The last call must have status: 'permanently_failed'
          const lastCall = mockWebhookDeliveryCreate.mock.calls[2][0] as Record<string, unknown>;
          expect(lastCall.status).toBe('permanently_failed');
          expect(lastCall.attempt).toBe(3);
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P29-c: Success on attempt N stops further retries (N < 3)
  // -------------------------------------------------------------------------
  it('stops retrying immediately after a successful delivery', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 3 }), // success on attempt N
        async (successAttempt) => {
          resetMocks();

          const event = makeThreatEvent();
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);

          // Fail attempts before successAttempt, succeed on successAttempt
          for (let i = 1; i < successAttempt; i++) {
            mockFetch.mockResolvedValueOnce({ status: 500, ok: false });
          }
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(VALID_ORG_ID, event);

          expect(mockFetch).toHaveBeenCalledTimes(successAttempt);

          // The delivery record for the successful attempt must be 'delivered'
          const successCall = mockWebhookDeliveryCreate.mock.calls[successAttempt - 1][0] as Record<string, unknown>;
          expect(successCall.status).toBe('delivered');
          expect(successCall.attempt).toBe(successAttempt);
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P29-d: Network errors count as failures (same retry bound applies)
  // -------------------------------------------------------------------------
  it('network errors count as failures and the 3-attempt bound still applies', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (requestId) => {
          resetMocks();

          const event = makeThreatEvent({ requestId });
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);
          // All 3 attempts throw network errors
          mockFetch
            .mockRejectedValueOnce(new Error('ECONNREFUSED'))
            .mockRejectedValueOnce(new Error('ETIMEDOUT'))
            .mockRejectedValueOnce(new Error('ECONNRESET'));

          await deliver(VALID_ORG_ID, event);

          expect(mockFetch).toHaveBeenCalledTimes(3);

          const lastCall = mockWebhookDeliveryCreate.mock.calls[2][0] as Record<string, unknown>;
          expect(lastCall.status).toBe('permanently_failed');
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P29-e: A WebhookDelivery record is written for every attempt
  // -------------------------------------------------------------------------
  it('a WebhookDelivery record is written for every attempt (1, 2, or 3)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 3 }), // success on attempt N
        async (successAttempt) => {
          resetMocks();

          const event = makeThreatEvent();
          const config = makeConfig();

          mockWebhookConfigFind.mockResolvedValueOnce([config]);

          for (let i = 1; i < successAttempt; i++) {
            mockFetch.mockResolvedValueOnce({ status: 500, ok: false });
          }
          mockFetch.mockResolvedValueOnce({ status: 200, ok: true });

          await deliver(VALID_ORG_ID, event);

          // One delivery record per attempt
          expect(mockWebhookDeliveryCreate).toHaveBeenCalledTimes(successAttempt);

          // Attempt numbers must be sequential starting at 1
          for (let i = 0; i < successAttempt; i++) {
            const call = mockWebhookDeliveryCreate.mock.calls[i][0] as Record<string, unknown>;
            expect(call.attempt).toBe(i + 1);
          }
        }
      ),
      { numRuns: 30 }
    );
  });
});
