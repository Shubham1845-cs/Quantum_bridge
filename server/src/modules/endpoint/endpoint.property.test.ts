/**
 * Property-based tests for Endpoint module (P14–P15, P18)
 * Feature: quantum-bridge
 *
 * Requirements: 5.1, 5.2, 5.7, 8.1
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockEndpointCreate,
  mockEndpointFindOne,
  mockEndpointCountDocuments,
  mockEndpointSave,
  mockOrgFindById,
  mockOrgFindOne,
  mockOrgMemberFindOne,
  mockRedisPublish,
  mockWriteAuditLog,
} = vi.hoisted(() => {
  const mockSave = vi.fn().mockResolvedValue(undefined);
  return {
    mockEndpointCreate: vi.fn(),
    mockEndpointFindOne: vi.fn(),
    mockEndpointCountDocuments: vi.fn(),
    mockEndpointSave: mockSave,
    mockOrgFindById: vi.fn(),
    mockOrgFindOne: vi.fn(),
    mockOrgMemberFindOne: vi.fn(),
    mockRedisPublish: vi.fn().mockResolvedValue(1),
    mockWriteAuditLog: vi.fn().mockResolvedValue(undefined),
  };
});

vi.mock('../../config/env.js', () => ({
  env: {
    NODE_ENV: 'test',
  },
}));

vi.mock('../../utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../utils/auditLog.js', () => ({
  writeAuditLog: mockWriteAuditLog,
}));

vi.mock('./Endpoint.js', () => ({
  Endpoint: {
    create: mockEndpointCreate,
    findOne: mockEndpointFindOne,
    countDocuments: mockEndpointCountDocuments,
    find: vi.fn().mockReturnValue({ sort: vi.fn().mockResolvedValue([]) }),
  },
}));

vi.mock('../organization/Organization.js', () => ({
  Organization: {
    findById: mockOrgFindById,
    findOne: mockOrgFindOne,
  },
}));

vi.mock('../organization/OrgMember.js', () => ({
  OrgMember: {
    findOne: mockOrgMemberFindOne,
  },
}));

vi.mock('../../config/redis.js', () => ({
  redis: {
    publish: mockRedisPublish,
  },
}));

// Import after mocks
import {
  create,
  regenerateApiKey,
  PaymentRequiredError,
  NotFoundError,
  ForbiddenError,
} from './endpointService.js';
import { hashApiKey, verifyApiKey } from './apiKey.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PLAN_LIMITS: Record<string, number> = {
  free: 1,
  pro: 10,
  enterprise: Infinity,
};

// Valid 24-char hex MongoDB ObjectId strings
const VALID_ORG_ID    = 'aabbccddeeff001122334455';
const VALID_USER_ID   = '112233445566778899aabbcc';
const VALID_EP_ID     = '665544332211ffeeddccbbaa';

function makeMember(role: 'owner' | 'admin' | 'viewer', userId = VALID_USER_ID) {
  return {
    _id: { toString: () => 'member-id' },
    orgId: { toString: () => VALID_ORG_ID },
    userId: { toString: () => userId },
    role,
    status: 'active' as const,
  };
}

function makeOrg(plan: 'free' | 'pro' | 'enterprise', slug = 'test-org') {
  return {
    _id: { toString: () => VALID_ORG_ID },
    slug,
    plan,
  };
}

function makeEndpoint(overrides: Record<string, unknown> = {}) {
  return {
    _id: { toString: () => VALID_EP_ID },
    orgId: { toString: () => VALID_ORG_ID },
    name: 'Test Endpoint',
    targetUrl: 'https://api.example.com',
    proxySlug: 'abc12345',
    apiKeyHash: hashApiKey('initial-raw-key'),
    ipAllowlist: [],
    isActive: true,
    requestCount: 0,
    save: mockEndpointSave,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Property 14: Plan Endpoint Limit Enforcement
// Feature: quantum-bridge, Property 14
//
// FOR ALL (plan, currentCount) pairs where currentCount >= planLimit,
// create() MUST throw PaymentRequiredError (402) and MUST NOT persist any
// endpoint record.
// Requirements: 5.2, 5.3, 8.1
// ---------------------------------------------------------------------------
describe('Property 14: Plan Endpoint Limit Enforcement (Req 5.2, 5.3, 8.1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws PaymentRequiredError when free plan is at its 1-endpoint limit', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 10 }), // currentCount >= 1 (the free limit)
        async (currentCount) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('free'));
          mockEndpointCountDocuments.mockResolvedValue(currentCount);

          await expect(
            create(VALID_ORG_ID, VALID_USER_ID, {
              name: 'New Endpoint',
              targetUrl: 'https://api.example.com',
            }, '127.0.0.1')
          ).rejects.toThrow(PaymentRequiredError);

          // No endpoint must have been created
          expect(mockEndpointCreate).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  it('throws PaymentRequiredError when pro plan is at its 10-endpoint limit', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 10, max: 20 }), // currentCount >= 10 (the pro limit)
        async (currentCount) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('pro'));
          mockEndpointCountDocuments.mockResolvedValue(currentCount);

          await expect(
            create(VALID_ORG_ID, VALID_USER_ID, {
              name: 'New Endpoint',
              targetUrl: 'https://api.example.com',
            }, '127.0.0.1')
          ).rejects.toThrow(PaymentRequiredError);

          expect(mockEndpointCreate).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  it('enterprise plan never hits a limit regardless of endpoint count', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 10_000 }),
        async (currentCount) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('enterprise'));
          mockEndpointCountDocuments.mockResolvedValue(currentCount);

          const proxySlug = 'ab12cd34';
          mockEndpointCreate.mockResolvedValue(makeEndpoint({ proxySlug }));

          // Should not throw — enterprise is unlimited
          await expect(
            create(VALID_ORG_ID, VALID_USER_ID, {
              name: 'New Endpoint',
              targetUrl: 'https://api.example.com',
            }, '127.0.0.1')
          ).resolves.toBeDefined();

          expect(mockEndpointCreate).toHaveBeenCalledTimes(1);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('create() succeeds when count is strictly below the plan limit', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('free' as const, 'pro' as const),
        async (plan) => {
          vi.clearAllMocks();

          const limit = PLAN_LIMITS[plan];
          const currentCount = limit - 1; // one slot remaining

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg(plan));
          mockEndpointCountDocuments.mockResolvedValue(currentCount);
          mockEndpointCreate.mockResolvedValue(makeEndpoint({ proxySlug: 'ab12cd34' }));

          await expect(
            create(VALID_ORG_ID, VALID_USER_ID, {
              name: 'New Endpoint',
              targetUrl: 'https://api.example.com',
            }, '127.0.0.1')
          ).resolves.toBeDefined();

          expect(mockEndpointCreate).toHaveBeenCalledTimes(1);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('plan limit is monotonically ordered: free < pro < enterprise', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 100 }),
        (_seed) => {
          expect(PLAN_LIMITS.free).toBeLessThan(PLAN_LIMITS.pro);
          expect(PLAN_LIMITS.pro).toBeLessThan(PLAN_LIMITS.enterprise);
          expect(PLAN_LIMITS.enterprise).toBe(Infinity);
        }
      ),
      { numRuns: 1 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 15: Proxy URL Format
// Feature: quantum-bridge, Property 15
//
// FOR ALL (orgSlug, proxySlug) pairs produced by create(), the returned
// proxyUrl MUST match the canonical format:
//   https://proxy.quantumbridge.io/{orgSlug}/{proxySlug}/
// Requirements: 5.1
// ---------------------------------------------------------------------------
describe('Property 15: Proxy URL Format (Req 5.1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('proxyUrl always matches https://proxy.quantumbridge.io/{orgSlug}/{proxySlug}/', async () => {
    await fc.assert(
      fc.asyncProperty(
        // org slugs: lowercase alphanumeric + hyphens
        fc.stringMatching(/^[a-z][a-z0-9-]{0,30}[a-z0-9]$/),
        async (orgSlug) => {
          vi.clearAllMocks();

          // The service generates its own proxySlug internally — we capture it from the result
          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('pro', orgSlug));
          mockEndpointCountDocuments.mockResolvedValue(0);
          // Return a mock endpoint; the service uses its own generated proxySlug for the URL
          mockEndpointCreate.mockImplementation(async (data: { proxySlug: string }) =>
            makeEndpoint({ proxySlug: data.proxySlug })
          );

          const result = await create(VALID_ORG_ID, VALID_USER_ID, {
            name: 'Test',
            targetUrl: 'https://api.example.com',
          }, '127.0.0.1');

          // Extract the proxySlug from the returned URL
          const parsed = new URL(result.proxyUrl);
          const segments = parsed.pathname.split('/').filter(Boolean);
          const returnedProxySlug = segments[1];

          // Verify the URL matches the canonical format exactly
          const expectedUrl = `https://proxy.quantumbridge.io/${orgSlug}/${returnedProxySlug}/`;
          expect(result.proxyUrl).toBe(expectedUrl);

          // proxySlug must be 8 hex chars (as generated by generateProxySlug)
          expect(returnedProxySlug).toMatch(/^[0-9a-f]{8}$/);
        }
      ),
      { numRuns: 50 }
    );
  });

  it('proxyUrl always starts with https://proxy.quantumbridge.io/', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{0,20}[a-z0-9]$/),
        async (orgSlug) => {
          vi.clearAllMocks();

          const proxySlug = 'ab12cd34';
          mockOrgMemberFindOne.mockResolvedValue(makeMember('owner'));
          mockOrgFindById.mockResolvedValue(makeOrg('enterprise', orgSlug));
          mockEndpointCountDocuments.mockResolvedValue(0);
          mockEndpointCreate.mockResolvedValue(makeEndpoint({ proxySlug }));

          const result = await create(VALID_ORG_ID, VALID_USER_ID, {
            name: 'Test',
            targetUrl: 'https://api.example.com',
          }, '127.0.0.1');

          expect(result.proxyUrl).toMatch(/^https:\/\/proxy\.quantumbridge\.io\//);
          expect(result.proxyUrl).toMatch(/\/$/); // must end with trailing slash
        }
      ),
      { numRuns: 30 }
    );
  });

  it('proxyUrl is a valid URL for any org/proxy slug combination', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{0,20}[a-z0-9]$/),
        fc.stringMatching(/^[0-9a-f]{8}$/),
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('pro', orgSlug));
          mockEndpointCountDocuments.mockResolvedValue(0);
          mockEndpointCreate.mockResolvedValue(makeEndpoint({ proxySlug }));

          const result = await create(VALID_ORG_ID, VALID_USER_ID, {
            name: 'Test',
            targetUrl: 'https://api.example.com',
          }, '127.0.0.1');

          // Must parse as a valid URL without throwing
          expect(() => new URL(result.proxyUrl)).not.toThrow();
          const parsed = new URL(result.proxyUrl);
          expect(parsed.protocol).toBe('https:');
          expect(parsed.hostname).toBe('proxy.quantumbridge.io');
        }
      ),
      { numRuns: 30 }
    );
  });

  it('proxyUrl embeds the org slug and proxy slug in the correct path positions', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/),
        async (orgSlug) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockOrgFindById.mockResolvedValue(makeOrg('pro', orgSlug));
          mockEndpointCountDocuments.mockResolvedValue(0);
          mockEndpointCreate.mockImplementation(async (data: { proxySlug: string }) =>
            makeEndpoint({ proxySlug: data.proxySlug })
          );

          const result = await create(VALID_ORG_ID, VALID_USER_ID, {
            name: 'Test',
            targetUrl: 'https://api.example.com',
          }, '127.0.0.1');

          const parsed = new URL(result.proxyUrl);
          const segments = parsed.pathname.split('/').filter(Boolean);

          // Path must be: /{orgSlug}/{proxySlug}/  — exactly 2 segments
          expect(segments).toHaveLength(2);
          // First segment must be the org slug
          expect(segments[0]).toBe(orgSlug);
          // Second segment must be an 8-char hex proxy slug
          expect(segments[1]).toMatch(/^[0-9a-f]{8}$/);
        }
      ),
      { numRuns: 30 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 18: API Key Rotation Invalidation
// Feature: quantum-bridge, Property 18
//
// FOR ALL regenerateApiKey calls:
//   1. The new raw key MUST hash to the value stored on the endpoint record.
//   2. The old key hash MUST NOT match the new raw key.
//   3. A cache invalidation event MUST be published to Redis.
//   4. The new raw key MUST be returned exactly once (not stored in plaintext).
// Requirements: 5.7
// ---------------------------------------------------------------------------
describe('Property 18: API Key Rotation Invalidation (Req 5.7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('new raw key hashes to the value saved on the endpoint record', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexaString({ minLength: 64, maxLength: 64 }), // simulate old key hash
        async (oldKeyHash) => {
          vi.clearAllMocks();

          let savedHash = oldKeyHash;
          const endpoint = makeEndpoint({
            apiKeyHash: oldKeyHash,
            save: vi.fn().mockImplementation(async function (this: { apiKeyHash: string }) {
              savedHash = this.apiKeyHash;
            }),
          });

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockEndpointFindOne.mockResolvedValue(endpoint);
          mockOrgFindById.mockReturnValue({
            select: vi.fn().mockResolvedValue(makeOrg('pro')),
          });

          const result = await regenerateApiKey(
            VALID_ORG_ID,
            VALID_EP_ID,
            VALID_USER_ID,
            '127.0.0.1'
          );

          // The returned raw key must hash to what was saved
          expect(hashApiKey(result.apiKey)).toBe(savedHash);
          expect(verifyApiKey(result.apiKey, savedHash)).toBe(true);
        }
      ),
      { numRuns: 30 }
    );
  });

  it('old key hash does not verify against the new raw key', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexaString({ minLength: 64, maxLength: 64 }), // old key hash
        async (oldKeyHash) => {
          vi.clearAllMocks();

          const endpoint = makeEndpoint({ apiKeyHash: oldKeyHash });

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockEndpointFindOne.mockResolvedValue(endpoint);
          mockOrgFindById.mockReturnValue({
            select: vi.fn().mockResolvedValue(makeOrg('pro')),
          });

          const result = await regenerateApiKey(
            VALID_ORG_ID,
            VALID_EP_ID,
            VALID_USER_ID,
            '127.0.0.1'
          );

          // Old hash must not match the new raw key
          expect(verifyApiKey(result.apiKey, oldKeyHash)).toBe(false);
        }
      ),
      { numRuns: 30 }
    );
  });

  it('cache invalidation is published to Redis on every key rotation', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/), // orgSlug
        fc.stringMatching(/^[0-9a-f]{8}$/),                    // proxySlug
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();

          const endpoint = makeEndpoint({ proxySlug });

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockEndpointFindOne.mockResolvedValue(endpoint);
          mockOrgFindById.mockReturnValue({
            select: vi.fn().mockResolvedValue(makeOrg('pro', orgSlug)),
          });

          await regenerateApiKey(
            VALID_ORG_ID,
            VALID_EP_ID,
            VALID_USER_ID,
            '127.0.0.1'
          );

          // Redis publish must have been called with the invalidation channel
          expect(mockRedisPublish).toHaveBeenCalledTimes(1);
          expect(mockRedisPublish).toHaveBeenCalledWith(
            'endpoint:invalidate',
            JSON.stringify({ orgSlug, proxySlug })
          );
        }
      ),
      { numRuns: 30 }
    );
  });

  it('new raw key is never equal to its own hash (not stored in plaintext)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(undefined),
        async () => {
          vi.clearAllMocks();

          const endpoint = makeEndpoint();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockEndpointFindOne.mockResolvedValue(endpoint);
          mockOrgFindById.mockReturnValue({
            select: vi.fn().mockResolvedValue(makeOrg('pro')),
          });

          const result = await regenerateApiKey(
            VALID_ORG_ID,
            VALID_EP_ID,
            VALID_USER_ID,
            '127.0.0.1'
          );

          // Raw key must not equal its own SHA-256 hash
          expect(result.apiKey).not.toBe(hashApiKey(result.apiKey));
          // Raw key must be 64 hex chars (32 random bytes)
          expect(result.apiKey).toMatch(/^[0-9a-f]{64}$/);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('regenerateApiKey throws NotFoundError for non-existent or inactive endpoints', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(undefined),
        async () => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin'));
          mockEndpointFindOne.mockResolvedValue(null); // not found

          await expect(
            regenerateApiKey(VALID_ORG_ID, VALID_EP_ID, VALID_USER_ID, '127.0.0.1')
          ).rejects.toThrow(NotFoundError);

          // No Redis publish on failure
          expect(mockRedisPublish).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });

  it('viewer cannot regenerate an API key (write operation blocked)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(undefined),
        async () => {
          vi.clearAllMocks();

          mockOrgMemberFindOne.mockResolvedValue(makeMember('viewer'));

          await expect(
            regenerateApiKey(VALID_ORG_ID, VALID_EP_ID, VALID_USER_ID, '127.0.0.1')
          ).rejects.toThrow(ForbiddenError);

          expect(mockEndpointFindOne).not.toHaveBeenCalled();
          expect(mockRedisPublish).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });
});
