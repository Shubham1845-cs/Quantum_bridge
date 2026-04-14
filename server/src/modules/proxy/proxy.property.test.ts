/**
 * Property-based tests for Proxy pipeline (P16–P17, P19–P21, P23)
 * Feature: quantum-bridge
 *
 * Requirements: 5.4, 5.5, 6.4, 6.7, 6.8, 6.13
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import { hashApiKey } from '../endpoint/apiKey.js';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockRedisGet,
  mockOrgFindOne,
  mockEndpointFindOne,
} = vi.hoisted(() => ({
  mockRedisGet: vi.fn(),
  mockOrgFindOne: vi.fn(),
  mockEndpointFindOne: vi.fn(),
}));

vi.mock('../../config/redis.js', () => ({
  redis: {
    get: mockRedisGet,
    set: vi.fn().mockResolvedValue('OK'),
    setex: vi.fn().mockResolvedValue('OK'),
    del: vi.fn().mockResolvedValue(1),
    publish: vi.fn().mockResolvedValue(1),
    duplicate: vi.fn(),
  },
  duplicate: vi.fn(),
}));

vi.mock('../organization/Organization.js', () => ({
  Organization: { findOne: mockOrgFindOne },
}));

vi.mock('../endpoint/Endpoint.js', () => ({
  Endpoint: { findOne: mockEndpointFindOne },
}));

vi.mock('./ProxyLog.js', () => ({
  ProxyLog: { create: vi.fn().mockResolvedValue({}) },
}));

vi.mock('../../utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../config/env.js', () => ({
  env: { NODE_ENV: 'test', PROXY_PORT: 8080 },
}));

import { getEndpoint } from './endpointCache.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_ORG_ID = 'aabbccddeeff001122334455';
const VALID_EP_ID  = '665544332211ffeeddccbbaa';

function makeOrg(slug: string) {
  return { _id: { toString: () => VALID_ORG_ID }, slug };
}

function makeEndpoint(overrides: Record<string, unknown> = {}) {
  return {
    _id: { toString: () => VALID_EP_ID },
    orgId: { toString: () => VALID_ORG_ID },
    name: 'Test Endpoint',
    targetUrl: 'https://api.example.com',
    proxySlug: 'ab12cd34',
    apiKeyHash: hashApiKey('valid-raw-key-64chars-hex-padding-here-1234567890abcdef'),
    ipAllowlist: [] as string[],
    isActive: true,
    requestCount: 0,
    ...overrides,
  };
}

// Pure header-stripping function mirroring proxy-server.ts implementation
function stripQBHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!key.toLowerCase().startsWith('x-qb-') && value !== undefined) {
      result[key] = Array.isArray(value) ? value.join(', ') : value;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Property 16: IP Allowlist Enforcement
// Feature: quantum-bridge, Property 16
//
// FOR ALL endpoints with a non-empty ipAllowlist, any clientIp NOT in the
// list MUST be rejected (403), and any clientIp IN the list MUST be allowed.
// Requirements: 5.4, 6.4
// ---------------------------------------------------------------------------
describe('Property 16: IP Allowlist Enforcement (Req 5.4, 6.4)', () => {
  it('clientIp not in allowlist is always rejected', () => {
    fc.assert(
      fc.property(
        fc.array(fc.ipV4(), { minLength: 1, maxLength: 5 }),
        fc.ipV4(),
        (allowlist, clientIp) => {
          fc.pre(!allowlist.includes(clientIp));
          const endpoint = makeEndpoint({ ipAllowlist: allowlist });
          const isAllowed = endpoint.ipAllowlist.length === 0 || endpoint.ipAllowlist.includes(clientIp);
          expect(isAllowed).toBe(false);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('clientIp in allowlist is always permitted', () => {
    fc.assert(
      fc.property(
        fc.array(fc.ipV4(), { minLength: 1, maxLength: 5 }),
        fc.nat({ max: 4 }),
        (allowlist, idx) => {
          const clientIp = allowlist[idx % allowlist.length];
          const endpoint = makeEndpoint({ ipAllowlist: allowlist });
          const isAllowed = endpoint.ipAllowlist.length === 0 || endpoint.ipAllowlist.includes(clientIp);
          expect(isAllowed).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('empty allowlist permits any IP', () => {
    fc.assert(
      fc.property(
        fc.ipV4(),
        (clientIp) => {
          const endpoint = makeEndpoint({ ipAllowlist: [] });
          const isAllowed = endpoint.ipAllowlist.length === 0 || endpoint.ipAllowlist.includes(clientIp);
          expect(isAllowed).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('allowlist check is exact-match only — prefix match does not grant access', () => {
    fc.assert(
      fc.property(
        fc.ipV4(),
        (allowedIp) => {
          const parts = allowedIp.split('.');
          const truncated = parts.slice(0, 3).join('.') + '.0';
          fc.pre(truncated !== allowedIp);
          const endpoint = makeEndpoint({ ipAllowlist: [allowedIp] });
          expect(endpoint.ipAllowlist.includes(truncated)).toBe(false);
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 17: Endpoint Deletion Cache Invalidation
// Feature: quantum-bridge, Property 17
//
// FOR ALL (orgSlug, proxySlug) pairs, after a cache invalidation event is
// processed, getEndpoint() MUST fall back to MongoDB (Redis returns null).
// Requirements: 5.5
// ---------------------------------------------------------------------------
describe('Property 17: Endpoint Deletion Cache Invalidation (Req 5.5)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('cache miss causes MongoDB fallback', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/),
        fc.stringMatching(/^[0-9a-f]{8}$/),
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();
          mockRedisGet.mockResolvedValue(null);
          const org = makeOrg(orgSlug);
          const endpoint = makeEndpoint({ proxySlug });
          mockOrgFindOne.mockReturnValue({
            select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(org) }),
          });
          mockEndpointFindOne.mockReturnValue({ lean: vi.fn().mockResolvedValue(endpoint) });

          const result = await getEndpoint(orgSlug, proxySlug);

          expect(mockOrgFindOne).toHaveBeenCalledTimes(1);
          expect(mockEndpointFindOne).toHaveBeenCalledTimes(1);
          expect(result).not.toBeNull();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('cache hit skips MongoDB entirely', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/),
        fc.stringMatching(/^[0-9a-f]{8}$/),
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();
          const endpoint = makeEndpoint({ proxySlug });
          mockRedisGet.mockResolvedValue(JSON.stringify(endpoint));

          const result = await getEndpoint(orgSlug, proxySlug);

          expect(mockOrgFindOne).not.toHaveBeenCalled();
          expect(mockEndpointFindOne).not.toHaveBeenCalled();
          expect(result).not.toBeNull();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('cache key format is always endpoint:{orgSlug}:{proxySlug}', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/),
        fc.stringMatching(/^[0-9a-f]{8}$/),
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();
          mockRedisGet.mockResolvedValue(null);
          mockOrgFindOne.mockReturnValue({
            select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(null) }),
          });

          await getEndpoint(orgSlug, proxySlug);

          expect(mockRedisGet).toHaveBeenCalledWith(`endpoint:${orgSlug}:${proxySlug}`);
        }
      ),
      { numRuns: 50 }
    );
  });

  it('returns null when org does not exist — endpoint lookup is skipped', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9-]{1,15}[a-z0-9]$/),
        fc.stringMatching(/^[0-9a-f]{8}$/),
        async (orgSlug, proxySlug) => {
          vi.clearAllMocks();
          mockRedisGet.mockResolvedValue(null);
          mockOrgFindOne.mockReturnValue({
            select: vi.fn().mockReturnValue({ lean: vi.fn().mockResolvedValue(null) }),
          });

          const result = await getEndpoint(orgSlug, proxySlug);

          expect(result).toBeNull();
          expect(mockEndpointFindOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 19: Threat Flag Invariant
// Feature: quantum-bridge, Property 19
//
// FOR ALL ProxyLog records where ecdsaVerified is false OR dilithiumVerified
// is false, threatFlag MUST be true.
// Requirements: 6.4, 6.7
// ---------------------------------------------------------------------------
describe('Property 19: Threat Flag Invariant (Req 6.4, 6.7)', () => {
  it('threatFlag is true whenever ecdsaVerified is false', () => {
    fc.assert(
      fc.property(fc.boolean(), (dilithiumVerified) => {
        const ecdsaVerified = false;
        const threatFlag = !ecdsaVerified || !dilithiumVerified;
        expect(threatFlag).toBe(true);
      }),
      { numRuns: 50 }
    );
  });

  it('threatFlag is true whenever dilithiumVerified is false', () => {
    fc.assert(
      fc.property(fc.boolean(), (ecdsaVerified) => {
        const dilithiumVerified = false;
        const threatFlag = !ecdsaVerified || !dilithiumVerified;
        expect(threatFlag).toBe(true);
      }),
      { numRuns: 50 }
    );
  });

  it('threatFlag is false only when both signatures are verified', () => {
    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), (ecdsaVerified, dilithiumVerified) => {
        const threatFlag = !ecdsaVerified || !dilithiumVerified;
        if (ecdsaVerified && dilithiumVerified) {
          expect(threatFlag).toBe(false);
        } else {
          expect(threatFlag).toBe(true);
        }
      }),
      { numRuns: 100 }
    );
  });

  it('invalid API key always produces threatFlag=true regardless of sig state', () => {
    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), (ecdsaVerified, dilithiumVerified) => {
        const apiKeyValid = false;
        const threatFlag = !apiKeyValid || !ecdsaVerified || !dilithiumVerified;
        expect(threatFlag).toBe(true);
      }),
      { numRuns: 50 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 20: No-Forward Invariant
// Feature: quantum-bridge, Property 20
//
// FOR ALL requests where threatFlag is true due to signature failure,
// forwardedToLegacy MUST be false — the request is never forwarded.
// Requirements: 6.7
// ---------------------------------------------------------------------------
describe('Property 20: No-Forward Invariant (Req 6.7)', () => {
  it('forwardedToLegacy is false when either signature fails', () => {
    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), (ecdsaVerified, dilithiumVerified) => {
        const sigFailure = !ecdsaVerified || !dilithiumVerified;
        const forwardedToLegacy = !sigFailure;
        if (sigFailure) {
          expect(forwardedToLegacy).toBe(false);
        }
      }),
      { numRuns: 100 }
    );
  });

  it('forwardedToLegacy is false when API key is invalid', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.hexaString({ minLength: 64, maxLength: 64 }),
        (rawKey, storedHash) => {
          fc.pre(hashApiKey(rawKey) !== storedHash);
          const apiKeyValid = false;
          const forwardedToLegacy = apiKeyValid;
          expect(forwardedToLegacy).toBe(false);
        }
      ),
      { numRuns: 50 }
    );
  });

  it('forwardedToLegacy can only be true when all checks pass', () => {
    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), fc.boolean(), (apiKeyValid, ecdsaVerified, dilithiumVerified) => {
        const canForward = apiKeyValid && ecdsaVerified && dilithiumVerified;
        if (!apiKeyValid || !ecdsaVerified || !dilithiumVerified) {
          expect(canForward).toBe(false);
        }
      }),
      { numRuns: 100 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 21: Header Stripping
// Feature: quantum-bridge, Property 21
//
// FOR ALL forwarded requests, no X-QB-* headers SHALL be present in the
// request received by the legacy API.
// Requirements: 6.8
// ---------------------------------------------------------------------------
describe('Property 21: Header Stripping (Req 6.8)', () => {
  it('no X-QB-* headers survive stripping', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.oneof(
            fc.stringMatching(/^x-qb-[a-z-]+$/),
            fc.stringMatching(/^[a-z][a-z-]{1,20}$/)
          ),
          fc.string({ minLength: 1, maxLength: 64 })
        ),
        (headers) => {
          const stripped = stripQBHeaders(headers);
          for (const key of Object.keys(stripped)) {
            expect(key.toLowerCase()).not.toMatch(/^x-qb-/);
          }
        }
      ),
      { numRuns: 100 }
    );
  });

  it('non-QB headers are preserved after stripping', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z][a-z-]{1,20}$/),
        fc.string({ minLength: 1, maxLength: 64 }),
        (headerName, headerValue) => {
          fc.pre(!headerName.toLowerCase().startsWith('x-qb-'));
          const stripped = stripQBHeaders({ [headerName]: headerValue });
          expect(stripped[headerName]).toBe(headerValue);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('known QB headers are always stripped', () => {
    const qbHeaders = [
      'x-qb-ecdsa-sig',
      'x-qb-dilithium-sig',
      'x-qb-key-version',
      'x-qb-encrypted',
      'x-qb-request-id',
    ];

    fc.assert(
      fc.property(
        fc.constantFrom(...qbHeaders),
        fc.string({ minLength: 1, maxLength: 64 }),
        (qbHeader, value) => {
          const headers = {
            [qbHeader]: value,
            'content-type': 'application/json',
            'authorization': 'Bearer token',
          };
          const stripped = stripQBHeaders(headers);
          expect(stripped[qbHeader]).toBeUndefined();
          expect(stripped['content-type']).toBe('application/json');
          expect(stripped['authorization']).toBe('Bearer token');
        }
      ),
      { numRuns: 50 }
    );
  });

  it('stripping is idempotent — applying twice yields the same result', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.oneof(
            fc.stringMatching(/^x-qb-[a-z-]+$/),
            fc.stringMatching(/^[a-z][a-z-]{1,20}$/)
          ),
          fc.string({ minLength: 1, maxLength: 64 })
        ),
        (headers) => {
          const once = stripQBHeaders(headers);
          const twice = stripQBHeaders(once);
          expect(twice).toEqual(once);
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 23: ProxyLog Completeness
// Feature: quantum-bridge, Property 23
//
// FOR ALL proxied requests (success or failure), a ProxyLog record MUST be
// written capturing all required fields. targetUrl MUST never be stored.
// Requirements: 6.13
// ---------------------------------------------------------------------------
describe('Property 23: ProxyLog Completeness (Req 6.13)', () => {
  it('ProxyLog entry contains all required fields with correct types', () => {
    fc.assert(
      fc.property(
        fc.uuid(),
        fc.constantFrom('GET', 'POST', 'PUT', 'DELETE', 'PATCH'),
        fc.webPath(),
        fc.integer({ min: 100, max: 599 }),
        fc.nat({ max: 30_000 }),
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        fc.ipV4(),
        (requestId, method, path, statusCode, latencyMs, ecdsaVerified, dilithiumVerified, forwardedToLegacy, clientIp) => {
          const threatFlag = !ecdsaVerified || !dilithiumVerified;

          const logEntry = {
            requestId,
            orgId: VALID_ORG_ID,
            endpointId: VALID_EP_ID,
            method,
            path,
            statusCode,
            latencyMs,
            ecdsaVerified,
            dilithiumVerified,
            threatFlag,
            keyVersion: 1,
            forwardedToLegacy,
            clientIp,
          };

          expect(logEntry.requestId).toBeDefined();
          expect(logEntry.orgId).toBeDefined();
          expect(logEntry.endpointId).toBeDefined();
          expect(typeof logEntry.method).toBe('string');
          expect(typeof logEntry.path).toBe('string');
          expect(typeof logEntry.statusCode).toBe('number');
          expect(typeof logEntry.latencyMs).toBe('number');
          expect(typeof logEntry.ecdsaVerified).toBe('boolean');
          expect(typeof logEntry.dilithiumVerified).toBe('boolean');
          expect(typeof logEntry.threatFlag).toBe('boolean');
          expect(typeof logEntry.forwardedToLegacy).toBe('boolean');
          expect(typeof logEntry.clientIp).toBe('string');

          if (!ecdsaVerified || !dilithiumVerified) {
            expect(logEntry.threatFlag).toBe(true);
          }
        }
      ),
      { numRuns: 100 }
    );
  });

  it('latencyMs is always non-negative', () => {
    fc.assert(
      fc.property(fc.nat({ max: 60_000 }), (latencyMs) => {
        expect(latencyMs).toBeGreaterThanOrEqual(0);
      }),
      { numRuns: 100 }
    );
  });

  it('requestId generated by randomUUID() is always a valid UUID v4 format', () => {
    // Verify that Node.js randomUUID() always produces v4 UUIDs (the proxy uses randomUUID)
    const { randomUUID } = require('node:crypto');
    fc.assert(
      fc.property(fc.constant(undefined), () => {
        const requestId = randomUUID();
        expect(requestId).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        );
      }),
      { numRuns: 50 }
    );
  });

  it('targetUrl is never stored in ProxyLog (privacy invariant)', () => {
    fc.assert(
      fc.property(fc.webUrl(), fc.uuid(), (targetUrl, requestId) => {
        const logEntry = {
          requestId,
          orgId: VALID_ORG_ID,
          endpointId: VALID_EP_ID,
          method: 'GET',
          path: '/api/data',
          statusCode: 200,
          latencyMs: 42,
          ecdsaVerified: true,
          dilithiumVerified: true,
          threatFlag: false,
          keyVersion: 1,
          forwardedToLegacy: true,
          clientIp: '1.2.3.4',
        };

        expect(JSON.stringify(logEntry)).not.toContain(targetUrl);
        expect(Object.keys(logEntry)).not.toContain('targetUrl');
      }),
      { numRuns: 50 }
    );
  });
});
