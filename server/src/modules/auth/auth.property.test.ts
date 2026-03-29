/**
 * Property-based tests for Auth module (P1–P5)
 * Feature: quantum-bridge
 *
 * Requirements: 1.6, 1.7, 2.1, 2.2, 2.3, 2.4
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import * as argon2 from 'argon2';
import jwt from 'jsonwebtoken';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockUserCreate,
  mockUserFindOne,
  mockUserSave,
  mockSendEmail,
  mockRedisGet,
  mockRedisSet,
  mockRedisDel,
} = vi.hoisted(() => ({
  mockUserCreate: vi.fn(),
  mockUserFindOne: vi.fn(),
  mockUserSave: vi.fn(),
  mockSendEmail: vi.fn().mockResolvedValue({ id: 'email-id' }),
  mockRedisGet: vi.fn(),
  mockRedisSet: vi.fn().mockResolvedValue('OK'),
  mockRedisDel: vi.fn().mockResolvedValue(1),
}));

vi.mock('../../config/env.js', () => ({
  env: {
    RESEND_API_KEY: 're_test_key',
    ALLOWED_ORIGIN: 'https://app.quantumbridge.io',
    NODE_ENV: 'test',
    JWT_SECRET: 'test-jwt-secret-at-least-32-chars-long!!',
    JWT_REFRESH_SECRET: 'test-refresh-secret-at-least-32-chars!!',
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

vi.mock('./User.js', () => ({
  User: {
    create: mockUserCreate,
    findOne: mockUserFindOne,
    findById: vi.fn(),
  },
}));

vi.mock('@server/config/redis.js', () => ({
  redis: {
    get: mockRedisGet,
    set: mockRedisSet,
    del: mockRedisDel,
  },
}));

// Import after mocks
import { register, login, refresh, logout, UnauthorizedError } from './authService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long!!';

function makeVerifiedUser(overrides: Record<string, unknown> = {}) {
  return {
    _id: { toString: () => 'user-id-abc' },
    email: 'user@example.com',
    passwordHash: '',
    isVerified: true,
    save: mockUserSave,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Property 1: Password Hash Non-Identity
// Feature: quantum-bridge, Property 1
//
// FOR ALL non-empty passwords, the argon2id hash MUST NOT equal the plaintext.
// Req 1.6 — only argon2id hashes are stored; plaintext is never persisted.
// ---------------------------------------------------------------------------
describe('Property 1: Password Hash Non-Identity (Req 1.6)', () => {
  it('hash(password) !== password for any non-empty password string', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 128 }),
        async (password) => {
          const hash = await argon2.hash(password, { type: argon2.argon2id });
          expect(hash).not.toBe(password);
          expect(hash).toMatch(/^\$argon2id\$/);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('register() stores an argon2id hash, never the plaintext password', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 8, maxLength: 64 }).filter((s) => s.trim().length > 0),
        async (password) => {
          vi.clearAllMocks();
          mockUserCreate.mockImplementation(async (data: Record<string, unknown>) =>
            ({ _id: { toString: () => 'uid' }, ...data, save: mockUserSave })
          );
          mockSendEmail.mockResolvedValue({ id: 'x' });

          await register('prop1@example.com', password);

          const stored: string = mockUserCreate.mock.calls[0][0].passwordHash;
          expect(stored).not.toBe(password);
          expect(stored).toMatch(/^\$argon2id\$/);
        }
      ),
      { numRuns: 10 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 2: Refresh Token Not in Response Body
// Feature: quantum-bridge, Property 2
//
// FOR ALL valid logins, the refresh token MUST NOT appear in the JSON response
// body — it is only returned for the route handler to set as an httpOnly cookie.
// Req 1.7, 2.1
// ---------------------------------------------------------------------------
describe('Property 2: Refresh Token Not in Response Body (Req 1.7, 2.1)', () => {
  it('login() returns refreshToken only as a separate value, not embedded in accessToken', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.emailAddress(),
        fc.string({ minLength: 8, maxLength: 64 }),
        async (email, password) => {
          vi.clearAllMocks();

          const hash = await argon2.hash(password, { type: argon2.argon2id });
          const user = makeVerifiedUser({ email, passwordHash: hash });
          mockUserFindOne.mockReturnValue({
            select: vi.fn().mockResolvedValue(user),
          });
          mockRedisSet.mockResolvedValue('OK');

          const result = await login(email, password);

          // accessToken must be a JWT string — not a raw token
          expect(result.accessToken).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

          // refreshToken must not be embedded inside the accessToken payload
          const decoded = jwt.decode(result.accessToken) as Record<string, unknown>;
          expect(JSON.stringify(decoded)).not.toContain(result.refreshToken);

          // The two tokens must be distinct values
          expect(result.accessToken).not.toBe(result.refreshToken);
        }
      ),
      { numRuns: 10 }
    );
  });

  it('refresh() response does not embed the old refresh token in the new access token', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (familyId) => {
          vi.clearAllMocks();

          const oldToken = `${familyId}:oldhex`;
          const family = {
            familyId,
            userId: 'user-id-abc',
            currentToken: oldToken,
            rotatedTokens: [],
            expiresAt: new Date(Date.now() + 86400_000).toISOString(),
          };

          mockRedisGet.mockResolvedValue(JSON.stringify(family));
          mockRedisSet.mockResolvedValue('OK');

          // Mock User.findById used inside refresh
          const { User } = await import('./User.js');
          vi.mocked(User.findById).mockReturnValue({
            select: vi.fn().mockResolvedValue({ email: 'user@example.com' }),
          } as never);

          const result = await refresh(oldToken);

          const decoded = jwt.decode(result.accessToken) as Record<string, unknown>;
          expect(JSON.stringify(decoded)).not.toContain(oldToken);
          expect(JSON.stringify(decoded)).not.toContain(result.refreshToken);
        }
      ),
      { numRuns: 10 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 3: JWT Expiry Invariant
// Feature: quantum-bridge, Property 3
//
// FOR ALL issued access tokens, the `exp` claim MUST be exactly 15 minutes
// after the `iat` claim (within a 5-second tolerance for test execution time).
// Req 2.1
// ---------------------------------------------------------------------------
describe('Property 3: JWT Expiry Invariant (Req 2.1)', () => {
  it('every access token has exp = iat + 900 seconds (15 minutes)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 8, maxLength: 64 }),
        async (password) => {
          vi.clearAllMocks();

          const hash = await argon2.hash(password, { type: argon2.argon2id });
          const user = makeVerifiedUser({ passwordHash: hash });
          mockUserFindOne.mockReturnValue({
            select: vi.fn().mockResolvedValue(user),
          });
          mockRedisSet.mockResolvedValue('OK');

          const { accessToken } = await login('user@example.com', password);

          const decoded = jwt.verify(accessToken, JWT_SECRET) as { iat: number; exp: number };
          const duration = decoded.exp - decoded.iat;

          // Must be exactly 900 seconds (15 min), tolerance ±5s for test execution
          expect(duration).toBeGreaterThanOrEqual(895);
          expect(duration).toBeLessThanOrEqual(905);
        }
      ),
      { numRuns: 10 }
    );
  });

  it('access token is invalid after its expiry time', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.string({ minLength: 1, maxLength: 64 }),
        (userId, email) => {
          // Issue a token that expired 1 second ago
          const expiredToken = jwt.sign(
            { sub: userId, email },
            JWT_SECRET,
            { expiresIn: -1 }
          );

          expect(() => jwt.verify(expiredToken, JWT_SECRET)).toThrow();
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 4: Token Invalidation Round Trip
// Feature: quantum-bridge, Property 4
//
// FOR ALL refresh token families: after logout(), the family is deleted from
// Redis and any subsequent refresh attempt MUST throw UnauthorizedError.
// Req 2.4
// ---------------------------------------------------------------------------
describe('Property 4: Token Invalidation Round Trip (Req 2.4)', () => {
  it('after logout, the refresh token family is deleted from Redis', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (familyId) => {
          vi.clearAllMocks();
          mockRedisDel.mockResolvedValue(1);

          const token = `${familyId}:somehex`;
          await logout(token);

          expect(mockRedisDel).toHaveBeenCalledWith(`refresh:family:${familyId}`);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('refresh() throws UnauthorizedError when family is not found (simulates post-logout)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (familyId) => {
          vi.clearAllMocks();
          // Simulate deleted family (Redis returns null)
          mockRedisGet.mockResolvedValue(null);

          const token = `${familyId}:somehex`;
          await expect(refresh(token)).rejects.toThrow(UnauthorizedError);
        }
      ),
      { numRuns: 20 }
    );
  });

  it('replay attack: using a rotated token invalidates the entire family', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        async (familyId) => {
          vi.clearAllMocks();

          const rotatedToken = `${familyId}:rotatedhex`;
          const currentToken = `${familyId}:currenthex`;

          const family = {
            familyId,
            userId: 'user-id-abc',
            currentToken,
            rotatedTokens: [rotatedToken], // already rotated
            expiresAt: new Date(Date.now() + 86400_000).toISOString(),
          };

          mockRedisGet.mockResolvedValue(JSON.stringify(family));
          mockRedisDel.mockResolvedValue(1);

          // Presenting a rotated token is a replay attack
          await expect(refresh(rotatedToken)).rejects.toThrow(UnauthorizedError);

          // Family must be fully invalidated
          expect(mockRedisDel).toHaveBeenCalledWith(`refresh:family:${familyId}`);
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 5: Invalid JWT Rejection
// Feature: quantum-bridge, Property 5
//
// FOR ALL strings that are not valid JWTs signed with JWT_SECRET,
// jwt.verify() MUST throw — ensuring the authenticate middleware rejects them.
// Req 2.3
// ---------------------------------------------------------------------------
describe('Property 5: Invalid JWT Rejection (Req 2.3)', () => {
  it('arbitrary strings are rejected by jwt.verify', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 256 }),
        (token) => {
          expect(() => jwt.verify(token, JWT_SECRET)).toThrow();
        }
      ),
      { numRuns: 100 }
    );
  });

  it('tokens signed with a different secret are rejected', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.string({ minLength: 32, maxLength: 64 }),
        (userId, email, wrongSecret) => {
          fc.pre(wrongSecret !== JWT_SECRET);

          const token = jwt.sign({ sub: userId, email }, wrongSecret, { expiresIn: '15m' });
          expect(() => jwt.verify(token, JWT_SECRET)).toThrow();
        }
      ),
      { numRuns: 50 }
    );
  });

  it('tampered JWT payloads are rejected', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.string({ minLength: 1, maxLength: 64 }),
        (userId, email) => {
          const token = jwt.sign({ sub: userId, email }, JWT_SECRET, { expiresIn: '15m' });
          const [header, , signature] = token.split('.');

          // Replace payload with arbitrary base64 content
          const tamperedPayload = Buffer.from(
            JSON.stringify({ sub: 'attacker', email: 'evil@example.com' })
          ).toString('base64url');

          const tamperedToken = `${header}.${tamperedPayload}.${signature}`;
          expect(() => jwt.verify(tamperedToken, JWT_SECRET)).toThrow();
        }
      ),
      { numRuns: 50 }
    );
  });
});
