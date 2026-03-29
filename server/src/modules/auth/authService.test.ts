/**
 * Unit tests for AuthService — register, verifyEmail, resendVerification
 * Requirements: 1.1, 1.2, 1.3, 1.5, 1.6
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as argon2 from 'argon2';

// ---------------------------------------------------------------------------
// Hoisted mock functions — must be declared with vi.hoisted so they are
// available when vi.mock factories are evaluated (which are hoisted to the top)
// ---------------------------------------------------------------------------
const { mockUserCreate, mockUserFindOne, mockUserSave, mockSendEmail } = vi.hoisted(() => ({
  mockUserCreate: vi.fn(),
  mockUserFindOne: vi.fn(),
  mockUserSave: vi.fn(),
  mockSendEmail: vi.fn().mockResolvedValue({ id: 'email-id-123' }),
}));

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../config/env.js', () => ({
  env: {
    RESEND_API_KEY: 're_test_key',
    ALLOWED_ORIGIN: 'https://app.quantumbridge.io',
    NODE_ENV: 'test',
  },
}));

vi.mock('../../utils/logger.js', () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
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
  },
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------
import {
  register,
  verifyEmail,
  resendVerification,
  ConflictError,
  GoneError,
} from './authService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUser(overrides: Record<string, unknown> = {}) {
  return {
    _id: { toString: () => 'user-id-123' },
    email: 'test@example.com',
    passwordHash: 'hashed',
    isVerified: false,
    verificationToken: 'token123',
    verificationTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    save: mockUserSave,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('register', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSendEmail.mockResolvedValue({ id: 'email-id' });
  });

  it('creates a user with an argon2id hash — never stores plaintext password (Req 1.6)', async () => {
    mockUserCreate.mockResolvedValue(makeUser());

    await register('Test@Example.com', 'SecurePass123!');

    expect(mockUserCreate).toHaveBeenCalledOnce();
    const callArg = mockUserCreate.mock.calls[0][0];

    // Req 1.6 — password must be hashed, not stored as plaintext
    expect(callArg.passwordHash).not.toBe('SecurePass123!');
    expect(callArg.passwordHash).toBeTruthy();

    // Verify it's a valid argon2id hash
    const isValid = await argon2.verify(callArg.passwordHash, 'SecurePass123!');
    expect(isValid).toBe(true);
  });

  it('normalises email to lowercase', async () => {
    mockUserCreate.mockResolvedValue(makeUser());

    await register('UPPER@EXAMPLE.COM', 'pass');

    const callArg = mockUserCreate.mock.calls[0][0];
    expect(callArg.email).toBe('upper@example.com');
  });

  it('sets isVerified to false and attaches a 64-char hex verification token with 24h expiry', async () => {
    mockUserCreate.mockResolvedValue(makeUser());

    const before = Date.now();
    await register('user@example.com', 'pass');
    const after = Date.now();

    const callArg = mockUserCreate.mock.calls[0][0];
    expect(callArg.isVerified).toBe(false);
    expect(callArg.verificationToken).toHaveLength(64); // 32 bytes hex
    expect(callArg.verificationTokenExpiresAt.getTime()).toBeGreaterThan(
      before + 23 * 60 * 60 * 1000
    );
    expect(callArg.verificationTokenExpiresAt.getTime()).toBeLessThan(
      after + 25 * 60 * 60 * 1000
    );
  });

  it('sends a verification email after creating the user (Req 1.1)', async () => {
    mockUserCreate.mockResolvedValue(makeUser());

    await register('user@example.com', 'pass');

    expect(mockSendEmail).toHaveBeenCalledOnce();
    const emailArg = mockSendEmail.mock.calls[0][0];
    expect(emailArg.to).toBe('user@example.com');
    expect(emailArg.html).toContain('verify-email?token=');
  });

  it('returns the userId on success', async () => {
    mockUserCreate.mockResolvedValue(makeUser());

    const result = await register('user@example.com', 'pass');
    expect(result.userId).toBe('user-id-123');
  });

  it('throws ConflictError (409) on duplicate email (Req 1.2)', async () => {
    const dupError = Object.assign(new Error('duplicate key'), { code: 11000 });
    mockUserCreate.mockRejectedValue(dupError);

    await expect(register('dup@example.com', 'pass')).rejects.toThrow(ConflictError);
  });

  it('uses a generic error message that does not reveal account existence (Req 1.2)', async () => {
    const dupError = Object.assign(new Error('duplicate key'), { code: 11000 });
    mockUserCreate.mockRejectedValue(dupError);

    try {
      await register('dup@example.com', 'pass');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ConflictError);
      const msg = (err as ConflictError).message.toLowerCase();
      // Must not say "already registered", "taken", etc.
      expect(msg).not.toContain('already registered');
      expect(msg).not.toContain('taken');
    }
  });

  it('still returns userId even if email sending fails', async () => {
    mockUserCreate.mockResolvedValue(makeUser());
    mockSendEmail.mockRejectedValue(new Error('SMTP error'));

    const result = await register('user@example.com', 'pass');
    expect(result.userId).toBe('user-id-123');
  });
});

describe('verifyEmail', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('marks user as verified and clears the token (Req 1.3)', async () => {
    const user = makeUser();
    mockUserFindOne.mockResolvedValue(user);
    mockUserSave.mockResolvedValue(undefined);

    await verifyEmail('valid-token');

    expect(user.isVerified).toBe(true);
    expect(user.verificationToken).toBeUndefined();
    expect(user.verificationTokenExpiresAt).toBeUndefined();
    expect(mockUserSave).toHaveBeenCalledOnce();
  });

  it('throws GoneError (410) when token is not found (Req 1.5)', async () => {
    mockUserFindOne.mockResolvedValue(null);

    await expect(verifyEmail('nonexistent-token')).rejects.toThrow(GoneError);
  });

  it('throws GoneError (410) when token has expired (Req 1.5)', async () => {
    const expiredUser = makeUser({
      verificationTokenExpiresAt: new Date(Date.now() - 1000), // 1 second in the past
    });
    mockUserFindOne.mockResolvedValue(expiredUser);

    await expect(verifyEmail('expired-token')).rejects.toThrow(GoneError);
  });

  it('does not save when token is expired', async () => {
    const expiredUser = makeUser({
      verificationTokenExpiresAt: new Date(Date.now() - 1000),
    });
    mockUserFindOne.mockResolvedValue(expiredUser);

    await expect(verifyEmail('expired-token')).rejects.toThrow(GoneError);
    expect(mockUserSave).not.toHaveBeenCalled();
  });
});

describe('resendVerification', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSendEmail.mockResolvedValue({ id: 'email-id' });
  });

  it('regenerates token and resends email for unverified user', async () => {
    const user = makeUser({ verificationToken: 'old-token' });
    mockUserFindOne.mockResolvedValue(user);
    mockUserSave.mockResolvedValue(undefined);

    await resendVerification('user@example.com');

    expect(user.verificationToken).not.toBe('old-token');
    expect((user.verificationToken as string)).toHaveLength(64);
    expect(mockUserSave).toHaveBeenCalledOnce();
    expect(mockSendEmail).toHaveBeenCalledOnce();
  });

  it('silently succeeds when user does not exist — avoids account enumeration', async () => {
    mockUserFindOne.mockResolvedValue(null);

    await expect(resendVerification('ghost@example.com')).resolves.toBeUndefined();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  it('silently succeeds when user is already verified', async () => {
    mockUserFindOne.mockResolvedValue(makeUser({ isVerified: true }));

    await expect(resendVerification('verified@example.com')).resolves.toBeUndefined();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  it('normalises email to lowercase before lookup', async () => {
    mockUserFindOne.mockResolvedValue(null);

    await resendVerification('UPPER@EXAMPLE.COM');

    expect(mockUserFindOne).toHaveBeenCalledWith({ email: 'upper@example.com' });
  });

  it('still resolves even if email sending fails', async () => {
    const user = makeUser();
    mockUserFindOne.mockResolvedValue(user);
    mockUserSave.mockResolvedValue(undefined);
    mockSendEmail.mockRejectedValue(new Error('SMTP error'));

    await expect(resendVerification('user@example.com')).resolves.toBeUndefined();
  });
});
