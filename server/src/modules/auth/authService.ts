import crypto from 'node:crypto';
import * as argon2 from 'argon2';
import { Resend } from 'resend';
import { env } from '../../config/env.js';
import logger from '../../utils/logger.js';
import { User } from './User.js';
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid';
import { redis } from '@server/config/redis.js';
const resend = new Resend(env.RESEND_API_KEY);

// ---------------------------------------------------------------------------
// Custom error types
// ---------------------------------------------------------------------------
export class UnauthorizedError extends Error{
  readonly statusCode=401;
  constructor(message='Unauthorized')
  {
    super(message);
    this.name='UnauthorizedError';
  }
}
export class ForbiddenError extends Error
{
    readonly statusCode=403;
    constructor(message="Forbidden")
    {
      super(message);
      this.name="ForbiddenError";

    }
}

export class ConflictError extends Error {
  readonly statusCode = 409;
  constructor(message = 'Conflict') {
    super(message);
    this.name = 'ConflictError';
  }
}

export class GoneError extends Error {
  readonly statusCode = 410;
  constructor(message = 'Gone') {
    super(message);
    this.name = 'GoneError';
  }
}

export class NotFoundError extends Error {
  readonly statusCode = 404;
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RefreshTokenFamily{
   familyId:string;
   userId:string;
   currentToken:string;   // row token
   rotatedTokens:string[];
   expiresAt:string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const REFRESH_TTL_SECONDS=7*24*60*60;  // 7 days
const ACCESS_TOKEN_EXPIRY='15m';

function refreshFamilyeKey(familyId:string):string{
  return `refresh:family:${familyId}`;

}
function generateRefreshToken():string{
   return crypto.randomBytes(40).toString('hex');

}

function issueAccessToken(userId:string,email:string):string
{
  return jwt.sign(
    { sub:userId,email},env.JWT_SECRET,{expiresIn:ACCESS_TOKEN_EXPIRY});
}

async function getRefreshFamily(familyId: string): Promise<RefreshTokenFamily | null> {
  const raw = await redis.get(refreshFamilyeKey(familyId));
  return raw ? (JSON.parse(raw) as RefreshTokenFamily) : null;
}

async function storeRefreshFamily(familyId: string, family: RefreshTokenFamily): Promise<void> {
  await redis.set(
    refreshFamilyeKey(familyId),
    JSON.stringify(family),
    'EX',
    REFRESH_TTL_SECONDS
  );
}

async function deleteRefreshFamily(familyId:string):Promise<void>
{
   await redis.del(refreshFamilyeKey(familyId));

}
// Refresh tokens embed the familyId as a prefix: "{familyId}:{randomBytes}"
function buildRefreshToken(familyId: string): string {
  return `${familyId}:${generateRefreshToken()}`;
}

function parseFamilyId(refreshToken: string): string {
  // familyId is a UUID (36 chars), followed by ":"
  return refreshToken.slice(0, 36);
}

function generateVerificationToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function verificationExpiresAt(): Date {
  const d = new Date();
  d.setHours(d.getHours() + 24);
  return d;
}

async function sendVerificationEmail(email: string, token: string): Promise<void> {
  const verifyUrl = `${env.ALLOWED_ORIGIN}/auth/verify-email?token=${token}`;

  await resend.emails.send({
    from: 'QuantumBridge <noreply@quantumbridge.io>',
    to: email,
    subject: 'Verify your QuantumBridge account',
    html: `
      <p>Welcome to QuantumBridge!</p>
      <p>Click the link below to verify your email address. This link expires in 24 hours.</p>
      <p><a href="${verifyUrl}">Verify Email</a></p>
      <p>If you did not create an account, you can safely ignore this email.</p>
    `,
  });

  logger.info('verification_email_sent', { email });
}

// ---------------------------------------------------------------------------
// AuthService
// ---------------------------------------------------------------------------

/**
 * register
 *
 * Req 1.1 — hash password with argon2id, create User, send verification email.
 * Req 1.2 — return 409 on duplicate email without revealing existence.
 * Req 1.6 — store only argon2id hashes; never plaintext.
 */
export async function register(
  email: string,
  password: string
): Promise<{ userId: string }> {
  const normalizedEmail = email.toLowerCase().trim();

  // Hash password with argon2id (default algorithm for the argon2 package)
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

  const verificationToken = generateVerificationToken();
  const verificationTokenExpiresAt = verificationExpiresAt();

  try {
    const user = await User.create({
      email: normalizedEmail,
      passwordHash,
      isVerified: false,
      verificationToken,
      verificationTokenExpiresAt,
    });

    // Send email after successful DB write; if email fails we still have the user
    // and they can use resendVerification.
    try {
      await sendVerificationEmail(normalizedEmail, verificationToken);
    } catch (emailErr) {
      logger.error('verification_email_failed', { email: normalizedEmail, error: emailErr });
    }

    logger.info('user_registered', { userId: user._id.toString() });
    return { userId: user._id.toString() };
  } catch (err: unknown) {
    // MongoDB duplicate key error code
    if (
      typeof err === 'object' &&
      err !== null &&
      'code' in err &&
      (err as { code: number }).code === 11000
    ) {
      // Req 1.2 — same error message regardless; do not reveal account existence
      logger.warn('registration_duplicate_email_attempt');
      throw new ConflictError('An account with this email already exists');
    }
    throw err;
  }
}

/**
 * verifyEmail
 *
 * Req 1.3 — mark user as verified and clear the token.
 * Req 1.5 — return 410 if the token has expired.
 */
export async function verifyEmail(token: string): Promise<void> {
  const user = await User.findOne({ verificationToken: token });

  if (!user) {
    // Token not found — treat as expired/invalid (410 per spec)
    throw new GoneError('Verification link is invalid or has expired');
  }

  if (
    !user.verificationTokenExpiresAt ||
    user.verificationTokenExpiresAt < new Date()
  ) {
    throw new GoneError('Verification link has expired');
  }

  user.isVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpiresAt = undefined;
  await user.save();

  logger.info('email_verified', { userId: user._id.toString() });
}

/**
 * resendVerification
 *
 * Regenerate the verification token and resend the email.
 * Always returns successfully — do not reveal whether the email exists.
 */
export async function resendVerification(email: string): Promise<void> {
  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });

  // Silently succeed if user not found or already verified — avoids account enumeration
  if (!user || user.isVerified) {
    logger.info('resend_verification_noop', { reason: user ? 'already_verified' : 'not_found' });
    return;
  }

  const verificationToken = generateVerificationToken();
  const verificationTokenExpiresAt = verificationExpiresAt();

  user.verificationToken = verificationToken;
  user.verificationTokenExpiresAt = verificationTokenExpiresAt;
  await user.save();

  try {
    await sendVerificationEmail(normalizedEmail, verificationToken);
  } catch (emailErr) {
    logger.error('resend_verification_email_failed', { email: normalizedEmail, error: emailErr });
  }

  logger.info('verification_resent', { userId: user._id.toString() });
}

// ---------------------------------------------------------------------------
// login  (Req 1.4, 1.7, 2.1)
// ---------------------------------------------------------------------------

/**
 * Verifies credentials, blocks unverified users (403), issues a 15-min JWT
 * access token and a 7-day refresh token stored as a Redis family.
 *
 * Returns the raw refresh token so the route handler can set it as an
 * httpOnly cookie — it is NEVER included in the JSON response body (Req 1.7).
 */

export async function login(email:string,password:string):Promise<{accessToken:string,refreshToken:string}>{
  const normalizedEmail=email.toLowerCase().trim();
  const user=await User.findOne({email:normalizedEmail}).select('+passwordHash');

    // Use a constant-time-equivalent path: always verify even on missing user
  // to avoid timing-based account enumeration.
  const dummyHash =
    '$argon2id$v=19$m=65536,t=3,p=4$dummysaltdummysalt$dummyhashvaluedummyhashvalue';

    const passwordHash=user?.passwordHash ?? dummyHash;
    const valid=await argon2.verify(passwordHash,password);

    if(!user || !valid)
    {
      throw new UnauthorizedError("Invalid email or password");

    }
    if(!user.isVerified)
    {
      throw new ForbiddenError('please verify your email address before logging in');
    }
   const familyId = uuidv4();
  const refreshToken = buildRefreshToken(familyId);

  const family: RefreshTokenFamily = {
    familyId,
    userId: user._id.toString(),
    currentToken: refreshToken,
    rotatedTokens: [],
    expiresAt: new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString(),
  };

  await storeRefreshFamily(familyId, family);

  const accessToken = issueAccessToken(user._id.toString(), user.email);

  logger.info('user_login', { userId: user._id.toString() });

  return { accessToken, refreshToken };
}

// ---------------------------------------------------------------------------
// refresh  (Req 2.2, 2.6)
// ---------------------------------------------------------------------------

/**
 * Rotates the refresh token family.
 * Req 2.6 — if the presented token was already rotated (replay), invalidate
 * the entire family and return 401.
 */
export async function refresh(
  refreshToken: string
): Promise<{ accessToken: string; refreshToken: string }> {
  const familyId = parseFamilyId(refreshToken);
  const family = await getRefreshFamily(familyId);

  if (!family) {
    throw new UnauthorizedError('Invalid or expired refresh token');
  }

  // Replay attack detection — token was already rotated
  if (family.rotatedTokens.includes(refreshToken)) {
    await deleteRefreshFamily(familyId); // invalidate entire family
    logger.warn('refresh_token_replay_detected', { familyId });
    throw new UnauthorizedError('Refresh token reuse detected — please log in again');
  }

  // Token doesn't match current AND isn't in rotated list → tampered/unknown
  if (family.currentToken !== refreshToken) {
    await deleteRefreshFamily(familyId);
    throw new UnauthorizedError('Invalid refresh token');
  }

  // Rotate: move current → rotatedTokens, issue new current
  const newRefreshToken = buildRefreshToken(familyId);
  const updatedFamily: RefreshTokenFamily = {
    ...family,
    currentToken: newRefreshToken,
    rotatedTokens: [...family.rotatedTokens, refreshToken],
  };

  await storeRefreshFamily(familyId, updatedFamily);

  // Fetch user for email claim — no DB query on every request, only on refresh
  const user = await User.findById(family.userId).select('email');
  if (!user) {
    await deleteRefreshFamily(familyId);
    throw new UnauthorizedError('User not found');
  }

  const accessToken = issueAccessToken(family.userId, user.email);

  logger.info('token_refreshed', { userId: family.userId, familyId });

  return { accessToken, refreshToken: newRefreshToken };
}

// ---------------------------------------------------------------------------
// logout  (Req 2.4)
// ---------------------------------------------------------------------------

/**
 * Deletes the refresh token family from Redis so the token cannot be reused.
 */
export async function logout(refreshToken: string): Promise<void> {
  const familyId = parseFamilyId(refreshToken);
  await deleteRefreshFamily(familyId);
  logger.info('user_logout', { familyId });
}
