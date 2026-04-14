import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { Resend } from 'resend';
import { env } from '../../config/env.js';
import { redis } from '../../config/redis.js';
import logger from '../../utils/logger.js';
import { slugify } from '../../utils/slugify.js';
import { Organization } from './Organization.js';
import { OrgMember } from './OrgMember.js';

// ---------------------------------------------------------------------------
// Forward reference for KeyVaultService (implemented in task 2.6)
// ---------------------------------------------------------------------------
interface IKeyVaultService {
  generateAndStore(orgId: string): Promise<void>;
}

// Lazy import — avoids circular deps and allows the module to be stubbed in tests
async function getKeyVaultService(): Promise<IKeyVaultService> {
  try {
    const mod = await import('../keyVault/keyVaultService.js');
    return mod.keyVaultService as IKeyVaultService;
  } catch {
    // KeyVaultService not yet implemented — use a no-op stub
    return {
      generateAndStore: async (orgId: string) => {
        logger.warn('keyVault_stub_generateAndStore', { orgId });
      },
    };
  }
}

const resend = new Resend(env.RESEND_API_KEY);

// ---------------------------------------------------------------------------
// Custom error types (re-exported from authService pattern)
// ---------------------------------------------------------------------------
export class ConflictError extends Error {
  readonly statusCode = 409;
  constructor(message = 'Conflict') {
    super(message);
    this.name = 'ConflictError';
  }
}

export class ForbiddenError extends Error {
  readonly statusCode = 403;
  constructor(message = 'Forbidden') {
    super(message);
    this.name = 'ForbiddenError';
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
// Helpers
// ---------------------------------------------------------------------------

/**
 * Asserts that the actor is a member of the org with a role that is NOT viewer.
 * Throws ForbiddenError (403) if the actor is a viewer or not a member.
 */
async function assertNotViewer(orgId: string, actorId: string): Promise<void> {
  const membership = await OrgMember.findOne({
    orgId,
    userId: actorId,
    status: 'active',
  });

  if (!membership) {
    throw new ForbiddenError('You are not a member of this organization');
  }

  if (membership.role === 'viewer') {
    throw new ForbiddenError('Viewers cannot perform write operations');
  }
}

/**
 * Asserts that the actor is an owner of the org.
 */
async function assertOwner(orgId: string, actorId: string): Promise<void> {
  const membership = await OrgMember.findOne({
    orgId,
    userId: actorId,
    status: 'active',
    role: 'owner',
  });

  if (!membership) {
    throw new ForbiddenError('Only the organization owner can perform this action');
  }
}

// ---------------------------------------------------------------------------
// OrgService
// ---------------------------------------------------------------------------

/**
 * create
 *
 * Req 3.1 — create org with auto-generated slug, assign owner, trigger keypair gen.
 * Req 3.2 — return 409 on duplicate slug.
 */
export async function create(
  userId: string,
  name: string
): Promise<InstanceType<typeof Organization>> {
  const slug = slugify(name);

  try {
    const org = await Organization.create({
      name,
      slug,
      plan: 'free',
      monthlyRequestCount: 0,
      quotaResetAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      publicVerificationEnabled: false,
      customDomainVerified: false,
    });

    // Assign the creator as owner
    await OrgMember.create({
      orgId: org._id,
      userId,
      role: 'owner',
      status: 'active',
    });

    // Trigger PQC keypair generation (non-blocking on stub; awaited for real impl)
    const keyVault = await getKeyVaultService();
    await keyVault.generateAndStore(org._id.toString());

    logger.info('org_created', { orgId: org._id.toString(), userId, slug });
    return org;
  } catch (err: unknown) {
    if (
      typeof err === 'object' &&
      err !== null &&
      'code' in err &&
      (err as { code: number }).code === 11000
    ) {
      throw new ConflictError(`An organization with slug "${slug}" already exists`);
    }
    throw err;
  }
}

/**
 * invite
 *
 * Req 3.4 — owner/admin sends invite email, creates pending OrgMember.
 * Req 3.7 — viewers cannot invite.
 */
export async function invite(
  orgId: string,
  actorId: string,
  email: string,
  role: 'admin' | 'viewer'
): Promise<void> {
  await assertNotViewer(orgId, actorId);

  const org = await Organization.findById(orgId);
  if (!org) {
    throw new NotFoundError('Organization not found');
  }

  const inviteToken = crypto.randomBytes(32).toString('hex');
  const normalizedEmail = email.toLowerCase().trim();

  // Upsert: if a pending invite already exists for this email+org, refresh it
  await OrgMember.findOneAndUpdate(
    { orgId, inviteEmail: normalizedEmail, status: 'pending' },
    {
      $setOnInsert: { orgId, userId: new mongoose.Types.ObjectId(), createdAt: new Date() },
      $set: { role, inviteToken, inviteEmail: normalizedEmail, status: 'pending' },
    },
    { upsert: true, new: true }
  );

  const inviteUrl = `${env.ALLOWED_ORIGIN}/accept-invite?token=${inviteToken}`;

  try {
    await resend.emails.send({
      from: 'QuantumBridge <noreply@quantumbridge.io>',
      to: normalizedEmail,
      subject: `You've been invited to join ${org.name} on QuantumBridge`,
      html: `
        <p>You have been invited to join <strong>${org.name}</strong> on QuantumBridge as a <strong>${role}</strong>.</p>
        <p>Click the link below to accept the invitation:</p>
        <p><a href="${inviteUrl}">Accept Invitation</a></p>
        <p>If you did not expect this invitation, you can safely ignore this email.</p>
      `,
    });
  } catch (emailErr) {
    logger.error('invite_email_failed', { orgId, email: normalizedEmail, error: emailErr });
  }

  logger.info('org_member_invited', { orgId, actorId, email: normalizedEmail, role });
}

/**
 * acceptInvite
 *
 * Req 3.5 — activate OrgMember, clear inviteToken.
 */
export async function acceptInvite(token: string, userId: string): Promise<void> {
  const member = await OrgMember.findOne({ inviteToken: token, status: 'pending' });

  if (!member) {
    throw new NotFoundError('Invitation not found or already accepted');
  }

  member.userId = new mongoose.Types.ObjectId(userId);
  member.status = 'active';
  member.inviteToken = undefined;
  await member.save();

  logger.info('org_invite_accepted', {
    orgId: member.orgId.toString(),
    userId,
    role: member.role,
  });
}

/**
 * removeMember
 *
 * Req 3.6 — delete OrgMember, revoke Redis sessions for that user+org.
 * Req 3.7 — viewers cannot remove members.
 */
export async function removeMember(
  orgId: string,
  actorId: string,
  targetUserId: string
): Promise<void> {
  await assertNotViewer(orgId, actorId);

  const member = await OrgMember.findOne({ orgId, userId: targetUserId });
  if (!member) {
    throw new NotFoundError('Member not found in this organization');
  }

  if (member.role === 'owner') {
    throw new ForbiddenError('Cannot remove the organization owner');
  }

  await OrgMember.deleteOne({ orgId, userId: targetUserId });

  // Revoke all Redis sessions for this user scoped to this org
  // Session keys follow the refresh:family:{familyId} pattern from authService.
  // We scan for any session keys that embed the userId and delete them.
  // Since refresh families are keyed by familyId (not userId), we use a scan
  // pattern approach. The userId is stored inside the family JSON value.
  //
  // For org-scoped session revocation we use a dedicated key set:
  // org-sessions:{orgId}:{userId} → set of familyIds
  const sessionSetKey = `org-sessions:${orgId}:${targetUserId}`;
  const familyIds = await redis.smembers(sessionSetKey);

  if (familyIds.length > 0) {
    const pipeline = redis.pipeline();
    for (const familyId of familyIds) {
      pipeline.del(`refresh:family:${familyId}`);
    }
    pipeline.del(sessionSetKey);
    await pipeline.exec();
    logger.info('org_member_sessions_revoked', { orgId, targetUserId, count: familyIds.length });
  }

  logger.info('org_member_removed', { orgId, actorId, targetUserId });
}

/**
 * transferOwnership
 *
 * Req 3.3 — single owner invariant enforced atomically.
 * Req 3.8 — atomic update of both OrgMember records.
 */
export async function transferOwnership(
  orgId: string,
  currentOwnerId: string,
  newOwnerId: string
): Promise<void> {
  await assertOwner(orgId, currentOwnerId);

  const newOwnerMember = await OrgMember.findOne({
    orgId,
    userId: newOwnerId,
    status: 'active',
  });

  if (!newOwnerMember) {
    throw new NotFoundError('New owner must be an active member of the organization');
  }

  if (newOwnerMember.role === 'owner') {
    throw new ConflictError('This user is already the owner');
  }

  // Atomic update using a MongoDB session to enforce single-owner invariant
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      // Demote current owner to admin
      await OrgMember.updateOne(
        { orgId, userId: currentOwnerId, role: 'owner' },
        { $set: { role: 'admin' } },
        { session }
      );

      // Promote new owner
      await OrgMember.updateOne(
        { orgId, userId: newOwnerId },
        { $set: { role: 'owner' } },
        { session }
      );
    });
  } finally {
    await session.endSession();
  }

  logger.info('org_ownership_transferred', { orgId, currentOwnerId, newOwnerId });
}

/**
 * getMembers
 *
 * Returns all active and pending members of an organization.
 */
export async function getMembers(orgId: string): Promise<InstanceType<typeof OrgMember>[]> {
  return OrgMember.find({ orgId }).sort({ createdAt: 1 });
}
