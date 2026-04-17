import { Resend } from 'resend';
import { Organization } from '../organization/Organization.js';
import { OrgMember } from '../organization/OrgMember.js';
import { User } from '../auth/User.js';
import { redis } from '../../config/redis.js';
import { env } from '../../config/env.js';
import logger from '../../utils/logger.js';

const resend = new Resend(env.RESEND_API_KEY);

// ---------------------------------------------------------------------------
// Plan quota limits (Req 8.1)
// ---------------------------------------------------------------------------
export const PLAN_QUOTA: Record<string, number> = {
  free:       10_000,
  pro:        1_000_000,
  enterprise: Infinity,
};

export class QuotaExceededError extends Error {
  readonly statusCode = 429;
  constructor(message = 'Monthly request quota exceeded') {
    super(message);
    this.name = 'QuotaExceededError';
  }
}

// ---------------------------------------------------------------------------
// sendQuotaWarningEmail (Req 8.2)
//
// Sends a warning email to the org owner when usage reaches 90% of quota.
// Uses a Redis flag (TTL = seconds until quota reset) to send only once per
// quota window.
// ---------------------------------------------------------------------------
async function sendQuotaWarningEmail(
  orgId: string,
  orgName: string,
  plan: string,
  count: number,
  limit: number,
  quotaResetAt: Date,
): Promise<void> {
  const flagKey = `quota:warning:${orgId}`;

  // Only send once per quota window
  const alreadySent = await redis.get(flagKey);
  if (alreadySent) return;

  // Find the org owner's email
  const ownerMembership = await OrgMember.findOne({ orgId, role: 'owner', status: 'active' });
  if (!ownerMembership) return;

  const owner = await User.findById(ownerMembership.userId).select('email');
  if (!owner) return;

  const pct = Math.round((count / limit) * 100);
  const resetDate = quotaResetAt.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  try {
    await resend.emails.send({
      from: 'QuantumBridge <noreply@quantumbridge.io>',
      to: owner.email,
      subject: `[QuantumBridge] You've used ${pct}% of your monthly quota`,
      html: `
        <p>Hi,</p>
        <p>Your organization <strong>${orgName}</strong> has used <strong>${count.toLocaleString()} of ${limit.toLocaleString()} requests</strong> (${pct}%) on the <strong>${plan}</strong> plan.</p>
        <p>Your quota resets on <strong>${resetDate}</strong>. Once you reach 100%, all proxy requests will be blocked until the quota resets.</p>
        <p>To avoid disruption, consider <a href="${env.ALLOWED_ORIGIN}/dashboard/billing">upgrading your plan</a>.</p>
        <p>— The QuantumBridge Team</p>
      `,
    });

    // Set Redis flag with TTL = seconds until quota reset (min 60s)
    const ttlSeconds = Math.max(60, Math.floor((quotaResetAt.getTime() - Date.now()) / 1000));
    await redis.set(flagKey, '1', 'EX', ttlSeconds);

    logger.info('quota_warning_email_sent', { orgId, plan, count, limit, pct });
  } catch (err) {
    logger.error('quota_warning_email_failed', { orgId, err });
  }
}

// ---------------------------------------------------------------------------
// atomicQuotaCheckAndIncrement (Req 8.3)
//
// Uses a MongoDB aggregation pipeline update to atomically:
//   1. Reset monthlyRequestCount to 0 if quotaResetAt has passed.
//   2. Increment monthlyRequestCount by 1.
//   3. Return the post-update document.
//
// If the post-increment count exceeds the plan limit, the increment is undone
// and QuotaExceededError is thrown.
//
// After a successful increment, triggers a 90% warning email if applicable.
// Enterprise orgs (Infinity limit) skip both checks.
// ---------------------------------------------------------------------------
export async function atomicQuotaCheckAndIncrement(orgId: string): Promise<void> {
  const now = new Date();

  const updated = await Organization.findOneAndUpdate(
    { _id: orgId },
    [
      {
        $set: {
          monthlyRequestCount: {
            $cond: {
              if: { $lte: ['$quotaResetAt', now] },
              then: 1,
              else: { $add: ['$monthlyRequestCount', 1] },
            },
          },
          quotaResetAt: {
            $cond: {
              if: { $lte: ['$quotaResetAt', now] },
              then: (() => {
                const nextMonth = new Date(now);
                nextMonth.setUTCMonth(nextMonth.getUTCMonth() + 1, 1);
                nextMonth.setUTCHours(0, 0, 0, 0);
                return nextMonth;
              })(),
              else: '$quotaResetAt',
            },
          },
        },
      },
    ],
    { new: true, select: 'name plan monthlyRequestCount quotaResetAt' }
  );

  if (!updated) {
    logger.warn('quota_check_org_not_found', { orgId });
    return;
  }

  const limit = PLAN_QUOTA[updated.plan] ?? PLAN_QUOTA.free;

  // Enterprise has no limit — skip all checks
  if (limit === Infinity) return;

  if (updated.monthlyRequestCount > limit) {
    // Undo the increment to keep the counter accurate
    await Organization.updateOne(
      { _id: orgId },
      { $inc: { monthlyRequestCount: -1 } }
    );

    logger.warn('quota_exceeded', {
      orgId,
      plan: updated.plan,
      count: updated.monthlyRequestCount,
      limit,
    });

    throw new QuotaExceededError(
      `Monthly request quota of ${limit.toLocaleString()} exceeded for ${updated.plan} plan.`
    );
  }

  // Req 8.2 — trigger 90% warning email (fire-and-forget, never blocks the request)
  const usageRatio = updated.monthlyRequestCount / limit;
  if (usageRatio >= 0.9) {
    sendQuotaWarningEmail(
      orgId,
      updated.name,
      updated.plan,
      updated.monthlyRequestCount,
      limit,
      updated.quotaResetAt,
    ).catch((err) => logger.error('quota_warning_trigger_failed', { orgId, err }));
  }
}
