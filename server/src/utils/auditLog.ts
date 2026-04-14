import { Schema, model, Document, Types } from 'mongoose';
import logger from './logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditAction =
  | 'member.invited'
  | 'member.removed'
  | 'member.role_changed'
  | 'ownership.transferred'
  | 'endpoint.created'
  | 'endpoint.deleted'
  | 'api_key.regenerated'
  | 'key.rotated'
  | 'plan.changed'
  | 'webhook.registered'
  | 'webhook.deleted';

export type AuditTargetResourceType =
  | 'user'
  | 'organization'
  | 'endpoint'
  | 'keyVault'
  | 'orgMember'
  | 'webhook'
  | 'plan';

export interface IAuditLog extends Document {
  _id: Types.ObjectId;
  actorUserId: Types.ObjectId;
  orgId: Types.ObjectId;
  action: AuditAction;
  targetResourceType: AuditTargetResourceType;
  targetResourceId: string;
  metadata?: Record<string, unknown>;
  ipAddress: string;
  timestamp: Date;
  // NO updatedAt — immutable by design
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const auditLogSchema = new Schema<IAuditLog>(
  {
    actorUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    orgId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'Organization',
    },
    action: {
      type: String,
      required: true,
      enum: [
        'member.invited',
        'member.removed',
        'member.role_changed',
        'ownership.transferred',
        'endpoint.created',
        'endpoint.deleted',
        'api_key.regenerated',
        'key.rotated',
        'plan.changed',
        'webhook.registered',
        'webhook.deleted',
      ] satisfies AuditAction[],
    },
    targetResourceType: {
      type: String,
      required: true,
      enum: ['user', 'organization', 'endpoint', 'keyVault', 'orgMember', 'webhook', 'plan'] satisfies AuditTargetResourceType[],
    },
    targetResourceId: {
      type: String,
      required: true,
    },
    metadata: {
      type: Schema.Types.Mixed,
    },
    ipAddress: {
      type: String,
      required: true,
    },
    timestamp: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
  },
  {
    // Disable automatic timestamps — immutable records manage their own timestamp field.
    // updatedAt is intentionally omitted.
    timestamps: false,
  }
);

// Compound index for efficient per-org audit log queries (newest first)
auditLogSchema.index({ orgId: 1, timestamp: -1 });

export const AuditLog = model<IAuditLog>('AuditLog', auditLogSchema);

// ---------------------------------------------------------------------------
// Write helper — insert-only; no update or delete methods exposed
// ---------------------------------------------------------------------------

export type WriteAuditLogInput = Omit<IAuditLog, '_id' | keyof Document>;

/**
 * Appends a single immutable entry to the AuditLog collection.
 *
 * This is the ONLY write surface for audit logs. No update or delete
 * operations are exposed anywhere in the application (Req 11.7, 16.1).
 */
export async function writeAuditLog(entry: WriteAuditLogInput): Promise<void> {
  try {
    await AuditLog.create(entry);
  } catch (err) {
    // Log the failure but do not rethrow — a failed audit write must never
    // break the primary operation that triggered it.
    logger.error('Failed to write audit log entry', { err, action: entry.action });
  }
}
