import { Schema, model, Document, Types } from 'mongoose';

/**
 * ProxyLog — immutable audit record of a single proxied request.
 *
 * Requirements: 6.13, 7.5, 16.1, 16.4, 16.5
 *
 * Never stored: target URL, request/response bodies.
 */
export interface IProxyLog extends Document {
  _id: Types.ObjectId;
  requestId: string;           // UUID v4 — unique per request
  orgId: Types.ObjectId;
  endpointId: Types.ObjectId;
  timestamp: Date;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
  keyVersion: number;
  forwardedToLegacy: boolean;
  clientIp: string;
}

const proxyLogSchema = new Schema<IProxyLog>(
  {
    requestId: {
      type: String,
      required: true,
    },
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
    },
    endpointId: {
      type: Schema.Types.ObjectId,
      ref: 'Endpoint',
      required: true,
    },
    timestamp: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    method: {
      type: String,
      required: true,
    },
    path: {
      type: String,
      required: true,
    },
    statusCode: {
      type: Number,
      required: true,
    },
    latencyMs: {
      type: Number,
      required: true,
    },
    ecdsaVerified: {
      type: Boolean,
      required: true,
      default: false,
    },
    dilithiumVerified: {
      type: Boolean,
      required: true,
      default: false,
    },
    threatFlag: {
      type: Boolean,
      required: true,
      default: false,
    },
    keyVersion: {
      type: Number,
      required: true,
      default: 0,
    },
    forwardedToLegacy: {
      type: Boolean,
      required: true,
      default: false,
    },
    clientIp: {
      type: String,
      required: true,
    },
  },
  {
    // No updatedAt — ProxyLog records are immutable by design
    timestamps: { createdAt: false, updatedAt: false },
  }
);

// Req 16.4 — paginated log queries per org sorted by time
proxyLogSchema.index({ orgId: 1, timestamp: -1 });

// Req 16.5 — threat dashboard queries
proxyLogSchema.index({ orgId: 1, threatFlag: 1 });

// Req 6.13 — unique requestId for deduplication
proxyLogSchema.index({ requestId: 1 }, { unique: true });

export const ProxyLog = model<IProxyLog>('ProxyLog', proxyLogSchema);
