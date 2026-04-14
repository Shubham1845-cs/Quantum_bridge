import { Schema, model, Document, Types } from 'mongoose';

/**
 * Endpoint — a registered legacy API target URL belonging to an Organization.
 *
 * Requirements: 5.8, 16.1, 16.2, 16.3
 */
export interface IEndpoint extends Document {
  _id: Types.ObjectId;
  orgId: Types.ObjectId;
  name: string;
  targetUrl: string;        // HTTPS only — validated before save
  proxySlug: string;        // unique across all orgs — used in proxy routing
  apiKeyHash: string;       // SHA-256 hex digest of the raw API key
  ipAllowlist: string[];    // optional IP allowlist; empty = allow all
  isActive: boolean;        // soft-delete flag
  deletedAt?: Date;         // set on soft-delete
  requestCount: number;     // lifetime request counter
  createdAt: Date;
  updatedAt: Date;
}

const endpointSchema = new Schema<IEndpoint>(
  {
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    targetUrl: {
      type: String,
      required: true,
      trim: true,
      // HTTPS enforcement is done at the service layer before creation
    },
    proxySlug: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    apiKeyHash: {
      // SHA-256 hex digest — never the raw key
      type: String,
      required: true,
    },
    ipAllowlist: {
      type: [String],
      default: [],
    },
    isActive: {
      type: Boolean,
      required: true,
      default: true,
    },
    deletedAt: {
      type: Date,
    },
    requestCount: {
      type: Number,
      required: true,
      default: 0,
    },
  },
  {
    timestamps: true, // createdAt + updatedAt
  }
);

// Req 5.8, 16.2 — unique index on proxySlug prevents routing collisions
endpointSchema.index({ proxySlug: 1 }, { unique: true });

// Req 16.3 — compound index for per-org endpoint queries
endpointSchema.index({ orgId: 1 });

export const Endpoint = model<IEndpoint>('Endpoint', endpointSchema);
