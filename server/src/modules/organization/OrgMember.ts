import { Schema, model, Document, Types } from 'mongoose';

export interface IOrgMember extends Document {
  _id: Types.ObjectId;
  orgId: Types.ObjectId;
  userId: Types.ObjectId;
  role: 'owner' | 'admin' | 'viewer';
  status: 'active' | 'pending';
  inviteToken?: string;
  inviteEmail?: string;
  createdAt: Date;
}

const orgMemberSchema = new Schema<IOrgMember>(
  {
    orgId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    role: {
      type: String,
      enum: ['owner', 'admin', 'viewer'],
      required: true,
    },
    status: {
      type: String,
      enum: ['active', 'pending'],
      required: true,
      default: 'pending',
    },
    inviteToken: {
      type: String,
    },
    inviteEmail: {
      type: String,
      lowercase: true,
      trim: true,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

// Compound unique index: one membership record per user per org
orgMemberSchema.index({ orgId: 1, userId: 1 }, { unique: true });
// Index for role-based queries (e.g. find all owners of an org)
orgMemberSchema.index({ orgId: 1, role: 1 });

export const OrgMember = model<IOrgMember>('OrgMember', orgMemberSchema);
