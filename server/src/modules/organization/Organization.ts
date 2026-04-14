import { Schema, model, Document, Types } from 'mongoose';

export interface IOrganization extends Document {
  _id: Types.ObjectId;
  name: string;
  slug: string;
  plan: 'free' | 'pro' | 'enterprise';
  stripeSubscriptionId?: string;
  stripeCustomerId?: string;
  monthlyRequestCount: number;
  quotaResetAt: Date;
  publicVerificationEnabled: boolean;
  customDomain?: string;
  customDomainVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const organizationSchema = new Schema<IOrganization>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    slug: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    plan: {
      type: String,
      enum: ['free', 'pro', 'enterprise'],
      required: true,
      default: 'free',
    },
    stripeSubscriptionId: {
      type: String,
    },
    stripeCustomerId: {
      type: String,
    },
    monthlyRequestCount: {
      type: Number,
      required: true,
      default: 0,
    },
    quotaResetAt: {
      type: Date,
      required: true,
    },
    publicVerificationEnabled: {
      type: Boolean,
      required: true,
      default: false,
    },
    customDomain: {
      type: String,
    },
    customDomainVerified: {
      type: Boolean,
      required: true,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

organizationSchema.index({ slug: 1 }, { unique: true });

export const Organization = model<IOrganization>('Organization', organizationSchema);
