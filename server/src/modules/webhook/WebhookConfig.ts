import { Schema, model, Document, Types } from 'mongoose';

export interface IWebhookConfig extends Document {
  _id: Types.ObjectId;
  orgId: Types.ObjectId;
  url: string;                  // HTTPS endpoint to POST events to
  secret: string;               // HMAC-SHA256 signing secret (random 32 bytes hex)
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const webhookConfigSchema = new Schema<IWebhookConfig>(
  {
    orgId:    { type: Schema.Types.ObjectId, required: true, ref: 'Organization' },
    url:      { type: String, required: true },
    secret:   { type: String, required: true },
    isActive: { type: Boolean, required: true, default: true },
  },
  { timestamps: true }
);

webhookConfigSchema.index({ orgId: 1 });

export const WebhookConfig = model<IWebhookConfig>('WebhookConfig', webhookConfigSchema);
