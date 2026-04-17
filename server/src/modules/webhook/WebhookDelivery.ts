import { Schema, model, Document, Types } from 'mongoose';

export type DeliveryStatus = 'delivered' | 'failed' | 'permanently_failed';

export interface IWebhookDelivery extends Document {
  _id: Types.ObjectId;
  webhookId: Types.ObjectId;    // ref WebhookConfig
  orgId: Types.ObjectId;
  requestId: string;            // the ProxyLog requestId that triggered this delivery
  attempt: number;              // 1, 2, or 3
  status: DeliveryStatus;
  httpStatus?: number;          // response status code (if received)
  responseTimeMs?: number;
  error?: string;               // error message on failure
  createdAt: Date;
}

const webhookDeliverySchema = new Schema<IWebhookDelivery>(
  {
    webhookId:      { type: Schema.Types.ObjectId, required: true, ref: 'WebhookConfig' },
    orgId:          { type: Schema.Types.ObjectId, required: true },
    requestId:      { type: String, required: true },
    attempt:        { type: Number, required: true },
    status:         { type: String, enum: ['delivered', 'failed', 'permanently_failed'], required: true },
    httpStatus:     { type: Number },
    responseTimeMs: { type: Number },
    error:          { type: String },
  },
  {
    timestamps: { createdAt: true, updatedAt: false }, // immutable — no updatedAt
  }
);

webhookDeliverySchema.index({ webhookId: 1, createdAt: -1 });
webhookDeliverySchema.index({ orgId: 1, requestId: 1 });

export const WebhookDelivery = model<IWebhookDelivery>('WebhookDelivery', webhookDeliverySchema);
