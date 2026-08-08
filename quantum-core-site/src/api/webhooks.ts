import apiClient from './client';

export interface Webhook {
  _id: string;
  url: string;
  status: 'active' | 'failed';
  lastDeliveryAt?: string;
  createdAt: string;
}

export interface WebhookDelivery {
  _id: string;
  webhookId: string;
  requestId: string;
  status: 'success' | 'failed';
  responseCode?: number;
  errorMessage?: string;
  deliveredAt: string;
}

/** GET /orgs/:orgId/webhooks — list all webhooks */
export async function listWebhooks(orgId: string): Promise<Webhook[]> {
  const { data } = await apiClient.get<Webhook[]>(`/orgs/${orgId}/webhooks`);
  return data;
}

/** POST /orgs/:orgId/webhooks — create a new webhook */
export async function createWebhook(orgId: string, url: string): Promise<Webhook> {
  const { data } = await apiClient.post<Webhook>(`/orgs/${orgId}/webhooks`, { url });
  return data;
}

/** DELETE /orgs/:orgId/webhooks/:webhookId — delete a webhook */
export async function deleteWebhook(orgId: string, webhookId: string): Promise<void> {
  await apiClient.delete(`/orgs/${orgId}/webhooks/${webhookId}`);
}

/** GET /orgs/:orgId/webhooks/:webhookId/deliveries — get webhook delivery log */
export async function getWebhookDeliveries(
  orgId: string,
  webhookId: string
): Promise<WebhookDelivery[]> {
  const { data } = await apiClient.get<WebhookDelivery[]>(
    `/orgs/${orgId}/webhooks/${webhookId}/deliveries`
  );
  return data;
}
