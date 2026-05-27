import apiClient from './client';

/** POST /billing/checkout — create Stripe checkout session */
export async function createCheckoutSession(
  orgId: string,
  plan: 'pro' | 'enterprise'
): Promise<{ url: string }> {
  const { data } = await apiClient.post<{ url: string }>('/billing/checkout', {
    orgId,
    plan,
  });
  return data;
}

/** GET /billing/portal — get Stripe customer portal URL */
export async function getCustomerPortalUrl(orgId: string): Promise<{ url: string }> {
  const { data } = await apiClient.get<{ url: string }>('/billing/portal', {
    params: { orgId },
  });
  return data;
}
