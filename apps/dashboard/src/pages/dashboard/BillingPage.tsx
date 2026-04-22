/**
 * /dashboard/billing — Billing page (Req 8.4, 8.8)
 *
 * - Upgrade plan button → POST /billing/checkout
 * - Stripe customer portal redirect → GET /billing/portal
 */
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface OrgBilling {
  plan: 'free' | 'pro' | 'enterprise';
  monthlyRequestCount: number;
  quotaResetAt: string;
}

const PLAN_LABELS: Record<string, string> = {
  free: 'Free',
  pro: 'Pro',
  enterprise: 'Enterprise',
};

export default function BillingPage() {
  const { orgId } = useOrg();
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [portalLoading, setPortalLoading] = useState(false);
  const [error, setError] = useState('');

  const { data: org } = useQuery<OrgBilling>({
    queryKey: ['org-billing', orgId],
    queryFn: () => apiClient.get(`/orgs/${orgId}`).then(r => r.data),
    enabled: !!orgId,
  });

  async function handleUpgrade(plan: 'pro' | 'enterprise') {
    setCheckoutLoading(true); setError('');
    try {
      const { data } = await apiClient.post<{ url: string }>(`/orgs/${orgId}/billing/checkout`, { plan });
      window.location.href = data.url;
    } catch {
      setError('Failed to start checkout. Please try again.');
      setCheckoutLoading(false);
    }
  }

  async function handlePortal() {
    setPortalLoading(true); setError('');
    try {
      const { data } = await apiClient.get<{ url: string }>(`/orgs/${orgId}/billing/portal`);
      window.location.href = data.url;
    } catch {
      setError('Failed to open billing portal. Please try again.');
      setPortalLoading(false);
    }
  }

  if (!orgId || !org) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 24 }}>Billing</h1>

      {/* Current plan */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24, marginBottom: 24 }}>
        <p style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Current plan</p>
        <p style={{ fontSize: 28, fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>{PLAN_LABELS[org.plan]}</p>
        <p style={{ fontSize: 13, color: '#64748b' }}>
          {org.monthlyRequestCount.toLocaleString()} requests used this month ·
          Resets {new Date(org.quotaResetAt).toLocaleDateString()}
        </p>
      </div>

      {error && <p role="alert" style={{ color: '#c0392b', marginBottom: 16 }}>{error}</p>}

      {/* Upgrade options */}
      {org.plan === 'free' && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
          <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24, flex: '1 1 220px' }}>
            <p style={{ fontWeight: 700, fontSize: 18, marginBottom: 4 }}>Pro</p>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 16 }}>10 endpoints · 1M requests/month</p>
            <button
              onClick={() => handleUpgrade('pro')}
              disabled={checkoutLoading}
              style={{ width: '100%', padding: '10px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 }}
            >
              {checkoutLoading ? 'Redirecting…' : 'Upgrade to Pro'}
            </button>
          </div>
          <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24, flex: '1 1 220px' }}>
            <p style={{ fontWeight: 700, fontSize: 18, marginBottom: 4 }}>Enterprise</p>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 16 }}>Unlimited endpoints · Unlimited requests</p>
            <button
              onClick={() => handleUpgrade('enterprise')}
              disabled={checkoutLoading}
              style={{ width: '100%', padding: '10px', background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 }}
            >
              {checkoutLoading ? 'Redirecting…' : 'Upgrade to Enterprise'}
            </button>
          </div>
        </div>
      )}

      {/* Stripe portal for existing subscribers */}
      {org.plan !== 'free' && (
        <button
          onClick={handlePortal}
          disabled={portalLoading}
          style={{ padding: '10px 20px', background: '#fff', border: '1px solid #e2e8f0', borderRadius: 6, cursor: 'pointer', fontSize: 14 }}
        >
          {portalLoading ? 'Opening portal…' : 'Manage subscription & invoices'}
        </button>
      )}
    </div>
  );
}
