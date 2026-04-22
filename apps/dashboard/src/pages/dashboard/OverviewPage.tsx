/**
 * /dashboard — Overview page (Req 7.1, 14.2)
 *
 * Summary cards:
 *   - Requests today
 *   - Threats flagged today
 *   - Average latency (ms)
 *   - Plan usage (requests used / quota)
 *
 * Fetches from GET /orgs/:orgId/analytics/summary
 */
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface AnalyticsSummary {
  requestsToday: number;
  threatFlagsToday: number;
  avgLatencyMs: number;
  sigSuccessRate: number;
  planUsed: number;
  planQuota: number;
  plan: string;
}

const cardStyle: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: 8,
  padding: '20px 24px',
  minWidth: 180,
  flex: '1 1 180px',
};

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  color: '#64748b',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  marginBottom: 6,
};

const valueStyle: React.CSSProperties = {
  fontSize: 28,
  fontWeight: 700,
  color: '#0f172a',
};

function SummaryCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={cardStyle}>
      <p style={labelStyle}>{label}</p>
      <p style={valueStyle}>{value}</p>
    </div>
  );
}

export default function OverviewPage() {
  const { orgId } = useOrg();

  const { data, isLoading, isError } = useQuery<AnalyticsSummary>({
    queryKey: ['analytics-summary', orgId],
    queryFn: () =>
      apiClient.get(`/orgs/${orgId}/analytics/summary`).then((r) => r.data),
    enabled: !!orgId,
    refetchInterval: 30_000, // refresh every 30s for near-real-time feel
  });

  if (!orgId || isLoading) {
    return <p style={{ color: '#64748b' }}>Loading…</p>;
  }

  if (isError || !data) {
    return <p style={{ color: '#c0392b' }}>Failed to load analytics.</p>;
  }

  const usagePct =
    data.planQuota === Infinity || data.planQuota === 0
      ? '∞'
      : `${data.planUsed.toLocaleString()} / ${data.planQuota.toLocaleString()}`;

  return (
    <div>
      <h1 style={{ marginBottom: 24, fontSize: 22, fontWeight: 700, color: '#0f172a' }}>
        Overview
      </h1>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
        <SummaryCard
          label="Requests today"
          value={data.requestsToday.toLocaleString()}
        />
        <SummaryCard
          label="Threats today"
          value={data.threatFlagsToday.toLocaleString()}
        />
        <SummaryCard
          label="Avg latency"
          value={`${Math.round(data.avgLatencyMs)} ms`}
        />
        <SummaryCard
          label={`Plan usage (${data.plan})`}
          value={usagePct}
        />
      </div>
    </div>
  );
}
