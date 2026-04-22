/**
 * /dashboard/analytics — Analytics page (Req 7.2, 14.1, 14.4, 14.5)
 *
 * - Recharts line/bar charts: request volume, ECDSA rate, ML-DSA rate, threat flag rate
 * - Date range filter (last 24h, 7d, 30d, custom)
 * - CSV/JSON export button
 */
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

type Range = '24h' | '7d' | '30d';

interface TimeseriesPoint {
  bucket: string;
  requests: number;
  threats: number;
  ecdsaVerified: number;
  dilithiumVerified: number;
}

const RANGES: { label: string; value: Range }[] = [
  { label: 'Last 24h', value: '24h' },
  { label: 'Last 7d',  value: '7d'  },
  { label: 'Last 30d', value: '30d' },
];

export default function AnalyticsPage() {
  const { orgId } = useOrg();
  const [range, setRange] = useState<Range>('7d');

  const { data: timeseries = [], isLoading } = useQuery<TimeseriesPoint[]>({
    queryKey: ['analytics-timeseries', orgId, range],
    queryFn: () =>
      apiClient.get(`/orgs/${orgId}/analytics/timeseries?range=${range}`).then(r => r.data),
    enabled: !!orgId,
  });

  function exportData(format: 'csv' | 'json') {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(timeseries, null, 2)], { type: 'application/json' });
      download(blob, `analytics-${range}.json`);
    } else {
      const header = 'bucket,requests,threats,ecdsaVerified,dilithiumVerified\n';
      const rows = timeseries.map(p =>
        `${p.bucket},${p.requests},${p.threats},${p.ecdsaVerified},${p.dilithiumVerified}`
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      download(blob, `analytics-${range}.csv`);
    }
  }

  function download(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  const btnStyle = (active: boolean): React.CSSProperties => ({
    padding: '6px 14px', border: '1px solid #e2e8f0', borderRadius: 6,
    background: active ? '#0ea5e9' : '#fff', color: active ? '#fff' : '#374151',
    cursor: 'pointer', fontSize: 13,
  });

  if (!orgId) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a' }}>Analytics</h1>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {/* Date range filter (Req 14.4) */}
          {RANGES.map(r => (
            <button key={r.value} style={btnStyle(range === r.value)} onClick={() => setRange(r.value)}>
              {r.label}
            </button>
          ))}
          {/* Export (Req 14.5) */}
          <button onClick={() => exportData('csv')} style={{ ...btnStyle(false), marginLeft: 8 }}>Export CSV</button>
          <button onClick={() => exportData('json')} style={btnStyle(false)}>Export JSON</button>
        </div>
      </div>

      {isLoading ? (
        <p style={{ color: '#64748b' }}>Loading charts…</p>
      ) : timeseries.length === 0 ? (
        <p style={{ color: '#64748b' }}>No data for this period.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
          {/* Request volume */}
          <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 20 }}>
            <h2 style={{ fontSize: 14, fontWeight: 600, color: '#374151', marginBottom: 16 }}>Request volume</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timeseries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="bucket" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Legend />
                <Bar dataKey="requests" fill="#0ea5e9" name="Requests" />
                <Bar dataKey="threats" fill="#f87171" name="Threats" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Signature verification rates */}
          <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 20 }}>
            <h2 style={{ fontSize: 14, fontWeight: 600, color: '#374151', marginBottom: 16 }}>Signature verification</h2>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={timeseries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="bucket" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="ecdsaVerified" stroke="#6366f1" name="ECDSA verified" dot={false} />
                <Line type="monotone" dataKey="dilithiumVerified" stroke="#10b981" name="ML-DSA verified" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
