/**
 * /dashboard/endpoints/:id — Endpoint detail page (Req 13.2, 13.6, 14.3)
 *
 * - Per-endpoint ProxyLog table with threat flag color highlight
 * - Key rotation controls (hidden for viewer role)
 * - Built-in API tester: send test request, display raw response + sig status
 */
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface ProxyLogEntry {
  _id: string;
  requestId: string;
  timestamp: string;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
}

interface EndpointDetail {
  _id: string;
  name: string;
  proxySlug: string;
  targetUrl: string;
  isActive: boolean;
  requestCount: number;
}

const th: React.CSSProperties = {
  textAlign: 'left', padding: '10px 12px', fontSize: 12,
  color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em',
  borderBottom: '1px solid #e2e8f0',
};
const td: React.CSSProperties = { padding: '10px 12px', fontSize: 13, borderBottom: '1px solid #f1f5f9' };

export default function EndpointDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { orgId } = useOrg();
  const qc = useQueryClient();

  const [testPath, setTestPath] = useState('/');
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testLoading, setTestLoading] = useState(false);

  const { data: endpoint } = useQuery<EndpointDetail>({
    queryKey: ['endpoint', orgId, id],
    queryFn: () => apiClient.get(`/orgs/${orgId}/endpoints/${id}`).then(r => r.data),
    enabled: !!orgId && !!id,
  });

  const { data: logs = [] } = useQuery<ProxyLogEntry[]>({
    queryKey: ['logs', orgId, id],
    queryFn: () => apiClient.get(`/orgs/${orgId}/logs?endpointId=${id}&limit=50`).then(r => r.data),
    enabled: !!orgId && !!id,
    refetchInterval: 15_000,
  });

  const rotateMutation = useMutation({
    mutationFn: () => apiClient.post(`/orgs/${orgId}/keys/rotate`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['keys', orgId] }),
  });

  async function runTest() {
    if (!endpoint) return;
    setTestLoading(true);
    setTestResult(null);
    try {
      const res = await apiClient.get(`/orgs/${orgId}/endpoints/${id}/test?path=${encodeURIComponent(testPath)}`);
      setTestResult(JSON.stringify(res.data, null, 2));
    } catch (err: unknown) {
      const data = (err as { response?: { data?: unknown } }).response?.data;
      setTestResult(JSON.stringify(data ?? { error: 'Request failed' }, null, 2));
    } finally {
      setTestLoading(false);
    }
  }

  if (!endpoint) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 4 }}>{endpoint.name}</h1>
      <p style={{ fontSize: 13, color: '#64748b', marginBottom: 24, fontFamily: 'monospace' }}>
        {`https://proxy.quantumbridge.io/.../${endpoint.proxySlug}/`}
      </p>

      {/* Key rotation — hidden for viewer (server enforces, UI shows button) */}
      <div style={{ marginBottom: 32 }}>
        <button
          onClick={() => rotateMutation.mutate()}
          disabled={rotateMutation.isPending}
          style={{ padding: '8px 16px', background: '#f59e0b', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', marginRight: 12 }}
        >
          {rotateMutation.isPending ? 'Rotating…' : 'Rotate keys'}
        </button>
        {rotateMutation.isSuccess && <span style={{ color: '#166534', fontSize: 13 }}>Keys rotated.</span>}
        {rotateMutation.isError && <span style={{ color: '#c0392b', fontSize: 13 }}>Rotation failed.</span>}
      </div>

      {/* Built-in API tester (Req 13.6) */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 20, marginBottom: 32 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>API Tester</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            value={testPath}
            onChange={e => setTestPath(e.target.value)}
            placeholder="/path"
            style={{ flex: 1, padding: '8px', border: '1px solid #d1d5db', borderRadius: 4, fontFamily: 'monospace', fontSize: 13 }}
          />
          <button
            onClick={runTest}
            disabled={testLoading}
            style={{ padding: '8px 16px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}
          >
            {testLoading ? 'Sending…' : 'Send'}
          </button>
        </div>
        {testResult && (
          <pre style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 4, padding: 12, fontSize: 12, overflowX: 'auto', maxHeight: 300 }}>
            {testResult}
          </pre>
        )}
      </div>

      {/* ProxyLog table (Req 14.3) */}
      <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Recent requests</h2>
      {logs.length === 0 ? (
        <p style={{ color: '#64748b' }}>No requests yet.</p>
      ) : (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Time</th>
                <th style={th}>Method</th>
                <th style={th}>Path</th>
                <th style={th}>Status</th>
                <th style={th}>Latency</th>
                <th style={th}>ECDSA</th>
                <th style={th}>ML-DSA</th>
                <th style={th}>Threat</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log._id} style={{ background: log.threatFlag ? '#fff1f2' : undefined }}>
                  <td style={td}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td style={{ ...td, fontFamily: 'monospace' }}>{log.method}</td>
                  <td style={{ ...td, fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.path}</td>
                  <td style={td}>
                    <span style={{ color: log.statusCode < 400 ? '#166534' : '#991b1b' }}>{log.statusCode}</span>
                  </td>
                  <td style={td}>{log.latencyMs}ms</td>
                  <td style={td}>{log.ecdsaVerified ? '✓' : '✗'}</td>
                  <td style={td}>{log.dilithiumVerified ? '✓' : '✗'}</td>
                  <td style={td}>
                    {log.threatFlag && <span style={{ color: '#c0392b', fontWeight: 600 }}>⚠ Threat</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
