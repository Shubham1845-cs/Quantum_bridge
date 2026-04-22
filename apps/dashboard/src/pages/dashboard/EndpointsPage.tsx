/**
 * /dashboard/endpoints — Endpoint list page (Req 13.1)
 *
 * Table: proxy URL, status, request count per endpoint
 */
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface Endpoint {
  _id: string;
  name: string;
  proxySlug: string;
  targetUrl: string;
  isActive: boolean;
  requestCount: number;
  createdAt: string;
}

const th: React.CSSProperties = {
  textAlign: 'left', padding: '10px 12px', fontSize: 12,
  color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em',
  borderBottom: '1px solid #e2e8f0',
};
const td: React.CSSProperties = {
  padding: '12px', fontSize: 14, borderBottom: '1px solid #f1f5f9',
};

export default function EndpointsPage() {
  const { orgId } = useOrg();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [formError, setFormError] = useState('');

  const { data: endpoints = [], isLoading } = useQuery<Endpoint[]>({
    queryKey: ['endpoints', orgId],
    queryFn: () => apiClient.get(`/orgs/${orgId}/endpoints`).then(r => r.data),
    enabled: !!orgId,
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.post(`/orgs/${orgId}/endpoints`, { name, targetUrl }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['endpoints', orgId] });
      setShowForm(false); setName(''); setTargetUrl(''); setFormError('');
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setFormError(msg ?? 'Failed to create endpoint.');
    },
  });

  if (!orgId || isLoading) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a' }}>Endpoints</h1>
        <button
          onClick={() => setShowForm(v => !v)}
          style={{ padding: '8px 16px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}
        >
          {showForm ? 'Cancel' : '+ New endpoint'}
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={e => { e.preventDefault(); createMutation.mutate(); }}
          style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 20, marginBottom: 24 }}
        >
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 13, color: '#374151' }}>Name</label>
            <input value={name} onChange={e => setName(e.target.value)} required
              style={{ display: 'block', width: '100%', padding: '8px', marginTop: 4, border: '1px solid #d1d5db', borderRadius: 4 }} />
          </div>
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 13, color: '#374151' }}>Target URL (HTTPS)</label>
            <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)} required type="url"
              style={{ display: 'block', width: '100%', padding: '8px', marginTop: 4, border: '1px solid #d1d5db', borderRadius: 4 }} />
          </div>
          {formError && <p role="alert" style={{ color: '#c0392b', marginBottom: 8 }}>{formError}</p>}
          <button type="submit" disabled={createMutation.isPending}
            style={{ padding: '8px 20px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
            {createMutation.isPending ? 'Creating…' : 'Create'}
          </button>
        </form>
      )}

      {endpoints.length === 0 ? (
        <p style={{ color: '#64748b' }}>No endpoints yet. Create one to get started.</p>
      ) : (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>Name</th>
                <th style={th}>Proxy URL</th>
                <th style={th}>Status</th>
                <th style={th}>Requests</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map(ep => (
                <tr key={ep._id}>
                  <td style={td}>
                    <Link to={`/dashboard/endpoints/${ep._id}`} style={{ color: '#0ea5e9', textDecoration: 'none' }}>
                      {ep.name}
                    </Link>
                  </td>
                  <td style={{ ...td, fontFamily: 'monospace', fontSize: 12, color: '#475569' }}>
                    {`https://proxy.quantumbridge.io/.../${ep.proxySlug}/`}
                  </td>
                  <td style={td}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 12, fontSize: 12,
                      background: ep.isActive ? '#dcfce7' : '#fee2e2',
                      color: ep.isActive ? '#166534' : '#991b1b',
                    }}>
                      {ep.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td style={td}>{ep.requestCount.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
