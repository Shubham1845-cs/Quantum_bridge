/**
 * /dashboard/team — Team management page (Req 13.3)
 *
 * - Invite member form (email + role)
 * - Member list with remove button
 * - Role assignment
 */
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface Member {
  _id: string;
  userId: string;
  role: 'owner' | 'admin' | 'viewer';
  status: 'active' | 'pending';
  inviteEmail?: string;
}

const td: React.CSSProperties = { padding: '12px', fontSize: 14, borderBottom: '1px solid #f1f5f9' };
const th: React.CSSProperties = {
  textAlign: 'left', padding: '10px 12px', fontSize: 12,
  color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em',
  borderBottom: '1px solid #e2e8f0',
};

export default function TeamPage() {
  const { orgId } = useOrg();
  const qc = useQueryClient();

  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'admin' | 'viewer'>('viewer');
  const [inviteError, setInviteError] = useState('');
  const [inviteSuccess, setInviteSuccess] = useState(false);

  const { data: members = [], isLoading } = useQuery<Member[]>({
    queryKey: ['members', orgId],
    queryFn: () => apiClient.get(`/orgs/${orgId}/members`).then(r => r.data),
    enabled: !!orgId,
  });

  const inviteMutation = useMutation({
    mutationFn: () => apiClient.post(`/orgs/${orgId}/members/invite`, { email, role }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['members', orgId] });
      setEmail(''); setInviteSuccess(true); setInviteError('');
      setTimeout(() => setInviteSuccess(false), 3000);
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setInviteError(msg ?? 'Failed to send invite.');
    },
  });

  const removeMutation = useMutation({
    mutationFn: (userId: string) => apiClient.delete(`/orgs/${orgId}/members/${userId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['members', orgId] }),
  });

  if (!orgId || isLoading) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 24 }}>Team</h1>

      {/* Invite form */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 20, marginBottom: 32 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>Invite member</h2>
        <form onSubmit={e => { e.preventDefault(); inviteMutation.mutate(); }} style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="email" required placeholder="email@example.com"
            value={email} onChange={e => setEmail(e.target.value)}
            style={{ flex: '1 1 200px', padding: '8px', border: '1px solid #d1d5db', borderRadius: 4 }}
          />
          <select value={role} onChange={e => setRole(e.target.value as 'admin' | 'viewer')}
            style={{ padding: '8px', border: '1px solid #d1d5db', borderRadius: 4 }}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
          <button type="submit" disabled={inviteMutation.isPending}
            style={{ padding: '8px 16px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
            {inviteMutation.isPending ? 'Sending…' : 'Send invite'}
          </button>
        </form>
        {inviteError && <p role="alert" style={{ color: '#c0392b', marginTop: 8, fontSize: 13 }}>{inviteError}</p>}
        {inviteSuccess && <p style={{ color: '#166534', marginTop: 8, fontSize: 13 }}>Invite sent.</p>}
      </div>

      {/* Member list */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>User</th>
              <th style={th}>Role</th>
              <th style={th}>Status</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {members.map(m => (
              <tr key={m._id}>
                <td style={td}>{m.inviteEmail ?? m.userId}</td>
                <td style={td}>
                  <span style={{
                    padding: '2px 8px', borderRadius: 12, fontSize: 12,
                    background: m.role === 'owner' ? '#fef3c7' : m.role === 'admin' ? '#dbeafe' : '#f1f5f9',
                    color: m.role === 'owner' ? '#92400e' : m.role === 'admin' ? '#1e40af' : '#475569',
                  }}>
                    {m.role}
                  </span>
                </td>
                <td style={td}>
                  <span style={{ fontSize: 12, color: m.status === 'active' ? '#166534' : '#92400e' }}>
                    {m.status}
                  </span>
                </td>
                <td style={td}>
                  {m.role !== 'owner' && (
                    <button
                      onClick={() => removeMutation.mutate(m.userId)}
                      disabled={removeMutation.isPending}
                      style={{ padding: '4px 10px', background: '#fee2e2', color: '#991b1b', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
