/**
 * /dashboard/keys — Keys page (Req 13.4, 13.5)
 *
 * - Display current keypair versions (ECDSA + ML-DSA-65)
 * - Rotation button visible to owner/admin; hidden for viewer
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import { useOrg } from '../../hooks/useOrg';

interface PublicKeySet {
  ecdsaPublicKey: string;
  dilithiumPublicKey: string;
  version: number;
}

interface OrgMember {
  role: 'owner' | 'admin' | 'viewer';
  userId: string;
}

export default function KeysPage() {
  const { orgId } = useOrg();
  const qc = useQueryClient();

  const { data: keys, isLoading: keysLoading } = useQuery<PublicKeySet>({
    queryKey: ['keys', orgId],
    queryFn: () => apiClient.get(`/orgs/${orgId}/keys`).then(r => r.data),
    enabled: !!orgId,
  });

  const { data: members = [] } = useQuery<OrgMember[]>({
    queryKey: ['members', orgId],
    queryFn: () => apiClient.get(`/orgs/${orgId}/members`).then(r => r.data),
    enabled: !!orgId,
  });

  // Determine current user's role from the members list
  // (The auth store has the user ID; we match against members)
  const { useAuthStore } = require('../../store/authStore') as typeof import('../../store/authStore');
  const userId = useAuthStore.getState().user?.id;
  const myMember = members.find(m => m.userId === userId);
  const canRotate = myMember?.role === 'owner' || myMember?.role === 'admin';

  const rotateMutation = useMutation({
    mutationFn: () => apiClient.post(`/orgs/${orgId}/keys/rotate`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['keys', orgId] }),
  });

  if (!orgId || keysLoading) return <p style={{ color: '#64748b' }}>Loading…</p>;

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 24 }}>Cryptographic Keys</h1>

      {keys ? (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24, marginBottom: 24 }}>
          <div style={{ marginBottom: 16 }}>
            <p style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
              Key version
            </p>
            <p style={{ fontSize: 24, fontWeight: 700, color: '#0f172a' }}>v{keys.version}</p>
          </div>

          <div style={{ marginBottom: 16 }}>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#374151', marginBottom: 4 }}>ECDSA P-256 Public Key</p>
            <pre style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 4, padding: 12, fontSize: 11, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {keys.ecdsaPublicKey}
            </pre>
          </div>

          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#374151', marginBottom: 4 }}>ML-DSA-65 Public Key</p>
            <pre style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 4, padding: 12, fontSize: 11, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 120 }}>
              {keys.dilithiumPublicKey}
            </pre>
          </div>
        </div>
      ) : (
        <p style={{ color: '#64748b' }}>No active keypair found.</p>
      )}

      {/* Req 13.5 — rotation button hidden for viewer */}
      {canRotate && (
        <div>
          <button
            onClick={() => rotateMutation.mutate()}
            disabled={rotateMutation.isPending}
            style={{ padding: '10px 20px', background: '#f59e0b', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600 }}
          >
            {rotateMutation.isPending ? 'Rotating…' : 'Rotate keys now'}
          </button>
          {rotateMutation.isSuccess && (
            <p style={{ color: '#166534', marginTop: 8, fontSize: 13 }}>Keys rotated successfully. New version active.</p>
          )}
          {rotateMutation.isError && (
            <p style={{ color: '#c0392b', marginTop: 8, fontSize: 13 }}>Rotation failed. You may not have permission.</p>
          )}
          <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 8 }}>
            Keys auto-rotate every 90 days. Manual rotation takes effect immediately with a 24-hour grace period for in-flight requests.
          </p>
        </div>
      )}
    </div>
  );
}
