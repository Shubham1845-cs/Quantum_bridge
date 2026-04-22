/**
 * /verify/:requestId — Public verification page (Req 18.1, 18.6)
 *
 * - Unauthenticated
 * - Fetches GET /verify/:requestId
 * - Displays: timestamp, org ID, verification status
 * - No internal IDs or target URLs exposed
 */
import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../../lib/apiClient';

interface VerifyResult {
  requestId: string;
  orgId: string;
  timestamp: string | number;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
  ecdsaPublicKey: string | null;
  dilithiumPublicKey: string | null;
}

type Status = 'loading' | 'found' | 'not_found' | 'error';

function StatusBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '10px 16px', borderRadius: 8,
      background: ok ? '#dcfce7' : '#fee2e2',
      color: ok ? '#166534' : '#991b1b',
      marginBottom: 8,
    }}>
      <span style={{ fontSize: 18 }}>{ok ? '✓' : '✗'}</span>
      <span style={{ fontWeight: 600 }}>{label}</span>
      <span style={{ marginLeft: 'auto', fontSize: 13 }}>{ok ? 'Verified' : 'Failed'}</span>
    </div>
  );
}

export default function VerifyRequestPage() {
  const { requestId } = useParams<{ requestId: string }>();
  const [status, setStatus] = useState<Status>('loading');
  const [result, setResult] = useState<VerifyResult | null>(null);

  useEffect(() => {
    if (!requestId) { setStatus('error'); return; }

    apiClient.get(`/verify/${requestId}`)
      .then(r => { setResult(r.data); setStatus('found'); })
      .catch((err: unknown) => {
        const httpStatus = (err as { response?: { status?: number } }).response?.status;
        setStatus(httpStatus === 404 ? 'not_found' : 'error');
      });
  }, [requestId]);

  return (
    <main style={{ maxWidth: 560, margin: '60px auto', padding: '0 16px', fontFamily: 'system-ui, sans-serif' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 4 }}>
          QuantumBridge Verification
        </h1>
        <p style={{ fontSize: 13, color: '#64748b' }}>
          Verify the cryptographic integrity of a proxied request.
        </p>
      </div>

      {status === 'loading' && <p style={{ color: '#64748b' }}>Verifying…</p>}

      {status === 'not_found' && (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24 }}>
          <p style={{ color: '#64748b' }}>No verification record found for this request ID.</p>
        </div>
      )}

      {status === 'error' && (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24 }}>
          <p style={{ color: '#c0392b' }}>Verification lookup failed. Please try again.</p>
        </div>
      )}

      {status === 'found' && result && (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24 }}>
          {/* Timestamp */}
          <div style={{ marginBottom: 20 }}>
            <p style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
              Request timestamp
            </p>
            <p style={{ fontSize: 15, color: '#0f172a' }}>
              {new Date(result.timestamp).toLocaleString()}
            </p>
          </div>

          {/* Overall status */}
          <div style={{ marginBottom: 20 }}>
            <p style={{ fontSize: 12, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
              Signature verification
            </p>
            <StatusBadge ok={result.ecdsaVerified} label="ECDSA P-256" />
            <StatusBadge ok={result.dilithiumVerified} label="ML-DSA-65 (Post-Quantum)" />
          </div>

          {/* Threat flag */}
          {result.threatFlag && (
            <div style={{ background: '#fff1f2', border: '1px solid #fecaca', borderRadius: 8, padding: 12, marginBottom: 20 }}>
              <p style={{ color: '#991b1b', fontWeight: 600, fontSize: 14 }}>
                ⚠ Threat detected — one or more signatures failed verification.
              </p>
            </div>
          )}

          {!result.threatFlag && result.ecdsaVerified && result.dilithiumVerified && (
            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: 12, marginBottom: 20 }}>
              <p style={{ color: '#166534', fontWeight: 600, fontSize: 14 }}>
                ✓ Both signatures valid — request integrity confirmed.
              </p>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
