/**
 * /verify-email — Email verification page (Req 1.3, 1.5)
 *
 * - Reads ?token= from query string and calls GET /auth/verify-email
 * - Shows success, expired (410 → resend option), or error state
 */
import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { apiClient } from '../../lib/apiClient';

type Status = 'loading' | 'success' | 'expired' | 'error';

export default function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') ?? '';

  const [status, setStatus]         = useState<Status>('loading');
  const [resendEmail, setResendEmail] = useState('');
  const [resendSent, setResendSent]  = useState(false);
  const [resendLoading, setResendLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      setStatus('error');
      return;
    }

    apiClient
      .get(`/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(() => setStatus('success'))
      .catch((err: unknown) => {
        const httpStatus = (err as { response?: { status?: number } }).response?.status;
        setStatus(httpStatus === 410 ? 'expired' : 'error');
      });
  }, [token]);

  async function handleResend() {
    if (!resendEmail) return;
    setResendLoading(true);
    try {
      await apiClient.post('/auth/resend-verification', { email: resendEmail });
      setResendSent(true);
    } catch {
      // Silently succeed — don't reveal whether email exists
      setResendSent(true);
    } finally {
      setResendLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      {status === 'loading' && <p>Verifying your email…</p>}

      {status === 'success' && (
        <>
          <h1>Email verified</h1>
          <p>Your account is now active.</p>
          <Link to="/login">Sign in</Link>
        </>
      )}

      {status === 'expired' && (
        <>
          <h1>Link expired</h1>
          <p>Your verification link has expired. Enter your email to get a new one.</p>
          {resendSent ? (
            <p>A new verification email is on its way.</p>
          ) : (
            <div>
              <input
                type="email"
                placeholder="your@email.com"
                value={resendEmail}
                onChange={(e) => setResendEmail(e.target.value)}
                style={{ width: '100%', padding: '8px', marginBottom: 8 }}
              />
              <button
                onClick={handleResend}
                disabled={resendLoading || !resendEmail}
                style={{ width: '100%', padding: '10px' }}
              >
                {resendLoading ? 'Sending…' : 'Resend verification email'}
              </button>
            </div>
          )}
        </>
      )}

      {status === 'error' && (
        <>
          <h1>Verification failed</h1>
          <p>The link is invalid or has already been used.</p>
          <Link to="/login">Back to sign in</Link>
        </>
      )}
    </main>
  );
}
