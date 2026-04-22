/**
 * /register — Registration page (Req 12.1, 12.5)
 *
 * - Form with email + password
 * - On success: show "check your email" message (Req 1.1)
 * - Loading state prevents duplicate submissions (Req 12.5)
 */
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '../../lib/apiClient';

export default function RegisterPage() {
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [success, setSuccess]   = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      await apiClient.post('/auth/register', { email, password });
      setSuccess(true);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 409) {
        // Req 1.2 — don't reveal whether account exists
        setSuccess(true);
      } else {
        setError('Registration failed. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  if (success) {
    return (
      <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
        <h1>Check your email</h1>
        <p>
          We've sent a verification link to <strong>{email}</strong>. Click the
          link to activate your account.
        </p>
        <p>
          <Link to="/login">Back to sign in</Link>
        </p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      <h1>Create your account</h1>

      <form onSubmit={handleSubmit} noValidate>
        <div style={{ marginBottom: 12 }}>
          <label htmlFor="email">Email</label>
          <br />
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={isLoading}
            style={{ width: '100%', padding: '8px', marginTop: 4 }}
          />
        </div>

        <div style={{ marginBottom: 12 }}>
          <label htmlFor="password">Password</label>
          <br />
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isLoading}
            style={{ width: '100%', padding: '8px', marginTop: 4 }}
          />
        </div>

        {error && (
          <p role="alert" style={{ color: '#c0392b', marginBottom: 12 }}>
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={isLoading}
          style={{ width: '100%', padding: '10px', cursor: isLoading ? 'not-allowed' : 'pointer' }}
        >
          {isLoading ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <p style={{ marginTop: 16 }}>
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </main>
  );
}
