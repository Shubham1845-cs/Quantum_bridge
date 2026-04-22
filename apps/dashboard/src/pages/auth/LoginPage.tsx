/**
 * /login — Login page (Req 12.1, 12.2, 12.3, 12.5)
 *
 * - Form with email + password
 * - Inline error on failure — no field-specific hint (Req 12.2)
 * - Redirects to /dashboard on success (Req 12.3)
 * - Loading state prevents duplicate submissions (Req 12.5)
 */
import { useState, type FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

export default function LoginPage() {
  const { login, isLoading } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await login(email, password);
      navigate('/dashboard', { replace: true });
    } catch {
      // Req 12.2 — no field-specific hint
      setError('Invalid email or password.');
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      <h1>Sign in to QuantumBridge</h1>

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
            autoComplete="current-password"
            required
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
          {isLoading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p style={{ marginTop: 16 }}>
        Don't have an account? <Link to="/register">Register</Link>
      </p>
    </main>
  );
}
