import { Link } from 'react-router-dom';

export default function LandingPage() {
  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 900, margin: '0 auto', padding: '80px 24px' }}>
      <h1 style={{ fontSize: 48, fontWeight: 800, color: '#0f172a', lineHeight: 1.1, marginBottom: 16 }}>
        Quantum-safe security<br />for your legacy APIs
      </h1>
      <p style={{ fontSize: 18, color: '#475569', maxWidth: 560, marginBottom: 40 }}>
        QuantumBridge wraps any API in a hybrid ECDSA + ML-DSA-65 dual-signature layer —
        zero changes to your existing system.
      </p>
      <div style={{ display: 'flex', gap: 12 }}>
        <a href="/dashboard/register"
          style={{ padding: '12px 28px', background: '#0ea5e9', color: '#fff', borderRadius: 8, textDecoration: 'none', fontWeight: 600, fontSize: 15 }}>
          Get started free
        </a>
        <Link to="/pricing"
          style={{ padding: '12px 28px', background: '#fff', color: '#0f172a', border: '1px solid #e2e8f0', borderRadius: 8, textDecoration: 'none', fontWeight: 600, fontSize: 15 }}>
          See pricing
        </Link>
      </div>
    </main>
  );
}
