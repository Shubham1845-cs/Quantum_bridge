export default function PricingPage() {
  const plans = [
    { name: 'Free', price: '$0', endpoints: '1 endpoint', requests: '10,000 req/mo', cta: 'Get started' },
    { name: 'Pro', price: '$49/mo', endpoints: '10 endpoints', requests: '1M req/mo', cta: 'Upgrade to Pro' },
    { name: 'Enterprise', price: 'Custom', endpoints: 'Unlimited', requests: 'Unlimited', cta: 'Contact us' },
  ];

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 900, margin: '0 auto', padding: '80px 24px' }}>
      <h1 style={{ fontSize: 36, fontWeight: 800, color: '#0f172a', marginBottom: 8, textAlign: 'center' }}>Pricing</h1>
      <p style={{ color: '#64748b', textAlign: 'center', marginBottom: 48 }}>Start free. Scale as you grow.</p>
      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', justifyContent: 'center' }}>
        {plans.map(p => (
          <div key={p.name} style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: 32, flex: '1 1 240px', maxWidth: 280 }}>
            <p style={{ fontWeight: 700, fontSize: 20, color: '#0f172a', marginBottom: 4 }}>{p.name}</p>
            <p style={{ fontSize: 32, fontWeight: 800, color: '#0ea5e9', marginBottom: 16 }}>{p.price}</p>
            <p style={{ color: '#64748b', fontSize: 14, marginBottom: 4 }}>{p.endpoints}</p>
            <p style={{ color: '#64748b', fontSize: 14, marginBottom: 24 }}>{p.requests}</p>
            <a href="/dashboard/register"
              style={{ display: 'block', textAlign: 'center', padding: '10px', background: '#0ea5e9', color: '#fff', borderRadius: 6, textDecoration: 'none', fontWeight: 600 }}>
              {p.cta}
            </a>
          </div>
        ))}
      </div>
    </main>
  );
}
