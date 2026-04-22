export default function DocsPage() {
  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 760, margin: '0 auto', padding: '80px 24px' }}>
      <h1 style={{ fontSize: 36, fontWeight: 800, color: '#0f172a', marginBottom: 24 }}>Documentation</h1>
      <p style={{ color: '#475569', marginBottom: 32 }}>
        QuantumBridge is a drop-in reverse proxy that adds post-quantum cryptographic signatures to any API.
      </p>
      <h2 style={{ fontSize: 20, fontWeight: 700, color: '#0f172a', marginBottom: 12 }}>Quick start</h2>
      <ol style={{ color: '#374151', lineHeight: 2, paddingLeft: 20 }}>
        <li>Create a free account and register your legacy API endpoint.</li>
        <li>Copy your proxy URL and API key from the dashboard.</li>
        <li>Replace your API base URL with the QuantumBridge proxy URL.</li>
        <li>Add <code>Authorization: Bearer YOUR_API_KEY</code> to every request.</li>
      </ol>
      <p style={{ marginTop: 32, color: '#64748b' }}>
        For full SDK examples, see the <a href="/dashboard/docs" style={{ color: '#0ea5e9' }}>integration guide</a> in your dashboard.
      </p>
    </main>
  );
}
