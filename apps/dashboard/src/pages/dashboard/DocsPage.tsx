/**
 * /dashboard/docs — Integration docs page (Req 13.7)
 *
 * Copy-paste SDK snippets for Node.js, Python, and curl
 */
import { useState } from 'react';

const PROXY_URL = 'https://proxy.quantumbridge.io/{org-slug}/{proxy-slug}/';
const API_KEY   = 'YOUR_API_KEY';

const SNIPPETS = {
  nodejs: `// Node.js — send a request through QuantumBridge
const response = await fetch('${PROXY_URL}your/path', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ${API_KEY}',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ key: 'value' }),
});
const data = await response.json();
console.log(data);`,

  python: `# Python — send a request through QuantumBridge
import requests

response = requests.post(
    '${PROXY_URL}your/path',
    headers={
        'Authorization': 'Bearer ${API_KEY}',
        'Content-Type': 'application/json',
    },
    json={'key': 'value'},
)
print(response.json())`,

  curl: `# curl — send a request through QuantumBridge
curl -X POST '${PROXY_URL}your/path' \\
  -H 'Authorization: Bearer ${API_KEY}' \\
  -H 'Content-Type: application/json' \\
  -d '{"key":"value"}'`,
};

type Lang = keyof typeof SNIPPETS;

export default function DocsPage() {
  const [activeLang, setActiveLang] = useState<Lang>('nodejs');
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(SNIPPETS[activeLang]).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '8px 16px', border: 'none', borderBottom: active ? '2px solid #0ea5e9' : '2px solid transparent',
    background: 'none', cursor: 'pointer', fontSize: 13, fontWeight: active ? 600 : 400,
    color: active ? '#0ea5e9' : '#64748b',
  });

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>Integration Guide</h1>
      <p style={{ color: '#64748b', marginBottom: 32, fontSize: 14 }}>
        Route your API traffic through QuantumBridge by replacing your legacy API URL with your proxy URL.
        Authenticate each request with your endpoint API key.
      </p>

      {/* Quick start */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, marginBottom: 32 }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #f1f5f9' }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, color: '#0f172a' }}>Quick start</h2>
        </div>

        {/* Language tabs */}
        <div style={{ display: 'flex', borderBottom: '1px solid #f1f5f9', padding: '0 8px' }}>
          {(Object.keys(SNIPPETS) as Lang[]).map(lang => (
            <button key={lang} style={tabStyle(activeLang === lang)} onClick={() => setActiveLang(lang)}>
              {lang === 'nodejs' ? 'Node.js' : lang === 'python' ? 'Python' : 'curl'}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative' }}>
          <pre style={{ margin: 0, padding: '20px', fontSize: 12, overflowX: 'auto', background: '#0f172a', color: '#e2e8f0', borderRadius: '0 0 8px 8px' }}>
            {SNIPPETS[activeLang]}
          </pre>
          <button
            onClick={copy}
            style={{ position: 'absolute', top: 12, right: 12, padding: '4px 10px', background: '#1e293b', color: '#94a3b8', border: '1px solid #334155', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>

      {/* How it works */}
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 24 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: '#0f172a', marginBottom: 12 }}>How it works</h2>
        <ol style={{ paddingLeft: 20, color: '#374151', fontSize: 14, lineHeight: 1.8 }}>
          <li>Register your legacy API endpoint in the <strong>Endpoints</strong> tab.</li>
          <li>Copy your proxy URL and API key.</li>
          <li>Replace your legacy API URL with the proxy URL in your application.</li>
          <li>Add the <code>Authorization: Bearer YOUR_API_KEY</code> header to every request.</li>
          <li>QuantumBridge wraps your traffic with ECDSA P-256 + ML-DSA-65 dual signatures automatically.</li>
        </ol>
      </div>
    </div>
  );
}
