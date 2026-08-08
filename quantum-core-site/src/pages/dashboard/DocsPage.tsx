import { useState } from 'react';
import { motion } from 'framer-motion';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Copy, CheckCheck, AlertTriangle, KeyRound, FileCode2, ExternalLink } from 'lucide-react';
import { listEndpoints } from '../../api/endpoints';
import { getOrg } from '../../api/orgs';
import { useToast } from '../../hooks/useToast';
import { useAuth } from '../../context/AuthContext';
import { copyToClipboard } from '../../lib/utils';
import { PageHeader } from '../../components/ui/PageHeader';
import { Card } from '../../components/ui/Card';
import { cn } from '../../lib/utils';

type Language = 'nodejs' | 'python' | 'curl';

function CodeBlock({ code, onCopy, copied }: { code: string; onCopy: () => void; copied: boolean }) {
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-xl border border-white/10 bg-black/50 p-4 font-mono-qb text-xs leading-relaxed text-white/80">
        {code}
      </pre>
      <button
        onClick={onCopy}
        className="absolute right-3 top-3 rounded-lg border border-white/10 bg-white/5 p-2 text-white/55 transition-colors hover:bg-white/10 hover:text-white"
        aria-label="Copy code"
      >
        {copied ? <CheckCheck size={14} className="text-qb-emerald" /> : <Copy size={14} />}
      </button>
    </div>
  );
}

export default function DocsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const toast = useToast();
  const { loading: authLoading } = useAuth();
  const [selectedLang, setSelectedLang] = useState<Language>('nodejs');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const { data: org } = useQuery({
    queryKey: ['org', orgId],
    queryFn: () => getOrg(orgId!),
    enabled: !!orgId && !authLoading,
  });

  const { data: endpoints } = useQuery({
    queryKey: ['endpoints', orgId],
    queryFn: () => listEndpoints(orgId!),
    enabled: !!orgId && !authLoading,
  });

  const firstEndpoint = endpoints?.[0];
  const proxyUrl = firstEndpoint
    ? `https://proxy.quantumbridge.io/${org?.slug}/${firstEndpoint.proxySlug}`
    : 'https://proxy.quantumbridge.io/your-org/your-endpoint';
  const apiKeyNote = firstEndpoint
    ? '__YOUR_API_KEY__  ← Generate via endpoint "Regenerate API key"'
    : '__YOUR_API_KEY__  ← Create an endpoint first to get your API key';

  const handleCopy = async (code: string, key: string) => {
    const success = await copyToClipboard(code);
    if (success) {
      setCopiedKey(key);
      toast.success('Code copied to clipboard');
      setTimeout(() => setCopiedKey(null), 1800);
    }
  };

  const codeExamples = {
    nodejs: {
      makeRequest: `const axios = require('axios');

const proxyUrl = '${proxyUrl}';
const apiKey = '${apiKeyNote}';

async function makeRequest() {
  try {
    const response = await axios.get(proxyUrl + '/your-path', {
      headers: {
        'Authorization': \`Bearer $\{apiKey}\`,
        'Content-Type': 'application/json'
      }
    });

    console.log('Response:', response.data);
    console.log('ECDSA Signature:', response.headers['x-qb-ecdsa-sig']);
    console.log('ML-DSA Signature:', response.headers['x-qb-dilithium-sig']);
    console.log('Key Version:', response.headers['x-qb-key-version']);

    return response.data;
  } catch (error) {
    console.error('Request failed:', error.message);
    throw error;
  }
}

makeRequest();`,
      verifySignatures: `const crypto = require('crypto');

function verifyECDSA(data, signature, publicKey) {
  const verify = crypto.createVerify('SHA256');
  verify.update(data);
  verify.end();

  return verify.verify(
    {
      key: publicKey,
      format: 'pem',
      type: 'spki'
    },
    signature,
    'base64'
  );
}

// Get public keys from /org/:orgId/keys endpoint
const ecdsaPublicKey = '-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----';
const signature = response.headers['x-qb-ecdsa-sig'];
const responseBody = JSON.stringify(response.data);

const isValid = verifyECDSA(responseBody, signature, ecdsaPublicKey);
console.log('ECDSA signature valid:', isValid);`,
    },
    python: {
      makeRequest: `import requests

proxy_url = '${proxyUrl}'
api_key = '${apiKeyNote}'

def make_request():
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(
            f'{proxy_url}/your-path',
            headers=headers
        )
        response.raise_for_status()

        print('Response:', response.json())
        print('ECDSA Signature:', response.headers.get('x-qb-ecdsa-sig'))
        print('ML-DSA Signature:', response.headers.get('x-qb-dilithium-sig'))
        print('Key Version:', response.headers.get('x-qb-key-version'))

        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Request failed: {e}')
        raise

make_request()`,
      verifySignatures: `from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import base64
import json

def verify_ecdsa(data: bytes, signature: str, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )
        sig_bytes = base64.b64decode(signature)
        public_key.verify(
            sig_bytes,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

ecdsa_public_key = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

signature = response.headers.get('x-qb-ecdsa-sig')
response_body = json.dumps(response.json()).encode()

is_valid = verify_ecdsa(response_body, signature, ecdsa_public_key)
print(f'ECDSA signature valid: {is_valid}')`,
    },
    curl: {
      makeRequest: `curl -X GET '${proxyUrl}/your-path' \\
  -H 'Authorization: Bearer ${apiKeyNote}' \\
  -H 'Content-Type: application/json' \\
  -i

# Response headers will include:
# x-qb-ecdsa-sig: <base64-encoded-signature>
# x-qb-dilithium-sig: <base64-encoded-signature>
# x-qb-key-version: <version-number>
# qb-encrypted: 1 (response is AES-256-GCM encrypted)`,
      verifySignatures: `# Get public keys
curl -X GET 'https://api.quantumbridge.io/orgs/:orgId/keys' \\
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'

# Save response body to file
curl -X GET '${proxyUrl}/your-path' \\
  -H 'Authorization: Bearer ${apiKeyNote}' \\
  -D headers.txt \\
  -o response.json

# Verify using OpenSSL (requires public key in PEM format)
SIGNATURE=$(grep -i 'x-qb-ecdsa-sig' headers.txt | cut -d' ' -f2)
echo -n "$(cat response.json)" | \\
  openssl dgst -sha256 -verify public_key.pem \\
  -signature <(echo "$SIGNATURE" | base64 -d)`,
    },
  };

  const langTab: Record<Language, string> = { nodejs: 'Node.js', python: 'Python', curl: 'cURL' };

  return (
    <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
      <PageHeader title="Documentation" description="Integration guides and code examples for QuantumBridge" />

      {/* Security warning */}
      <div className="mb-8 flex items-start gap-3 rounded-xl border border-qb-amber/20 bg-qb-amber/5 p-4">
        <AlertTriangle className="mt-0.5 shrink-0 text-qb-amber" size={18} />
        <div>
          <h3 className="mb-1 text-sm font-medium text-qb-amber">Security Warning</h3>
          <p className="text-xs text-qb-amber/80">
            Never commit your API keys to version control. Use environment variables or secure secret management systems.
          </p>
        </div>
      </div>

      {/* Language tabs */}
      <div className="mb-6 flex gap-2">
        {(['nodejs', 'python', 'curl'] as Language[]).map((lang) => (
          <button
            key={lang}
            onClick={() => setSelectedLang(lang)}
            className={cn(
              'flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
              selectedLang === lang
                ? 'border border-qb-cyan/30 bg-qb-cyan/10 text-qb-cyan'
                : 'border border-white/10 bg-white/[0.02] text-white/55 hover:bg-white/[0.05] hover:text-white',
            )}
          >
            <FileCode2 size={14} />
            {langTab[lang]}
          </button>
        ))}
      </div>

      {/* Making Requests */}
      <div className="mb-8">
        <h3 className="mb-4 text-lg font-bold">Making Requests</h3>
        <CodeBlock
          code={codeExamples[selectedLang].makeRequest}
          onCopy={() => handleCopy(codeExamples[selectedLang].makeRequest, 'make')}
          copied={copiedKey === 'make'}
        />
      </div>

      {/* Verifying Signatures */}
      <div className="mb-8">
        <h3 className="mb-2 text-lg font-bold">Verifying Signatures</h3>
        <p className="mb-4 text-sm text-white/40">
          All responses include dual signatures (ECDSA P-256 and ML-DSA-65) in the response headers.
          Verify them to ensure response integrity.
        </p>
        <CodeBlock
          code={codeExamples[selectedLang].verifySignatures}
          onCopy={() => handleCopy(codeExamples[selectedLang].verifySignatures, 'verify')}
          copied={copiedKey === 'verify'}
        />
      </div>

      {/* Reference */}
      <Card className="mb-8 p-6">
        <h3 className="mb-4 text-lg font-bold">Key Information</h3>
        <div className="space-y-4 text-sm">
          <div>
            <h4 className="mb-2 text-white/60">Proxy URL</h4>
            <code className="block rounded-lg border border-white/10 bg-black/40 p-3 font-mono-qb text-xs text-qb-cyan">{proxyUrl}</code>
          </div>
          <div>
            <h4 className="mb-2 text-white/60">Auth Header</h4>
            <code className="block rounded-lg border border-white/10 bg-black/40 p-3 font-mono-qb text-xs text-white/80">
              Authorization: Bearer {apiKeyNote}
            </code>
          </div>
          <div>
            <h4 className="mb-2 text-white/60">Response Headers</h4>
            <ul className="space-y-1.5 text-xs text-white/55">
              <li>• <code className="text-qb-cyan">QB-Encrypted</code> — "1" when response is AES-256-GCM encrypted</li>
              <li>• <code className="text-qb-cyan">X-QB-ECDSA-Sig</code> — ECDSA P-256 signature (base64)</li>
              <li>• <code className="text-qb-cyan">X-QB-Dilithium-Sig</code> — ML-DSA-65 signature (base64)</li>
              <li>• <code className="text-qb-cyan">X-QB-Key-Version</code> — Key version used for signing</li>
              <li>• <code className="text-qb-cyan">X-QB-IV</code> — AES-256-GCM IV (base64, when encrypted)</li>
            </ul>
          </div>
        </div>
      </Card>

      {/* Resources */}
      <Card className="p-6">
        <h3 className="mb-4 text-lg font-bold">Additional Resources</h3>
        <div className="space-y-3 text-sm">
          <a
            href="https://github.com/quantumbridge/examples"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-qb-cyan transition-colors hover:text-qb-cyan/80"
          >
            <ExternalLink size={16} />
            View example projects on GitHub
          </a>
          <Link to={`/org/${orgId}/keys`} className="flex items-center gap-2 text-qb-cyan transition-colors hover:text-qb-cyan/80">
            <KeyRound size={16} />
            View your organization's public keys
          </Link>
        </div>
      </Card>
    </motion.div>
  );
}
