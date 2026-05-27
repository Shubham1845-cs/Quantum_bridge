import { useState } from 'react';
import { motion } from 'framer-motion';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { listEndpoints } from '../../api/endpoints';
import { getOrg } from '../../api/orgs';
import { useToast } from '../../hooks/useToast';
import { copyToClipboard } from '../../lib/utils';

type Language = 'nodejs' | 'python' | 'curl';

export default function DocsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const toast = useToast();
  const [selectedLang, setSelectedLang] = useState<Language>('nodejs');

  const { data: org } = useQuery({
    queryKey: ['org', orgId],
    queryFn: () => getOrg(orgId!),
    enabled: !!orgId,
  });

  const { data: endpoints } = useQuery({
    queryKey: ['endpoints', orgId],
    queryFn: () => listEndpoints(orgId!),
    enabled: !!orgId,
  });

  const firstEndpoint = endpoints?.[0];
  const proxyUrl = firstEndpoint
    ? `https://proxy.quantumbridge.io/${org?.slug}/${firstEndpoint.proxySlug}`
    : 'https://proxy.quantumbridge.io/your-org/your-endpoint';
  const apiKey = 'your-api-key-here';

  const handleCopy = async (code: string) => {
    const success = await copyToClipboard(code);
    if (success) {
      toast.success('Code copied to clipboard');
    }
  };

  const codeExamples = {
    nodejs: {
      makeRequest: `const axios = require('axios');

const proxyUrl = '${proxyUrl}';
const apiKey = '${apiKey}';

async function makeRequest() {
  try {
    const response = await axios.get(proxyUrl + '/your-path', {
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json'
      }
    });

    console.log('Response:', response.data);
    console.log('ECDSA Signature:', response.headers['x-ecdsa-signature']);
    console.log('ML-DSA Signature:', response.headers['x-dilithium-signature']);
    
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
const signature = response.headers['x-ecdsa-signature'];
const responseBody = JSON.stringify(response.data);

const isValid = verifyECDSA(responseBody, signature, ecdsaPublicKey);
console.log('ECDSA signature valid:', isValid);`,
    },
    python: {
      makeRequest: `import requests

proxy_url = '${proxyUrl}'
api_key = '${apiKey}'

def make_request():
    headers = {
        'X-API-Key': api_key,
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(
            f'{proxy_url}/your-path',
            headers=headers
        )
        response.raise_for_status()
        
        print('Response:', response.json())
        print('ECDSA Signature:', response.headers.get('x-ecdsa-signature'))
        print('ML-DSA Signature:', response.headers.get('x-dilithium-signature'))
        
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
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )
        
        # Decode signature from base64
        sig_bytes = base64.b64decode(signature)
        
        # Verify signature
        public_key.verify(
            sig_bytes,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# Get public keys from /org/:orgId/keys endpoint
ecdsa_public_key = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

signature = response.headers.get('x-ecdsa-signature')
response_body = json.dumps(response.json()).encode()

is_valid = verify_ecdsa(response_body, signature, ecdsa_public_key)
print(f'ECDSA signature valid: {is_valid}')`,
    },
    curl: {
      makeRequest: `curl -X GET '${proxyUrl}/your-path' \\
  -H 'X-API-Key: ${apiKey}' \\
  -H 'Content-Type: application/json' \\
  -i

# Response headers will include:
# x-ecdsa-signature: <base64-encoded-signature>
# x-dilithium-signature: <base64-encoded-signature>
# x-key-version: <version-number>`,
      verifySignatures: `# Get public keys
curl -X GET 'https://api.quantumbridge.io/orgs/:orgId/keys' \\
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'

# Save response body to file
curl -X GET '${proxyUrl}/your-path' \\
  -H 'X-API-Key: ${apiKey}' \\
  -D headers.txt \\
  -o response.json

# Extract signature from headers
SIGNATURE=$(grep -i 'x-ecdsa-signature' headers.txt | cut -d' ' -f2)

# Verify using OpenSSL (requires public key in PEM format)
echo -n "$(cat response.json)" | \\
  openssl dgst -sha256 -verify public_key.pem \\
  -signature <(echo "$SIGNATURE" | base64 -d)`,
    },
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight mb-1">Documentation</h2>
        <p className="text-white/40 text-sm">
          Integration guides and code examples for QuantumBridge
        </p>
      </div>

      {/* Warning */}
      <div className="mb-8 p-4 rounded-xl bg-yellow-500/5 border border-yellow-500/20">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <h3 className="text-yellow-400 font-medium text-sm mb-1">
              Security Warning
            </h3>
            <p className="text-yellow-400/80 text-xs">
              Never commit your API keys to version control. Use environment variables or secure secret management systems.
            </p>
          </div>
        </div>
      </div>

      {/* Language Selector */}
      <div className="flex gap-2 mb-6">
        {(['nodejs', 'python', 'curl'] as Language[]).map((lang) => (
          <button
            key={lang}
            onClick={() => setSelectedLang(lang)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              selectedLang === lang
                ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30'
                : 'bg-white/[0.02] text-white/60 border border-white/10 hover:bg-white/[0.04]'
            }`}
          >
            {lang === 'nodejs' ? 'Node.js' : lang === 'python' ? 'Python' : 'cURL'}
          </button>
        ))}
      </div>

      {/* Making Requests */}
      <div className="mb-8">
        <h3 className="text-lg font-bold mb-4">Making Requests</h3>
        <div className="relative">
          <pre className="p-4 rounded-xl bg-black/40 border border-white/10 overflow-x-auto text-xs text-white/80 font-mono">
            {codeExamples[selectedLang].makeRequest}
          </pre>
          <button
            onClick={() => handleCopy(codeExamples[selectedLang].makeRequest)}
            className="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white/60 hover:text-white text-xs transition-colors"
          >
            Copy
          </button>
        </div>
      </div>

      {/* Verifying Signatures */}
      <div className="mb-8">
        <h3 className="text-lg font-bold mb-4">Verifying Signatures</h3>
        <p className="text-white/40 text-sm mb-4">
          All responses include dual signatures (ECDSA P-256 and ML-DSA-65) in the response headers.
          Verify these signatures to ensure response integrity.
        </p>
        <div className="relative">
          <pre className="p-4 rounded-xl bg-black/40 border border-white/10 overflow-x-auto text-xs text-white/80 font-mono">
            {codeExamples[selectedLang].verifySignatures}
          </pre>
          <button
            onClick={() => handleCopy(codeExamples[selectedLang].verifySignatures)}
            className="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white/60 hover:text-white text-xs transition-colors"
          >
            Copy
          </button>
        </div>
      </div>

      {/* Key Information */}
      <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
        <h3 className="text-lg font-bold mb-4">Key Information</h3>
        <div className="space-y-4 text-sm">
          <div>
            <h4 className="text-white/60 mb-2">Proxy URL</h4>
            <code className="block p-3 rounded-lg bg-black/40 border border-white/10 text-cyber-cyan font-mono text-xs">
              {proxyUrl}
            </code>
          </div>
          <div>
            <h4 className="text-white/60 mb-2">API Key Header</h4>
            <code className="block p-3 rounded-lg bg-black/40 border border-white/10 text-white/80 font-mono text-xs">
              X-API-Key: {apiKey}
            </code>
          </div>
          <div>
            <h4 className="text-white/60 mb-2">Response Headers</h4>
            <ul className="space-y-2 text-white/60 text-xs">
              <li>• <code className="text-cyber-cyan">x-ecdsa-signature</code> - ECDSA P-256 signature (base64)</li>
              <li>• <code className="text-cyber-cyan">x-dilithium-signature</code> - ML-DSA-65 signature (base64)</li>
              <li>• <code className="text-cyber-cyan">x-key-version</code> - Key version used for signing</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Additional Resources */}
      <div className="mt-8 p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
        <h3 className="text-lg font-bold mb-4">Additional Resources</h3>
        <div className="space-y-3 text-sm">
          <a
            href="https://github.com/quantumbridge/examples"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-cyber-cyan hover:text-cyber-cyan/80 transition-colors"
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            View example projects on GitHub
          </a>
          <a
            href="/org/${orgId}/keys"
            className="flex items-center gap-2 text-cyber-cyan hover:text-cyber-cyan/80 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
            View your organization's public keys
          </a>
        </div>
      </div>
    </motion.div>
  );
}
