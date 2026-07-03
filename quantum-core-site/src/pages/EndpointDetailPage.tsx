import { useState } from "react";
import { motion } from "framer-motion";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getEndpoint, regenerateApiKey, deleteEndpoint } from "../api/endpoints";
import { useToast } from "../hooks/useToast";
import { copyToClipboard } from "../lib/utils";

export default function EndpointDetailPage() {
  const { orgId, endpointId } = useParams<{ orgId: string; endpointId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [apiKey, setApiKey] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [testMethod, setTestMethod] = useState("GET");
  const [testPath, setTestPath] = useState("");
  const [testBody, setTestBody] = useState("");
  const [testResult, setTestResult] = useState<{ status: number; latency: number; data: any; ecdsaSig: string | null; dilithiumSig: string | null; keyVersion: number | null; encrypted: boolean } | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: endpoint, isLoading } = useQuery({
    queryKey: ["endpoints", orgId, endpointId],
    queryFn: () => getEndpoint(orgId!, endpointId!),
    enabled: !!orgId && !!endpointId,
  });

  const regenMut = useMutation({
    mutationFn: () => regenerateApiKey(orgId!, endpointId!),
    onSuccess: (data) => {
      setApiKey(data.apiKey);
      setShowKey(true);
      toast.success('New API key generated — save it now, you won\'t see it again.');
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to regenerate API key');
    }
  });

  const handleCopyKey = async () => {
    if (!apiKey) return;
    const ok = await copyToClipboard(apiKey);
    if (ok) toast.success('API key copied to clipboard');
  };

  const delMut = useMutation({
    mutationFn: () => deleteEndpoint(orgId!, endpointId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["endpoints", orgId] });
      navigate(`/org/${orgId}/endpoints`);
    }
  });

  const handleTestProxy = async () => {
    if (!endpoint) return;
    if (!apiKey) {
      toast.error('API key required — regenerate your key first');
      return;
    }
    setTestError(null);
    setTestResult(null);
    setIsTesting(true);
    try {
      const proxyUrl = `https://proxy.quantumbridge.io/${endpoint.proxySlug}${testPath.startsWith('/') ? testPath : '/' + testPath}`;
      const startTime = performance.now();

      const headers: Record<string, string> = {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      };

      const fetchOptions: RequestInit = {
        method: testMethod,
        headers,
      };

      if (testMethod !== 'GET' && testMethod !== 'HEAD' && testBody) {
        fetchOptions.body = testBody;
      }

      const response = await fetch(proxyUrl, fetchOptions);
      const endTime = performance.now();

      const ecdsaSig = response.headers.get('x-qb-ecdsa-sig');
      const dilithiumSig = response.headers.get('x-qb-dilithium-sig');
      const keyVersion = response.headers.get('x-qb-key-version');
      const encrypted = response.headers.get('qb-encrypted') === '1';

      let data: any;
      const contentType = response.headers.get('content-type');
      if (encrypted && contentType === 'application/octet-stream') {
        data = await response.text();
        // Truncate encrypted base64 for display
        if (data.length > 200) data = data.substring(0, 200) + '...';
      } else if (contentType?.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      setTestResult({
        status: response.status,
        latency: Math.round(endTime - startTime),
        data,
        ecdsaSig,
        dilithiumSig,
        keyVersion: keyVersion ? parseInt(keyVersion, 10) : null,
        encrypted,
      });
    } catch (e: any) {
      setTestError(e.message || 'Request failed — check that the proxy server is running');
    } finally {
      setIsTesting(false);
    }
  };

  if (isLoading) return <div className="text-white/40">Loading endpoint details...</div>;
  if (!endpoint) return <div className="text-white/40">Endpoint not found</div>;

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight mb-1">{endpoint.name}</h2>
          <p className="text-white/40 text-sm font-mono">proxy.quantumbridge.io/{endpoint.proxySlug}</p>
        </div>
        <span className={`px-3 py-1 border rounded-lg text-xs font-medium ${endpoint.isActive ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>
          {endpoint.isActive ? "Active" : "Inactive"}
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <h3 className="text-base font-bold mb-4">API tester</h3>
          
          <div className="mb-4">
            <label className="block text-xs text-white/50 mb-1.5">Method + path</label>
            <div className="flex gap-2">
              <select 
                value={testMethod}
                onChange={(e) => setTestMethod(e.target.value)}
                className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white outline-none w-24 focus:border-cyber-cyan/50"
              >
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>DELETE</option>
              </select>
              <input 
                type="text" 
                placeholder="/api/v1/test" 
                value={testPath}
                onChange={(e) => setTestPath(e.target.value)}
                className="flex-1 bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white outline-none focus:border-cyber-cyan/50" 
              />
            </div>
          </div>
          
          <div className="mb-4">
            <label className="block text-xs text-white/50 mb-1.5">Request body (optional)</label>
            <input 
              type="text" 
              placeholder='{"id": 42}' 
              value={testBody}
              onChange={(e) => setTestBody(e.target.value)}
              className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white outline-none focus:border-cyber-cyan/50" 
            />
          </div>

          {!apiKey && (
            <div className="mb-4 p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20 text-yellow-400/80 text-xs">
              API key required to test. Use "Regenerate API key" below to get one.
            </div>
          )}

          <button
            onClick={handleTestProxy}
            disabled={isTesting || !apiKey}
            className="w-full py-2 bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-lg text-sm font-medium hover:bg-cyber-cyan/20 transition-colors mb-4 disabled:opacity-50"
          >
            {isTesting ? "Testing..." : "Send through proxy"}
          </button>

          {testError && (
            <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg text-red-400 text-xs mb-3">
              {testError}
            </div>
          )}

          {testResult && (
            <div className="p-3 bg-black/40 border border-white/5 rounded-lg font-mono text-xs text-white/50 whitespace-pre-wrap">
              <div className={testResult.status < 400 ? 'text-green-400 mb-1' : 'text-red-400 mb-1'}>
                {testResult.status} — {testResult.latency}ms
              </div>
              {testResult.ecdsaSig && (
                <div>X-QB-ECDSA-Sig: {testResult.ecdsaSig.substring(0, 40)}...</div>
              )}
              {testResult.dilithiumSig && (
                <div>X-QB-Dilithium-Sig: {testResult.dilithiumSig.substring(0, 40)}...</div>
              )}
              {testResult.keyVersion != null && (
                <div>X-QB-Key-Version: {testResult.keyVersion}</div>
              )}
              {testResult.encrypted && (
                <div className="text-cyber-cyan">QB-Encrypted: true (response encrypted with AES-256-GCM)</div>
              )}
              <div className="mt-2 text-white/70">{typeof testResult.data === 'string' ? testResult.data : JSON.stringify(testResult.data, null, 2)}</div>
            </div>
          )}
        </div>

        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <h3 className="text-base font-bold mb-4">Settings</h3>
          
          <div className="flex justify-between py-3 border-b border-white/[0.06]">
            <span className="text-white/40 text-sm">Target URL</span>
            <span className="text-sm">{endpoint.targetUrl}</span>
          </div>
          <div className="flex justify-between py-3 border-b border-white/[0.06]">
            <span className="text-white/40 text-sm">Requests</span>
            <span className="text-sm text-white/80">{endpoint.requestCount}</span>
          </div>
          <div className="flex justify-between py-3 mb-4">
            <span className="text-white/40 text-sm">Created At</span>
            <span className="text-sm text-white/80">{new Date(endpoint.createdAt).toLocaleDateString()}</span>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => regenMut.mutate()}
              disabled={regenMut.isPending}
              className="px-3 py-1.5 border border-white/10 rounded-lg text-xs text-white/60 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-50"
            >
              {regenMut.isPending ? "..." : "Regenerate API key"}
            </button>

            {apiKey && showKey && (
              <div className="mt-4 p-3 rounded-lg bg-cyber-cyan/5 border border-cyber-cyan/20">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-cyber-cyan text-xs font-medium">API Key</span>
                  <div className="flex gap-2">
                    <button
                      onClick={handleCopyKey}
                      className="px-2 py-1 rounded bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-[10px] hover:bg-cyber-cyan/20 transition-colors"
                    >
                      Copy
                    </button>
                    <button
                      onClick={() => { setShowKey(false); setApiKey(null); }}
                      className="px-2 py-1 rounded bg-white/5 border border-white/10 text-white/40 text-[10px] hover:text-white/60 transition-colors"
                    >
                      Hide
                    </button>
                  </div>
                </div>
                <code className="block text-[10px] text-white/80 font-mono break-all select-all">
                  {apiKey}
                </code>
                <p className="mt-1 text-white/30 text-[9px]">
                  This key is shown once. Copy it now — it cannot be retrieved later.
                </p>
              </div>
            )}
            <button 
              onClick={() => {
                if (confirm("Are you sure you want to delete this endpoint?")) {
                  delMut.mutate();
                }
              }}
              disabled={delMut.isPending}
              className="px-3 py-1.5 border border-red-500/20 text-red-400 rounded-lg text-xs hover:bg-red-500/10 transition-colors disabled:opacity-50"
            >
              {delMut.isPending ? "..." : "Delete endpoint"}
            </button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

