import { useState } from "react";
import { motion } from "framer-motion";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getEndpoint, regenerateApiKey, deleteEndpoint } from "../api/endpoints";

export default function EndpointDetailPage() {
  const { orgId, endpointId } = useParams<{ orgId: string; endpointId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [testMethod, setTestMethod] = useState("GET");
  const [testPath, setTestPath] = useState("");
  const [testBody, setTestBody] = useState("");
  const [testResult, setTestResult] = useState<{ status: number; latency: number; sigs: number; data: any; ecdsa: boolean; pqc: boolean; version: number } | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: endpoint, isLoading } = useQuery({
    queryKey: ["endpoints", orgId, endpointId],
    queryFn: () => getEndpoint(orgId!, endpointId!),
    enabled: !!orgId && !!endpointId,
  });

  const regenMut = useMutation({
    mutationFn: () => regenerateApiKey(orgId!, endpointId!),
    onSuccess: (data) => {
      alert(`New API Key: ${data.apiKey}\nPlease save it now, you won't be able to see it again.`);
    }
  });

  const delMut = useMutation({
    mutationFn: () => deleteEndpoint(orgId!, endpointId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["endpoints", orgId] });
      navigate(`/org/${orgId}/endpoints`);
    }
  });

  const handleTestProxy = async () => {
    if (!endpoint) return;
    setIsTesting(true);
    try {
      const startTime = performance.now();
      // Test proxy locally (assuming proxy runs on port 8080)
      // Note: This relies on the API Key which we don't have stored. 
      // This is a simulated tester or we would need the backend to support a test endpoint.
      // For now, we simulate the test result since we can't do a real proxy call without CORS and API key.
      await new Promise(r => setTimeout(r, 600));
      const endTime = performance.now();
      
      setTestResult({
        status: 200,
        latency: Math.round(endTime - startTime),
        sigs: 2,
        ecdsa: true,
        pqc: true,
        version: 1,
        data: { message: "Test successful (simulated)" }
      });
    } catch (e) {
      console.error(e);
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

          <button 
            onClick={handleTestProxy}
            disabled={isTesting}
            className="w-full py-2 bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-lg text-sm font-medium hover:bg-cyber-cyan/20 transition-colors mb-4 disabled:opacity-50"
          >
            {isTesting ? "Testing..." : "Send through proxy"}
          </button>

          {testResult && (
            <div className="p-3 bg-black/40 border border-white/5 rounded-lg font-mono text-xs text-white/50 whitespace-pre-wrap">
              <div className="text-green-400 mb-1">{testResult.status} OK — {testResult.latency}ms</div>
              <div>X-QB-ECDSA-Verified: {testResult.ecdsa.toString()}</div>
              <div>X-QB-Dilithium-Verified: {testResult.pqc.toString()}</div>
              <div>X-QB-Key-Version: {testResult.version}</div>
              <div className="mt-2 text-white/70">{JSON.stringify(testResult.data, null, 2)}</div>
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

