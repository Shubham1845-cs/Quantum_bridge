import { useState } from "react";
import { motion } from "framer-motion";
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listEndpoints, createEndpoint } from "../api/endpoints";

export default function EndpointsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [newTarget, setNewTarget] = useState("");
  const [newName, setNewName] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const { data: endpoints, isLoading } = useQuery({
    queryKey: ["endpoints", orgId],
    queryFn: () => listEndpoints(orgId!),
    enabled: !!orgId,
  });

  const createMut = useMutation({
    mutationFn: () => createEndpoint(orgId!, { name: newName, targetUrl: newTarget }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["endpoints", orgId] });
      setShowModal(false);
      setNewName("");
      setNewTarget("");
      setErrorMsg("");
    },
    onError: (err: any) => {
      setErrorMsg(err.message || "Failed to create endpoint");
    }
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    createMut.mutate();
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight mb-1">Endpoints</h2>
          <p className="text-white/40 text-sm">Registered legacy APIs proxied through QuantumBridge</p>
        </div>
        <button 
          onClick={() => setShowModal(true)}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-lg text-sm font-medium hover:bg-cyber-cyan/20 transition-colors"
        >
          + New endpoint
        </button>
      </div>

      {isLoading ? (
        <div className="text-white/40">Loading endpoints...</div>
      ) : !endpoints || endpoints.length === 0 ? (
        <div className="p-8 text-center rounded-2xl bg-white/[0.02] border border-white/[0.06] text-white/40">
          No endpoints registered yet. Click "New endpoint" to get started.
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {endpoints.map(ep => (
            <div key={ep._id} className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <div className="font-bold text-lg mb-1">{ep.name}</div>
                  <div className="text-white/40 text-xs font-mono">proxy.quantumbridge.io/{ep.proxySlug}</div>
                </div>
                <div className="flex items-center gap-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] border ${ep.isActive ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>
                    {ep.isActive ? "Active" : "Inactive"}
                  </span>
                  <span className="text-white/40 text-xs">{ep.requestCount} req today</span>
                  <Link to={`/org/${orgId}/endpoints/${ep._id}`} className="px-3 py-1.5 border border-white/10 rounded-md text-xs text-white/60 hover:text-white hover:bg-white/5 transition-colors">
                    Details →
                  </Link>
                </div>
              </div>
              <div className="flex gap-6 text-xs text-white/50">
                <span>Target: <span className="text-white/80">{ep.targetUrl}</span></span>
                <span>IP restriction: <span className="text-white/80">{ep.ipAllowlist?.length ? `${ep.ipAllowlist.length} IPs` : "None"}</span></span>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111111] border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-xl font-bold mb-4">Register new endpoint</h3>
            {errorMsg && <div className="mb-4 text-red-400 text-sm bg-red-400/10 p-2 rounded">{errorMsg}</div>}
            <form onSubmit={handleCreate}>
              <div className="mb-4">
                <label className="block text-white/60 text-xs mb-1">Name / Identifier</label>
                <input 
                  type="text" 
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded p-2 text-sm text-white placeholder-white/20 focus:border-cyber-cyan focus:outline-none" 
                  placeholder="e.g. core-api-v2"
                />
              </div>
              <div className="mb-6">
                <label className="block text-white/60 text-xs mb-1">Target URL</label>
                <input 
                  type="url" 
                  required
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded p-2 text-sm text-white placeholder-white/20 focus:border-cyber-cyan focus:outline-none" 
                  placeholder="https://internal.yourdomain.com/api"
                />
              </div>
              <div className="flex justify-end gap-3">
                <button 
                  type="button" 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-sm text-white/60 hover:text-white"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={createMut.isPending}
                  className="px-4 py-2 bg-cyber-cyan text-black rounded text-sm font-medium hover:bg-cyber-cyan/80 disabled:opacity-50"
                >
                  {createMut.isPending ? "Creating..." : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </motion.div>
  );
}

