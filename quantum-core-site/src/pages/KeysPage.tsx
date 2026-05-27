import { motion } from "framer-motion";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getKeys, rotateKeys } from "../api/keys";

export default function KeysPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();

  const { data: keys, isLoading, error } = useQuery({
    queryKey: ["keys", orgId],
    queryFn: () => getKeys(orgId!),
    enabled: !!orgId,
  });

  const rotateMut = useMutation({
    mutationFn: () => rotateKeys(orgId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keys", orgId] });
      alert("Keys rotated successfully.");
    },
    onError: (err: any) => {
      alert(`Failed to rotate keys: ${err.message}`);
    }
  });

  if (isLoading) return <div className="text-white/40">Loading keys...</div>;
  
  if (error) {
    return (
      <div className="p-6 rounded-2xl bg-red-500/5 border border-red-500/20 text-center">
        <p className="text-red-400 text-sm mb-2">Failed to load keys</p>
        <p className="text-white/40 text-xs">
          Make sure the backend server is running and accessible
        </p>
      </div>
    );
  }

  // Ensure keys is an array, handle API errors gracefully
  const keysArray = Array.isArray(keys) ? keys : [];
  const activeKey = keysArray.find(k => k.isActive);
  const graceKeys = keysArray.filter(k => !k.isActive);

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight mb-1">Cryptographic keys</h2>
        <p className="text-white/40 text-sm">PQC keypairs for your organization. Rotated every 90 days.</p>
      </div>

      {keysArray.length === 0 ? (
        <div className="p-8 text-center rounded-2xl bg-white/[0.02] border border-white/[0.06] text-white/40">
          <div className="text-4xl mb-4">🔐</div>
          <p className="text-white/40 text-sm mb-4">No cryptographic keys found</p>
          <p className="text-white/20 text-xs">Keys will be automatically generated when you create your first endpoint</p>
        </div>
      ) : (
        <>
          {activeKey && (
        <div className="p-6 rounded-2xl bg-white/[0.02] border-l-2 border-green-500 border-t border-r border-b border-t-white/[0.06] border-r-white/[0.06] border-b-white/[0.06] mb-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-6">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <span className="font-bold text-lg">Version {activeKey.version}</span>
                <span className="px-2 py-0.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded text-[10px] uppercase tracking-wider font-bold">Active</span>
              </div>
              <div className="text-white/40 text-xs">Generated {new Date(activeKey.createdAt).toLocaleDateString()} — expires {new Date(activeKey.expiresAt).toLocaleDateString()}</div>
            </div>
            <button 
              onClick={() => {
                if (confirm("Rotate keys now? The old keys will remain in grace period for 24h.")) {
                  rotateMut.mutate();
                }
              }}
              disabled={rotateMut.isPending}
              className="px-3 py-1.5 border border-white/10 rounded-lg text-xs text-white/60 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-50"
            >
              {rotateMut.isPending ? "Rotating..." : "Rotate now"}
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <div className="text-white/40 text-xs mb-2">ECDSA P-256 public key</div>
              <div className="p-4 bg-black/40 border border-white/5 rounded-lg font-mono text-xs text-white/60 whitespace-pre-wrap break-all">
                {activeKey.ecdsaPublicKey}
              </div>
            </div>
            <div>
              <div className="text-white/40 text-xs mb-2">ML-DSA-65 public key</div>
              <div className="p-4 bg-black/40 border border-white/5 rounded-lg font-mono text-xs text-white/60 whitespace-pre-wrap break-all">
                {activeKey.dilithiumPublicKey}
              </div>
            </div>
          </div>
        </div>
      )}

      {graceKeys.map(gk => (
        <div key={gk.version} className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] opacity-60 mb-4">
          <div className="flex items-center gap-3 mb-1">
            <span className="font-bold text-lg text-white/60">Version {gk.version}</span>
            <span className="px-2 py-0.5 bg-white/5 text-white/40 border border-white/10 rounded text-[10px] uppercase tracking-wider font-bold">Grace period</span>
          </div>
          <div className="text-white/30 text-xs">
            Retired {new Date(gk.expiresAt).toLocaleDateString()} — 
            grace expires {gk.graceExpiresAt ? new Date(gk.graceExpiresAt).toLocaleDateString() : "unknown"}
          </div>
        </div>
      ))}

      <div className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06] mt-8">
        <div className="font-bold text-sm mb-2">Auto-rotation schedule</div>
        <div className="text-white/40 text-sm leading-relaxed">
          {activeKey 
            ? `Next automatic rotation: ${new Date(activeKey.expiresAt).toLocaleDateString()}. `
            : "Automatic rotation is scheduled. "}
          Previous keypair is retained for 24 hours after rotation to verify in-flight requests. Private keys are never exposed — all signing happens server-side.
        </div>
      </div>
        </>
      )}
    </motion.div>
  );
}
