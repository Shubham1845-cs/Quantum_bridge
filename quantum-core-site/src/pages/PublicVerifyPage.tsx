import { motion } from "framer-motion";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { verifyRequest } from "../api/verify";

export default function PublicVerifyPage() {
  const { requestId } = useParams<{ requestId: string }>();

  const { data, isLoading, error } = useQuery({
    queryKey: ['verify', requestId],
    queryFn: () => verifyRequest(requestId!),
    enabled: !!requestId,
  });

  const bothValid = data?.ecdsaVerified && data?.dilithiumVerified;
  const oneValid = (data?.ecdsaVerified && !data?.dilithiumVerified) || (!data?.ecdsaVerified && data?.dilithiumVerified);

  return (
    <div className="min-h-screen bg-black text-white relative">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[400px] rounded-full opacity-[0.04] blur-[150px] bg-gradient-to-br from-cyber-cyan to-neon-purple" />
      </div>

      <header className="relative z-10 px-6 py-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-1 group">
          <span className="text-2xl font-bold tracking-tighter text-white">
            Quantum<span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">Bridge</span>
          </span>
        </Link>
        <Link to="/login" className="px-4 py-1.5 text-sm font-medium text-white/60 hover:text-white transition-colors">
          Sign In
        </Link>
      </header>

      <main className="relative z-10 pt-20 pb-20 px-6">
        <motion.div 
          className="max-w-2xl mx-auto"
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          <div className="text-center mb-10">
            <h1 className="text-4xl font-bold tracking-tight mb-3">Request Verification</h1>
            <p className="text-white/40 text-lg">Independently verify post-quantum signatures for request {requestId}</p>
          </div>

          {isLoading && (
            <div className="p-8 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-md text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-cyber-cyan mx-auto mb-4" />
              <p className="text-white/60">Verifying request...</p>
            </div>
          )}

          {error && (
            <div className="p-8 rounded-2xl bg-red-500/10 border border-red-500/30 backdrop-blur-md">
              <p className="text-red-400">Request not found or verification is disabled for this organization.</p>
            </div>
          )}

          {data && (
            <>
              <div className={`p-8 rounded-2xl border backdrop-blur-md mb-8 ${
                bothValid ? 'bg-green-500/10 border-green-500/30' :
                oneValid ? 'bg-yellow-500/10 border-yellow-500/30' :
                'bg-red-500/10 border-red-500/30'
              }`}>
                <div className="text-center mb-6">
                  <div className={`text-6xl mb-4 ${
                    bothValid ? 'text-green-400' :
                    oneValid ? 'text-yellow-400' :
                    'text-red-400'
                  }`}>
                    {bothValid ? '✓' : oneValid ? '⚠' : '✗'}
                  </div>
                  <h2 className={`text-2xl font-bold ${
                    bothValid ? 'text-green-400' :
                    oneValid ? 'text-yellow-400' :
                    'text-red-400'
                  }`}>
                    {bothValid ? 'Both signatures valid' :
                     oneValid ? 'One signature failed' :
                     'Both signatures failed'}
                  </h2>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="p-4 rounded-xl bg-black/30">
                    <div className="text-white/60 text-sm mb-2">ECDSA P-256</div>
                    <div className={`text-lg font-bold ${data.ecdsaVerified ? 'text-green-400' : 'text-red-400'}`}>
                      {data.ecdsaVerified ? '✓ Verified' : '✗ Failed'}
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-black/30">
                    <div className="text-white/60 text-sm mb-2">ML-DSA-65</div>
                    <div className={`text-lg font-bold ${data.dilithiumVerified ? 'text-green-400' : 'text-red-400'}`}>
                      {data.dilithiumVerified ? '✓ Verified' : '✗ Failed'}
                    </div>
                  </div>
                </div>

                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-white/60">Organization:</span>
                    <span className="font-medium">{data.orgName}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white/60">Timestamp:</span>
                    <span className="font-medium">{new Date(data.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white/60">Key Version:</span>
                    <span className="font-medium">{data.publicKeys.version}</span>
                  </div>
                </div>
              </div>

              <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] mb-4">
                <h3 className="font-bold mb-4">Public Keys</h3>
                <div className="space-y-4">
                  <div>
                    <div className="text-white/60 text-sm mb-2">ECDSA P-256 Public Key</div>
                    <div className="p-3 rounded-lg bg-black/50 font-mono text-xs text-white/80 break-all">
                      {data.publicKeys.ecdsaPublicKey}
                    </div>
                  </div>
                  <div>
                    <div className="text-white/60 text-sm mb-2">ML-DSA-65 Public Key</div>
                    <div className="p-3 rounded-lg bg-black/50 font-mono text-xs text-white/80 break-all">
                      {data.publicKeys.dilithiumPublicKey}
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 text-sm">
                ⚠️ This endpoint is rate-limited to 30 requests per minute.
              </div>
            </>
          )}
        </motion.div>
      </main>
    </div>
  );
}
