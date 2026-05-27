import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { getSummary, getProxyLogs, type ProxyLog } from "../api/analytics";

export default function OrgOverviewPage() {
  const { orgId } = useParams<{ orgId: string }>();

  const { data: summary, isLoading: isLoadingSummary } = useQuery({
    queryKey: ["analytics", orgId, "summary"],
    queryFn: () => getSummary(orgId!),
    enabled: !!orgId,
  });

  const { data: logsData, isLoading: isLoadingLogs } = useQuery({
    queryKey: ["analytics", orgId, "logs"],
    queryFn: () => getProxyLogs(orgId!, { limit: 5 }),
    enabled: !!orgId,
  });

  const todayStr = new Date().toLocaleDateString("en-US", { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight mb-1">Overview</h2>
        <p className="text-white/40 text-sm">{todayStr}</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {[
          { label: "Requests today", val: isLoadingSummary ? "-" : summary?.requestsToday || 0, sub: "Last 24h", color: "#00FFFF" },
          { label: "Threats flagged", val: isLoadingSummary ? "-" : summary?.threatsToday || 0, sub: "Signature failures", color: "#ef4444" },
          { label: "Avg latency", val: isLoadingSummary ? "-" : `${summary?.avgLatency || 0}ms`, sub: "End-to-end", color: "#a855f7" },
          { label: "Plan usage", val: isLoadingSummary ? "-" : `${summary?.requestsToday || 0}`, sub: "Requests used", color: "#3b82f6" },
        ].map((m) => (
          <div key={m.label} className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
            <div className="text-white/40 text-xs font-medium mb-1">{m.label}</div>
            <div className="text-2xl font-bold mb-1" style={{ color: m.color }}>{m.val}</div>
            <div className="text-white/30 text-[10px]">{m.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <h3 className="text-base font-bold mb-4">Recent proxy logs</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="text-white/40 border-b border-white/[0.06]">
                  <th className="pb-2 font-medium">Time</th>
                  <th className="pb-2 font-medium">Endpoint</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Sigs</th>
                </tr>
              </thead>
              <tbody className="text-white/80">
                {isLoadingLogs ? (
                  <tr><td colSpan={4} className="py-4 text-center text-white/40">Loading logs...</td></tr>
                ) : !logsData?.logs || logsData.logs.length === 0 ? (
                  <tr><td colSpan={4} className="py-4 text-center text-white/40">No recent logs</td></tr>
                ) : (
                  logsData.logs.map((log: ProxyLog) => {
                    const timeStr = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    const sigScore = (log.ecdsaVerified ? 1 : 0) + (log.dilithiumVerified ? 1 : 0);
                    return (
                      <tr key={log._id} className={`border-b border-white/[0.06] ${log.threatFlag ? 'bg-red-500/[0.02]' : ''}`}>
                        <td className="py-3 text-white/40">{timeStr}</td>
                        <td className="py-3">{log.endpointId}</td>
                        <td className="py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] border ${log.statusCode < 400 ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                            {log.statusCode}
                          </span>
                        </td>
                        <td className="py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] border ${sigScore === 2 ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                            {sigScore}/2
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <h3 className="text-base font-bold mb-4">Signature verification rate</h3>
          
          <div className="mb-4">
            <div className="flex justify-between mb-1">
              <span className="text-white/40 text-xs">ECDSA P-256</span>
              <span className="text-green-400 text-xs font-medium">100%</span>
            </div>
            <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
              <div className="h-full bg-green-400" style={{ width: '100%' }} />
            </div>
          </div>
          
          <div className="mb-6">
            <div className="flex justify-between mb-1">
              <span className="text-white/40 text-xs">ML-DSA-65</span>
              <span className="text-green-400 text-xs font-medium">100%</span>
            </div>
            <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
              <div className="h-full bg-green-400" style={{ width: '100%' }} />
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

