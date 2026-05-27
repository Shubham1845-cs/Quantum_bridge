import { useState } from "react";
import { motion } from "framer-motion";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getSummary, getProxyLogs, type ProxyLog } from "../api/analytics";

export default function AnalyticsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const [page, setPage] = useState(1);
  const [limit] = useState(20);

  const { data: summary, isLoading: isLoadingSummary } = useQuery({
    queryKey: ["analytics", orgId, "summary"],
    queryFn: () => getSummary(orgId!),
    enabled: !!orgId,
  });

  const { data: logsData, isLoading: isLoadingLogs } = useQuery({
    queryKey: ["analytics", orgId, "logs", page, limit],
    queryFn: () => getProxyLogs(orgId!, { page, limit }),
    enabled: !!orgId,
  });

  const handleExport = () => {
    alert("Export feature will trigger a backend CSV generation job.");
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight mb-1">Analytics</h2>
          <p className="text-white/40 text-sm">Request volume, verification rates, and threat events</p>
        </div>
        <div className="flex gap-2">
          <select className="bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-cyber-cyan/50">
            <option>Last 24h</option>
            <option>Last 7d</option>
            <option>Last 30d</option>
          </select>
          <button onClick={handleExport} className="px-3 py-1.5 border border-white/10 rounded-lg text-xs text-white/60 hover:text-white hover:bg-white/5 transition-colors">
            Export CSV
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
          <div className="text-white/40 text-xs font-medium mb-1">Total requests</div>
          <div className="text-2xl font-bold text-white">{isLoadingSummary ? "-" : summary?.requestsToday || 0}</div>
        </div>
        <div className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
          <div className="text-white/40 text-xs font-medium mb-1">Threat events</div>
          <div className="text-2xl font-bold text-red-500">{isLoadingSummary ? "-" : summary?.threatsToday || 0}</div>
        </div>
        <div className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
          <div className="text-white/40 text-xs font-medium mb-1">Avg latency</div>
          <div className="text-2xl font-bold text-white">{isLoadingSummary ? "-" : `${summary?.avgLatency || 0}ms`}</div>
        </div>
        <div className="p-5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
          <div className="text-white/40 text-xs font-medium mb-1">Avg Latency</div>
          <div className="text-2xl font-bold text-cyber-cyan">{isLoadingSummary ? "-" : `${summary?.avgLatency || 0}ms`}</div>
        </div>
      </div>

      <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
        <h3 className="text-base font-bold mb-4">Proxy logs</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left mb-4">
            <thead>
              <tr className="text-white/40 border-b border-white/[0.06]">
                <th className="pb-2 font-medium">Time</th>
                <th className="pb-2 font-medium">Request ID</th>
                <th className="pb-2 font-medium">Endpoint</th>
                <th className="pb-2 font-medium">Method</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Threat</th>
              </tr>
            </thead>
            <tbody className="text-white/80">
              {isLoadingLogs ? (
                <tr><td colSpan={6} className="py-4 text-center text-white/40">Loading logs...</td></tr>
              ) : !logsData?.logs || logsData.logs.length === 0 ? (
                <tr><td colSpan={6} className="py-4 text-center text-white/40">No logs found</td></tr>
              ) : (
                logsData.logs.map((log: ProxyLog) => (
                  <tr key={log._id} className={`border-b border-white/[0.06] ${log.threatFlag ? 'bg-red-500/[0.02]' : ''}`}>
                    <td className="py-3 text-white/40">{new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
                    <td className="py-3 font-mono text-xs">{log.requestId.substring(0, 8)}...</td>
                    <td className="py-3">{log.endpointId}</td>
                    <td className="py-3 text-xs">{log.method}</td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${log.statusCode < 400 ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                        {log.statusCode}
                      </span>
                    </td>
                    <td className="py-3">
                      {log.threatFlag ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/20">Yes</span>
                      ) : (
                        <span className="text-white/20">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <div className="flex justify-between items-center text-xs text-white/40">
            <div>
              Showing {logsData?.logs?.length || 0} of {logsData?.total || 0} logs
            </div>
            <div className="flex gap-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 border border-white/10 rounded-lg hover:text-white hover:bg-white/5 disabled:opacity-50"
              >
                Previous
              </button>
              <button 
                onClick={() => setPage(p => p + 1)}
                disabled={(logsData?.logs?.length || 0) < limit}
                className="px-3 py-1 border border-white/10 rounded-lg hover:text-white hover:bg-white/5 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

