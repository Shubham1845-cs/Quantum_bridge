import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, ShieldCheck, AlertTriangle, Gauge } from "lucide-react";
import {
  getSummary,
  getProxyLogs,
  getTimeseries,
  type ProxyLog,
} from "../api/analytics";
import { useAuth } from "../context/AuthContext";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { Card } from "../components/ui/Card";
import { cn } from "../lib/utils";

const LOG_SAMPLE = 100;

export default function OrgOverviewPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const { loading: authLoading } = useAuth();

  const { data: summary, isLoading: isLoadingSummary } = useQuery({
    queryKey: ["analytics", orgId, "summary"],
    queryFn: () => getSummary(orgId!),
    enabled: !!orgId && !authLoading,
  });

  const { data: logsData, isLoading: isLoadingLogs } = useQuery({
    queryKey: ["analytics", orgId, "logs", "sample", LOG_SAMPLE],
    queryFn: () => getProxyLogs(orgId!, { limit: LOG_SAMPLE }),
    enabled: !!orgId && !authLoading,
    refetchInterval: 5000,
  });

  const { data: timeseries = [] } = useQuery({
    queryKey: ["analytics", orgId, "timeseries", "24h"],
    queryFn: () =>
      getTimeseries(orgId!, {
        startDate: new Date(Date.now() - 24 * 3600_000).toISOString(),
        endDate: new Date().toISOString(),
        granularity: "hourly",
      }),
    enabled: !!orgId && !authLoading,
    refetchInterval: 30000,
  });

  const recentLogs = logsData?.logs ?? [];
  const tableLogs = recentLogs.slice(0, 6);

  const sampleTotal = recentLogs.length;
  const ecdsaRate =
    sampleTotal > 0
      ? Math.round((recentLogs.filter((l) => l.ecdsaVerified).length / sampleTotal) * 100)
      : null;
  const dilithiumRate =
    sampleTotal > 0
      ? Math.round((recentLogs.filter((l) => l.dilithiumVerified).length / sampleTotal) * 100)
      : null;

  const todayStr = new Date().toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const total24h = timeseries.reduce((acc, p) => acc + (p.requestCount ?? 0), 0);
  const threats24h = timeseries.reduce(
    (acc, p) => acc + Math.round((p.requestCount ?? 0) * (p.threatFlagRate ?? 0)),
    0,
  );

  const chartData = timeseries.map((p) => ({
    time: new Date(p.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    requests: p.requestCount ?? 0,
    threatRate: Math.round((p.threatFlagRate ?? 0) * 1000) / 10,
  }));

  return (
    <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
      <PageHeader title="Overview" description={todayStr} />

      {/* Stat cards */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Requests (24h)" value={total24h.toLocaleString()} hint="Last 24 hours" icon={Activity} tone="cyan" loading={isLoadingSummary} />
        <StatCard label="Threats flagged" value={threats24h || (summary?.threatsToday ?? 0)} hint="Signature failures" icon={AlertTriangle} tone="rose" loading={isLoadingSummary} />
        <StatCard label="Avg latency" value={`${summary?.avgLatency ?? 0}ms`} hint="End-to-end" icon={Gauge} tone="violet" loading={isLoadingSummary} />
        <StatCard label="Plan usage" value={(summary?.monthlyRequestCount ?? 0).toLocaleString()} hint="Requests this month" icon={ShieldCheck} tone="emerald" loading={isLoadingSummary} />
      </div>

      {/* Request volume chart */}
      <Card className="mb-6 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold">Request volume</h3>
            <p className="mt-0.5 text-xs text-white/40">Hourly proxied requests · last 24h</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-white/40">
            <span className="h-2 w-2 rounded-full bg-qb-cyan" /> Requests
          </div>
        </div>
        <div className="h-56 w-full">
          {chartData.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-white/30">
              No traffic in this window yet.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="qb-area" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={36} />
                <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={36} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "rgba(11,17,32,0.95)",
                    border: "1px solid rgba(34,211,238,0.2)",
                    borderRadius: 12,
                    fontSize: 12,
                    color: "white",
                    boxShadow: "0 12px 32px rgba(0,0,0,0.5)",
                  }}
                  labelStyle={{ color: "rgba(255,255,255,0.5)" }}
                  cursor={{ stroke: "rgba(34,211,238,0.3)" }}
                />
                <Area type="monotone" dataKey="requests" stroke="#22d3ee" strokeWidth={2} fill="url(#qb-area)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      {/* Logs + verification */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="mb-4 text-base font-semibold">Recent proxy logs</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] text-white/40">
                  <th className="pb-2 font-medium">Time</th>
                  <th className="pb-2 font-medium">Endpoint</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Sigs</th>
                </tr>
              </thead>
              <tbody className="text-white/80">
                {isLoadingLogs ? (
                  <tr><td colSpan={4} className="py-4 text-center text-white/40">Loading logs…</td></tr>
                ) : tableLogs.length === 0 ? (
                  <tr><td colSpan={4} className="py-4 text-center text-white/40">No recent logs</td></tr>
                ) : (
                  tableLogs.map((log: ProxyLog) => {
                    const timeStr = new Date(log.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                    const sigScore = (log.ecdsaVerified ? 1 : 0) + (log.dilithiumVerified ? 1 : 0);
                    return (
                      <tr key={log._id} className={cn("border-b border-white/[0.06]", log.threatFlag && "bg-qb-rose/[0.03]")}>
                        <td className="py-3 text-white/40 font-mono-qb text-xs">{timeStr}</td>
                        <td className="py-3 font-mono-qb text-xs">{log.endpointId}</td>
                        <td className="py-3">
                          <span className={cn("rounded-full border px-2 py-0.5 text-[10px]", log.statusCode < 400 ? "bg-qb-emerald/10 text-qb-emerald border-qb-emerald/20" : "bg-qb-rose/10 text-qb-rose border-qb-rose/20")}>
                            {log.statusCode}
                          </span>
                        </td>
                        <td className="py-3">
                          <span className={cn("rounded-full border px-2 py-0.5 text-[10px]", sigScore === 2 ? "bg-qb-emerald/10 text-qb-emerald border-qb-emerald/20" : "bg-qb-rose/10 text-qb-rose border-qb-rose/20")}>
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
        </Card>

        <Card className="p-6">
          <h3 className="mb-1 text-base font-semibold">Signature verification rate</h3>
          <p className="mb-5 text-[11px] text-white/30">
            Computed from the last {sampleTotal > 0 ? sampleTotal : 0} proxied request{sampleTotal === 1 ? "" : "s"}.
          </p>
          {[
            { label: "ECDSA P-256", rate: ecdsaRate },
            { label: "ML-DSA-65", rate: dilithiumRate },
          ].map((b) => {
            const known = b.rate !== null;
            const pct = known ? (b.rate as number) : 0;
            const color = !known ? "bg-white/20" : pct >= 99 ? "bg-qb-emerald" : pct >= 50 ? "bg-qb-amber" : "bg-qb-rose";
            const text = !known ? "—" : `${pct}%`;
            const textColor = !known ? "text-white/40" : pct >= 99 ? "text-qb-emerald" : pct >= 50 ? "text-qb-amber" : "text-qb-rose";
            return (
              <div key={b.label} className="mb-5 last:mb-0">
                <div className="mb-1 flex justify-between">
                  <span className="text-xs text-white/40">{b.label}</span>
                  <span className={cn("text-xs font-medium", textColor)}>{text}</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
                  <div className={cn("h-full transition-all duration-500", color)} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
          <div className="mt-6 border-t border-white/[0.06] pt-4 text-xs text-white/40">
            Both algorithms must verify ({`2/2`}) for a request to pass the proxy unflagged.
          </div>
        </Card>
      </div>
    </motion.div>
  );
}
