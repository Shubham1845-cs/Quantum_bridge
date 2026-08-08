import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, AlertTriangle, Gauge, ShieldCheck, Download } from "lucide-react";
import { getSummary, getProxyLogs, getTimeseries, exportLogs, type ProxyLog } from "../api/analytics";
import { useToast } from "../hooks/useToast";
import { useAuth } from "../context/AuthContext";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { Card } from "../components/ui/Card";
import Button from "../components/ui/Button";
import { cn } from "../lib/utils";

type Range = "24h" | "7d" | "30d";
const RANGE_DAYS: Record<Range, number> = { "24h": 1, "7d": 7, "30d": 30 };
const RANGE_GRAN: Record<Range, "hourly" | "daily"> = { "24h": "hourly", "7d": "daily", "30d": "daily" };

export default function AnalyticsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const toast = useToast();
  const { loading: authLoading } = useAuth();
  const [page, setPage] = useState(1);
  const [limit] = useState(20);
  const [range, setRange] = useState<Range>("24h");
  const [isExporting, setIsExporting] = useState(false);

  const startDate = new Date(Date.now() - RANGE_DAYS[range] * 86_400_000).toISOString();

  const { data: summary, isLoading: isLoadingSummary } = useQuery({
    queryKey: ["analytics", orgId, "summary"],
    queryFn: () => getSummary(orgId!),
    enabled: !!orgId && !authLoading,
  });

  const { data: logsData, isLoading: isLoadingLogs } = useQuery({
    queryKey: ["analytics", orgId, "logs", page, limit, range],
    queryFn: () => getProxyLogs(orgId!, { page, limit, startDate }),
    enabled: !!orgId && !authLoading,
    refetchInterval: 5000,
  });

  const { data: timeseries = [] } = useQuery({
    queryKey: ["analytics", orgId, "timeseries", range],
    queryFn: () =>
      getTimeseries(orgId!, {
        startDate,
        endDate: new Date().toISOString(),
        granularity: RANGE_GRAN[range],
      }),
    enabled: !!orgId && !authLoading,
    refetchInterval: 30000,
  });

  const handleExport = async () => {
    if (!orgId) return;
    setIsExporting(true);
    try {
      const blob = await exportLogs(orgId, "csv");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `quantumbridge-logs-${range}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("CSV export downloaded");
    } catch (err: any) {
      toast.error(err.response?.data?.error || "Failed to export logs");
    } finally {
      setIsExporting(false);
    }
  };

  const chartData = timeseries.map((p) => ({
    time:
      RANGE_GRAN[range] === "hourly"
        ? new Date(p.timestamp).toLocaleTimeString([], { hour: "2-digit" })
        : new Date(p.timestamp).toLocaleDateString([], { month: "short", day: "numeric" }),
    requests: p.requestCount ?? 0,
    ecdsa: Math.round((p.ecdsaVerificationRate ?? 0) * 1000) / 10,
    dilithium: Math.round((p.dilithiumVerificationRate ?? 0) * 1000) / 10,
  }));

  const totalRequests = chartData.reduce((a, p) => a + p.requests, 0);
  const avgVerif = summary && summary.requestsToday > 0
    ? ((summary.requestsToday - summary.threatsToday) / summary.requestsToday) * 100
    : 100;

  const tooltipStyle = {
    background: "rgba(11,17,32,0.95)",
    border: "1px solid rgba(34,211,238,0.2)",
    borderRadius: 12,
    fontSize: 12,
    color: "white",
    boxShadow: "0 12px 32px rgba(0,0,0,0.5)",
  };

  return (
    <div>
      <PageHeader
        title="Analytics"
        description="Request volume, verification rates, and threat events"
        actions={
          <>
            <select
              value={range}
              onChange={(e) => { setRange(e.target.value as Range); setPage(1); }}
              className="qb-input-focus rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-xs text-white"
            >
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
              <option value="30d">Last 30d</option>
            </select>
            <Button onClick={handleExport} variant="secondary" size="sm" disabled={isExporting}>
              <Download size={13} className="mr-1.5" />
              {isExporting ? "Exporting…" : "Export CSV"}
            </Button>
          </>
        }
      />

      {/* Stat cards */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total requests" value={totalRequests.toLocaleString()} icon={Activity} tone="cyan" loading={isLoadingSummary} />
        <StatCard label="Threat events" value={summary?.threatsToday ?? 0} icon={AlertTriangle} tone="rose" loading={isLoadingSummary} />
        <StatCard label="Avg latency" value={`${summary?.avgLatency ?? 0}ms`} icon={Gauge} tone="violet" loading={isLoadingSummary} />
        <StatCard label="Signature Verif." value={`${avgVerif.toFixed(1)}%`} icon={ShieldCheck} tone="emerald" loading={isLoadingSummary} />
      </div>

      {/* Request volume */}
      <Card className="mb-6 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold">Request volume</h3>
            <p className="mt-0.5 text-xs text-white/40">Proxied requests over the selected window</p>
          </div>
          <span className="flex items-center gap-2 text-xs text-white/40">
            <span className="h-2 w-2 rounded-full bg-qb-cyan" /> Requests
          </span>
        </div>
        <div className="h-60 w-full">
          {chartData.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-white/30">No data in this window.</div>
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
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "rgba(255,255,255,0.5)" }} cursor={{ stroke: "rgba(34,211,238,0.3)" }} />
                <Area type="monotone" dataKey="requests" stroke="#22d3ee" strokeWidth={2} fill="url(#qb-area)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      {/* Verification rates */}
      <Card className="mb-6 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold">Verification rates</h3>
            <p className="mt-0.5 text-xs text-white/40">ECDSA P-256 vs ML-DSA-65 over time</p>
          </div>
          <div className="flex items-center gap-4 text-xs text-white/40">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-qb-cyan" /> ECDSA</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-qb-violet" /> ML-DSA-65</span>
          </div>
        </div>
        <div className="h-60 w-full">
          {chartData.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-white/30">No data in this window.</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={36} />
                <YAxis domain={[0, 100]} stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={36} tickFormatter={(v) => `${v}%`} />
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "rgba(255,255,255,0.5)" }} cursor={{ stroke: "rgba(34,211,238,0.3)" }} />
                <Line type="monotone" dataKey="ecdsa" stroke="#22d3ee" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="dilithium" stroke="#a855f7" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      {/* Log table */}
      <Card className="p-6">
        <h3 className="mb-4 text-base font-semibold">Proxy logs</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-white/[0.06] text-white/40">
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
                <tr><td colSpan={6} className="py-4 text-center text-white/40">Loading logs…</td></tr>
              ) : !logsData?.logs || logsData.logs.length === 0 ? (
                <tr><td colSpan={6} className="py-4 text-center text-white/40">No logs found</td></tr>
              ) : (
                logsData.logs.map((log: ProxyLog) => (
                  <tr key={log._id} className={cn("border-b border-white/[0.06]", log.threatFlag && "bg-qb-rose/[0.03]")}>
                    <td className="py-3 font-mono-qb text-xs text-white/40">{new Date(log.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</td>
                    <td className="py-3 font-mono-qb text-xs">{log.requestId.substring(0, 8)}…</td>
                    <td className="py-3 font-mono-qb text-xs">{log.endpointId}</td>
                    <td className="py-3 text-xs">{log.method}</td>
                    <td className="py-3">
                      <span className={cn("rounded-full border px-2 py-0.5 text-[10px]", log.statusCode < 400 ? "bg-qb-emerald/10 text-qb-emerald border-qb-emerald/20" : "bg-qb-rose/10 text-qb-rose border-qb-rose/20")}>
                        {log.statusCode}
                      </span>
                    </td>
                    <td className="py-3">
                      {log.threatFlag ? (
                        <span className="rounded-full border border-qb-rose/20 bg-qb-rose/10 px-2 py-0.5 text-[10px] text-qb-rose">Yes</span>
                      ) : (
                        <span className="text-white/20">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-4 flex items-center justify-between text-xs text-white/40">
          <div>Showing {logsData?.logs?.length || 0} of {logsData?.total || 0} logs</div>
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>Previous</Button>
            <Button variant="secondary" size="sm" onClick={() => setPage((p) => p + 1)} disabled={(logsData?.logs?.length || 0) < limit}>Next</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
