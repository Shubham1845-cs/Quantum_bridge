import { useState, useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Search,
  Bell,
  Settings,
  LayoutDashboard,
  AlertTriangle,
  FileText,
  Users,
  Server,
  Activity,
  Lock,
  ChevronDown,
  Clock,
  Database,
  HelpCircle,
  Calendar,
  ArrowUpRight,
  ArrowDownRight,
  ShieldAlert,
  ShieldCheck,
  Target,
  Timer,
  Eye,
  Cpu,
  LogOut,
  Globe,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";

// ---------- DATA ----------
const quantumActivityData = [
  { time: "00:00", requests: 320, verified: 318, failed: 2 },
  { time: "02:00", requests: 410, verified: 408, failed: 2 },
  { time: "04:00", requests: 280, verified: 279, failed: 1 },
  { time: "06:00", requests: 520, verified: 517, failed: 3 },
  { time: "08:00", requests: 680, verified: 676, failed: 4 },
  { time: "10:00", requests: 890, verified: 885, failed: 5 },
  { time: "12:00", requests: 1240, verified: 1234, failed: 6 },
  { time: "14:00", requests: 1050, verified: 1045, failed: 5 },
  { time: "16:00", requests: 1380, verified: 1374, failed: 6 },
  { time: "18:00", requests: 1180, verified: 1175, failed: 5 },
  { time: "20:00", requests: 920, verified: 916, failed: 4 },
  { time: "22:00", requests: 640, verified: 637, failed: 3 },
];

const signatureTypesData = [
  { name: "ML-DSA-65", value: 52, color: "#00D9D9" },
  { name: "ECDSA P-256", value: 48, color: "#8B5CF6" },
];

const topEndpoints = [
  { name: "/api/auth/login", requests: 4823, latency: 42, status: "healthy", method: "POST" },
  { name: "/api/users/profile", requests: 4128, latency: 38, status: "healthy", method: "GET" },
  { name: "/api/data/fetch", requests: 2945, latency: 51, status: "healthy", method: "GET" },
  { name: "/api/payments/process", requests: 2210, latency: 67, status: "warning", method: "POST" },
  { name: "/api/reports/generate", requests: 1684, latency: 89, status: "warning", method: "POST" },
  { name: "/api/analytics/track", requests: 1247, latency: 35, status: "healthy", method: "POST" },
];

const recentVerifications = [
  {
    id: "VRF-2847",
    severity: "Success",
    type: "Dual Signature Verified",
    endpoint: "/api/auth/login",
    time: "2 min ago",
    status: "Verified",
  },
  {
    id: "VRF-2846",
    severity: "Success",
    type: "ML-DSA-65 Verified",
    endpoint: "/api/users/profile",
    time: "8 min ago",
    status: "Verified",
  },
  {
    id: "VRF-2845",
    severity: "Warning",
    type: "Signature Mismatch",
    endpoint: "/api/data/fetch",
    time: "14 min ago",
    status: "Rejected",
  },
  {
    id: "VRF-2844",
    severity: "Success",
    type: "ECDSA P-256 Verified",
    endpoint: "/api/payments/process",
    time: "23 min ago",
    status: "Verified",
  },
  {
    id: "VRT-2843",
    severity: "Warning",
    type: "Expired Signature",
    endpoint: "/api/reports/generate",
    time: "41 min ago",
    status: "Rejected",
  },
  {
    id: "VRF-2842",
    severity: "Success",
    type: "Dual Signature Verified",
    endpoint: "/api/analytics/track",
    time: "1 hr ago",
    status: "Verified",
  },
];

const networkTrafficData = [
  { time: "00:00", requests: 420, verified: 415, rejected: 5 },
  { time: "03:00", requests: 380, verified: 376, rejected: 4 },
  { time: "06:00", requests: 510, verified: 504, rejected: 6 },
  { time: "09:00", requests: 780, verified: 772, rejected: 8 },
  { time: "12:00", requests: 920, verified: 910, rejected: 10 },
  { time: "15:00", requests: 1050, verified: 1038, rejected: 12 },
  { time: "18:00", requests: 890, verified: 881, rejected: 9 },
  { time: "21:00", requests: 640, verified: 634, rejected: 6 },
];

const systemHealthData = [
  { name: "Quantum Bridge", value: 98, fill: "#00D9D9" },
  { name: "ML-DSA-65 Engine", value: 97, fill: "#8B5CF6" },
  { name: "ECDSA P-256 Engine", value: 99, fill: "#10B981" },
  { name: "API Gateway", value: 96, fill: "#F59E0B" },
];

// ---------- STYLE MAPS ----------
const severityStyles: Record<string, string> = {
  Success: "bg-[#10B981]/15 text-[#34D399] border-[#10B981]/30",
  Warning: "bg-[#F59E0B]/15 text-[#FBBF24] border-[#F59E0B]/30",
  Error: "bg-[#EF4444]/15 text-[#FF6B6B] border-[#EF4444]/30",
  Info: "bg-[#3B82F6]/15 text-[#60A5FA] border-[#3B82F6]/30",
};

const statusStyles: Record<string, string> = {
  Verified: "text-[#34D399]",
  Rejected: "text-[#FF6B6B]",
  Pending: "text-[#FBBF24]",
  Processing: "text-[#60A5FA]",
};

// ---------- MOCK DATA FOR SECTIONS ----------
const mockAlerts = [
  {
    id: 'ALT-001',
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    threatType: 'Brute Force Attempt',
    sourceIp: '192.168.1.101',
    target: '/api/auth/login',
    severity: 'high',
    status: 'active',
  },
  {
    id: 'ALT-002',
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    threatType: 'Malware Signature Detected',
    sourceIp: '10.0.0.45',
    target: '/api/users/profile',
    severity: 'medium',
    status: 'investigating',
  },
  {
    id: 'ALT-003',
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    threatType: 'Anomalous Traffic Spike',
    sourceIp: '172.16.254.12',
    target: '/api/data/fetch',
    severity: 'low',
    status: 'resolved',
  },
  {
    id: 'ALT-004',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    threatType: 'Zero-Day Exploit Attempt',
    sourceIp: '203.0.113.45',
    target: '/api/payments/process',
    severity: 'critical',
    status: 'blocked',
  },
];

const mockKeys = [
  {
    id: 'KEY-001',
    name: 'Primary Signing Key',
    algorithm: 'ML-DSA-65',
    keyId: 'mk-2a4f8c9e',
    created: '2024-01-15',
    expires: '2027-01-15',
    status: 'active',
    usage: '12,450 signatures',
  },
  {
    id: 'KEY-002',
    name: 'Backup Encryption Key',
    algorithm: 'ECDSA P-256',
    keyId: 'ek-9b3d1f2a',
    created: '2023-11-02',
    expires: '2026-11-02',
    status: 'active',
    usage: '3,200 encryptions',
  },
  {
    id: 'KEY-003',
    name: 'Legacy Key (Rotating)',
    algorithm: 'RSA-2048',
    keyId: 'lk-4c7a6b1d',
    created: '2022-06-10',
    expires: '2025-06-10',
    status: 'rotating',
    usage: '1,050 signatures',
  },
];

const mockUsers = [
  {
    id: 'USR-001',
    name: 'Alice Smith',
    email: 'alice@example.com',
    role: 'Administrator',
    status: 'active',
    lastLogin: '2 minutes ago',
  },
  {
    id: 'USR-002',
    name: 'Bob Jones',
    email: 'bob@example.com',
    role: 'Operator',
    status: 'active',
    lastLogin: '5 hours ago',
  },
  {
    id: 'USR-003',
    name: 'Carol Lee',
    email: 'carol@example.com',
    role: 'Auditor',
    status: 'inactive',
    lastLogin: '2 days ago',
  },
  {
    id: 'USR-004',
    name: 'David Brown',
    email: 'david@example.com',
    role: 'Viewer',
    status: 'active',
    lastLogin: '1 week ago',
  },
];

const mockReports = [
  {
    id: 'RPT-001',
    name: 'Monthly Security Summary',
    type: 'Summary',
    generatedAt: '2024-06-20 08:00:00',
    size: '2.4 MB',
    status: 'ready',
  },
  {
    id: 'RPT-002',
    name: 'Threat Landscape Q2',
    type: 'Analysis',
    generatedAt: '2024-06-15 14:30:00',
    size: '5.1 MB',
    status: 'ready',
  },
  {
    id: 'RPT-003',
    name: 'Key Usage Analytics',
    type: 'Analytics',
    generatedAt: '2024-06-10 09:15:00',
    size: '1.2 MB',
    status: 'generating',
  },
];

const mockSettings = {
  general: {
    theme: 'dark',
    language: 'en',
    timeFormat: '24h',
    refreshInterval: '5m',
  },
  notifications: {
    emailAlerts: true,
    pushNotifications: false,
    severityThreshold: 'medium',
  },
  security: {
    sessionTimeout: '30m',
    maxLoginAttempts: 5,
    require2FA: true,
  },
  system: {
    logRetention: '90 days',
    backupFrequency: 'daily',
    apiRateLimit: '1000/hour',
  },
};

// ---------- COMPONENTS ----------
interface SidebarItemProps {
  icon: React.ElementType;
  label: string;
  active?: boolean;
  badge?: number;
  onClick?: () => void;
}

function SidebarItem({ icon: Icon, label, active, badge, onClick }: SidebarItemProps) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm transition-all ${
        active
          ? "bg-[#00D9D9]/10 text-[#00D9D9] border-l-2 border-[#00D9D9]"
          : "text-[#8B95A7] hover:bg-[#141823] hover:text-white border-l-2 border-transparent"
      }`}
    >
      <Icon className="w-[18px] h-[18px]" />
      <span className="flex-1 text-left font-medium">{label}</span>
      {badge ? (
        <span className="bg-[#EF4444] text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
          {badge}
        </span>
      ) : null}
    </button>
  );
}

interface StatCardProps {
  icon: React.ElementType;
  label: string;
  value: string;
  change: string;
  trend: "up" | "down";
  accent: string;
  iconBg: string;
}

function StatCard({ icon: Icon, label, value, change, trend, accent, iconBg }: StatCardProps) {
  const TrendIcon = trend === "up" ? ArrowUpRight : ArrowDownRight;
  const isPositive = trend === "up";
  const trendColor = isPositive ? "text-[#FF6B6B]" : "text-[#34D399]";
  const trendBg = isPositive ? "bg-[#EF4444]/10" : "bg-[#10B981]/10";

  return (
    <div
      onClick={() => console.log("Viewing details for:", label)}
      className="bg-[#141823] border border-[#1F2533] rounded-xl p-5 hover:border-[#00D9D9]/30 transition-all cursor-pointer group"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`w-11 h-11 rounded-xl flex items-center justify-center ${iconBg} group-hover:scale-110 transition-transform`}>
          <Icon className={`w-5 h-5 ${accent}`} />
        </div>
        <div className={`flex items-center gap-1 px-2 py-1 rounded-md ${trendBg}`}>
          <TrendIcon className={`w-3 h-3 ${trendColor}`} />
          <span className={`text-[11px] font-semibold ${trendColor}`}>{change}</span>
        </div>
      </div>
      <div className="text-[#8B95A7] text-xs font-medium mb-1.5">{label}</div>
      <div className="text-white text-[28px] font-bold leading-none mb-1.5">{value}</div>
      <div className="text-[11px] text-[#5A6478]">vs previous 24 hours</div>
    </div>
  );
}

// ---------- SECTION RENDERERS ----------
const renderAlertsSection = () => {
  const alerts = mockAlerts;
  return (
    <>
      <div className="space-y-6">
        {/* Alerts Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-white">Security Alerts</h2>
            <p className="text-white/40 text-sm">
              {alerts.length} active threats detected
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => {/* TODO: Implement filter */}}
              className="px-3 py-1 bg-white/5 rounded-md text-sm text-white/70 hover:bg-white/10 hover:text-white transition-colors"
            >
              Filter
            </button>
            <button
              onClick={() => {/* TODO: Implement export */}}
              className="px-3 py-1 bg-cyber-cyan/10 text-cyber-cyan rounded-md text-sm hover:bg-cyber-cyan/20 transition-colors"
            >
              Export
            </button>
          </div>
        </div>

        {/* Alerts Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-4">
            <div className="text-white/40 text-xs">Critical Alerts</div>
            <div className="text-red-400 font-bold text-xl">
              {alerts.filter(a => a.severity === 'critical').length}
            </div>
          </div>
          <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-4">
            <div className="text-white/40 text-xs">Warnings</div>
            <div className="text-yellow-400 font-bold text-xl">
              {alerts.filter(a => a.severity === 'warning').length}
            </div>
          </div>
          <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-4">
            <div className="text-white/40 text-xs">Info</div>
            <div className="text-blue-400 font-bold text-xl">
              {alerts.filter(a => a.severity === 'info').length}
            </div>
          </div>
          <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-4">
            <div className="text-white/40 text-xs">Last 24h</div>
            <div className="text-cyber-cyan font-bold text-xl">
              {alerts.length}
            </div>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                  <th className="text-left font-semibold px-6 py-3">Time</th>
                  <th className="text-left font-semibold px-6 py-3">Threat Type</th>
                  <th className="text-left font-semibold px-6 py-3">Source IP</th>
                  <th className="text-left font-semibold px-6 py-3">Target</th>
                  <th className="text-left font-semibold px-6 py-3">Severity</th>
                  <th className="text-left font-semibold px-6 py-3">Status</th>
                  <th className="text-left font-semibold px-6 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B]/50 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-3.5 text-[12px] text-white/80 font-mono">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-3.5 text-[12px]">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                        alert.severity === 'critical'
                          ? 'bg-red-500/20 text-red-400'
                          : alert.severity === 'warning'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-blue-500/20 text-blue-400'
                      }`}>
                        {alert.threatType || 'Unknown Threat'}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-[12px]">
                      {alert.sourceIp || 'N/A'}
                    </td>
                    <td className="px-6 py-3.5 text-[12px]">
                      {alert.target || 'N/A'}
                    </td>
                    <td className="px-6 py-3.5">
                      <span className={`text-[10px] uppercase tracking-wider font-bold px-2.5 py-1 rounded border ${
                        severityStyles[alert.severity] || ''
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3.5">
                      <span className={`text-[12px] font-semibold ${statusStyles[alert.status] || ''}`}>
                        {alert.status}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-[12px] text-white/60">
                      <button
                        onClick={() => console.log("View alert:", alert.id)}
                        className="px-2 py-1 bg-[#00D9D9]/10 text-[#00D9D9] rounded hover:bg-[#00D9D9]/20 transition-colors text-sm"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
};

const renderMonitoringSection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Live Monitoring</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
        <div className="space-y-4">
          <div className="text-white/40 text-sm mb-2">
            Real-time monitoring of API traffic, signature verification, and system health.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#0D111B] p-4 rounded-lg">
              <div className="text-white/40 text-xs">Total Requests (24h)</div>
              <div className="text-white text-2xl font-bold">1,245,678</div>
            </div>
            <div className="bg-[#0D111B] p-4 rounded-lg">
              <div className="text-white/40 text-xs">Average Latency</div>
              <div className="text-white text-2xl font-bold">42 ms</div>
            </div>
            <div className="bg-[#0D111B] p-4 rounded-lg">
              <div className="text-white/40 text-xs">Success Rate</div>
              <div className="text-white text-2xl font-bold">99.8%</div>
            </div>
            <div className="bg-[#0D111B] p-4 rounded-lg">
              <div className="text-white/40 text-xs">Blocked Threats</div>
              <div className="text-white text-2xl font-bold">1,234</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const renderVerificationsSection = () => {
  const verifications = recentVerifications;
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Verifications</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                <th className="text-left font-semibold px-6 py-3">Verification ID</th>
                <th className="text-left font-semibold px-3 py-3">Result</th>
                <th className="text-left font-semibold px-3 py-3">Type</th>
                <th className="text-left font-semibold px-3 py-3">Endpoint</th>
                <th className="text-left font-semibold px-3 py-3">Status</th>
                <th className="text-left font-semibold px-3 py-3">Time</th>
              </tr>
            </thead>
            <tbody>
              {verifications.map((v) => (
                <tr
                  key={v.id}
                  className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B]/50 transition-colors cursor-pointer"
                >
                  <td className="px-6 py-3.5 font-mono text-[12px] text-[#00D9D9]">
                    {v.id}
                  </td>
                  <td className="px-3 py-3.5">
                    <span
                      className={`text-[10px] uppercase tracking-wider font-bold px-2.5 py-1 rounded border ${
                        severityStyles[v.severity]
                      }`}
                    >
                      {v.severity}
                    </span>
                  </td>
                  <td className="px-3 py-3.5 text-[13px] text-[#D1D5DB] font-medium">
                    {v.type}
                  </td>
                  <td className="px-3 py-3.5 font-mono text-[12px] text-[#8B95A7]">
                    {v.endpoint}
                  </td>
                  <td className="px-3 py-3.5">
                    <span className={`text-[12px] font-semibold ${statusStyles[v.status]}`}>
                      {v.status}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 text-[12px] text-[#8B95A7]">
                    {v.time}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const renderSignaturesSection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Signatures</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">Signature Distribution</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={signatureTypesData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {signatureTypesData.map((entry, index) => (
                    <Cell key={`sign-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0D111B",
                    border: "1px solid #1F2533",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">Signature Details</h3>
          <div className="space-y-3">
            {signatureTypesData.map((sig) => (
              <div key={sig.name} className="flex items-center justify-between text-[12px]">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-sm"
                    style={{ backgroundColor: sig.color }}
                  />
                  <span>{sig.name}</span>
                </div>
                <span className="font-semibold text-white">{sig.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

const renderEndpointsSection = () => {
  const endpoints = topEndpoints;
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Endpoints</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                <th className="text-left font-semibold px-6 py-3">Endpoint</th>
                <th className="text-left font-semibold px-3 py-3">Method</th>
                <th className="text-left font-semibold px-3 py-3">Requests</th>
                <th className="text-left font-semibold px-3 py-3">Latency</th>
                <th className="text-left font-semibold px-3 py-3">Status</th>
                <th className="text-left font-semibold px-3 py-3">Last Checked</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep) => (
                <tr
                  key={ep.name}
                  className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B]/50 transition-colors cursor-pointer"
                >
                  <td className="px-6 py-3.5 text-[12px]">
                    {ep.name}
                  </td>
                  <td className="px-3 py-3.5 text-[10px] uppercase">
                    {ep.method}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {ep.requests.toLocaleString()}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {ep.latency}ms
                  </td>
                  <td className="px-3 py-3.5">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      ep.status === "healthy"
                        ? "bg-[#10B981]/20 text-[#10B981]"
                        : ep.status === "warning"
                          ? "bg-[#F59E0B]/20 text-[#F59E0B]"
                          : "bg-[#EF4444]/20 text-[#EF4444]"
                    }`}>
                      {ep.status}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 text-[12px] text-[#8B95A7]">
                    {new Date().toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const renderKeysSection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Key Management</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                <th className="text-left font-semibold px-6 py-3">Key ID</th>
                <th className="text-left font-semibold px-3 py-3">Name</th>
                <th className="text-left font-semibold px-3 py-3">Algorithm</th>
                <th className="text-left font-semibold px-3 py-3">Created</th>
                <th className="text-left font-semibold px-3 py-3">Expires</th>
                <th className="text-left font-semibold px-3 py-3">Status</th>
                <th className="text-left font-semibold px-3 py-3">Usage</th>
              </tr>
            </thead>
            <tbody>
              {mockKeys.map((key) => (
                <tr
                  key={key.id}
                  className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B]/50 transition-colors cursor-pointer"
                >
                  <td className="px-6 py-3.5 text-[12px] font-mono">
                    {key.keyId}
                  </td>
                  <td className="px-6 py-3.5 text-[13px]">
                    {key.name}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {key.algorithm}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {key.created}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {key.expires}
                  </td>
                  <td className="px-3 py-3.5">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      key.status === "active"
                        ? "bg-[#10B981]/20 text-[#10B981]"
                        : key.status === "rotating"
                          ? "bg-[#F59E0B]/20 text-[#F59E0B]"
                          : "bg-[#EF4444]/20 text-[#EF4444]"
                    }`}>
                      {key.status}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 text-[12px]">
                    {key.usage}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const renderUsersSection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Users</h2>
        <button
          onClick={() => {/* TODO: Refresh */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                <th className="text-left font-semibold px-6 py-3">User ID</th>
                <th className="text-left font-semibold px-3 py-3">Name</th>
                <th className="text-left font-semibold px-3 py-3">Email</th>
                <th className="text-left font-semibold px-3 py-3">Role</th>
                <th className="text-left font-semibold px-3 py-3">Status</th>
                <th className="text-left font-semibold px-3 py-3">Last Login</th>
              </tr>
            </thead>
            <tbody>
              {mockUsers.map((user) => (
                <tr
                  key={user.id}
                  className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B]/50 transition-colors cursor-pointer"
                >
                  <td className="px-6 py-3.5 text-[12px] font-mono">
                    {user.id}
                  </td>
                  <td className="px-6 py-3.5 text-[13px]">
                    {user.name}
                  </td>
                  <td className="px-6 py-3.5 text-[12px]">
                    {user.email}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {user.role}
                  </td>
                  <td className="px-3 py-3.5">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      user.status === "active"
                        ? "bg-[#10B981]/20 text-[#10B981]"
                        : user.status === "inactive"
                          ? "bg-[#F59E0B]/20 text-[#F59E0B]"
                          : "bg-[#EF4444]/20 text-[#EF4444]"
                    }`}>
                      {user.status}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 text-[12px]">
                    {user.lastLogin}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const renderReportsSection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Reports</h2>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {/* TODO: Generate report */}}
            className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
          >
            Generate Report
          </button>
          <button
            onClick={() => {/* TODO: Refresh */}}
            className="px-4 py-2 bg-white/5 text-white/70 rounded-md hover:bg-white/10 hover:text-white transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>
      <div className="bg-[#141823] border border-[#1F2533] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                <th className="text-left font-semibold px-6 py-3">Report ID</th>
                <th className="text-left font-semibold px-3 py-3">Name</th>
                <th className="text-left font-semibold px-3 py-3">Type</th>
                <th className="text-left font-semibold px-3 py-3">Generated At</th>
                <th className="text-left font-semibold px-3 py-3">Size</th>
                <th className="text-left font-semibold px-3 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {mockReports.map((rep) => (
                <tr
                  key={rep.id}
                  className="border-b border-[#1F2533] last:border-0 hover:bg-[0D111B]/50 transition-colors cursor-pointer"
                >
                  <td className="px-6 py-3.5 text-[12px] font-mono">
                    {rep.id}
                  </td>
                  <td className="px-6 py-3.5 text-[13px]">
                    {rep.name}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {rep.type}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {rep.generatedAt}
                  </td>
                  <td className="px-3 py-3.5 text-[12px]">
                    {rep.size}
                  </td>
                  <td className="px-3 py-3.5">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      rep.status === "ready"
                        ? "bg-[#10B981]/20 text-[#10B981]"
                        : rep.status === "generating"
                          ? "bg-[#F59E0B]/20 text-[#F59E0B]"
                          : "bg-[#EF4444]/20 text-[#EF4444]"
                    }`}>
                      {rep.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const renderSettingsSection = () => {
  const s = mockSettings;
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">Settings</h2>
        <button
          onClick={() => {/* TODO: Save */}}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan rounded-md hover:bg-cyber-cyan/20 transition-colors"
        >
          Save Settings
        </button>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">General</h3>
          <div className="space-y-3">
            <div className="flex justify-between text-[12px]">
              <span>Theme</span>
              <span className="text-white">{s.general.theme}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Language</span>
              <span className="text-white">{s.general.language}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Time Format</span>
              <span className="text-white">{s.general.timeFormat}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Refresh Interval</span>
              <span className="text-white">{s.general.refreshInterval}</span>
            </div>
          </div>
        </div>
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">Notifications</h3>
          <div className="space-y-3">
            <div className="flex justify-between text-[12px]">
              <span>Email Alerts</span>
              <span className="text-white">{s.notifications.emailAlerts ? "Enabled" : "Disabled"}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Push Notifications</span>
              <span className="text-white">{s.notifications.pushNotifications ? "Enabled" : "Disabled"}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Severity Threshold</span>
              <span className="text-white">{s.notifications.severityThreshold}</span>
            </div>
          </div>
        </div>
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">Security</h3>
          <div className="space-y-3">
            <div className="flex justify-between text-[12px]">
              <span>Session Timeout</span>
              <span className="text-white">{s.security.sessionTimeout}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Max Login Attempts</span>
              <span className="text-white">{s.security.maxLoginAttempts}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>2FA Required</span>
              <span className="text-white">{s.security.require2FA ? "Enabled" : "Disabled"}</span>
            </div>
          </div>
        </div>
        <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
          <h3 className="text-[15px] font-bold text-white mb-4">System</h3>
          <div className="space-y-3">
            <div className="flex justify-between text-[12px]">
              <span>Log Retention</span>
              <span className="text-white">{s.system.logRetention}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>Backup Frequency</span>
              <span className="text-white">{s.system.backupFrequency}</span>
            </div>
            <div className="flex justify-between text-[12px]">
              <span>API Rate Limit</span>
              <span className="text-white">{s.system.apiRateLimit}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ---------- COMPONENT ----------
export default function ThreatAnalysisDashboard() {
  const { section } = useParams<{ section?: string }>();
  const [timeRange, setTimeRange] = useState("Last 24 Hours");
  const [searchQuery, setSearchQuery] = useState("");
  const [showTimeRangeDropdown, setShowTimeRangeDropdown] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [activeSection, setActiveSection] = useState(section || "dashboard");
  const navigate = useNavigate();
  const { logout } = useAuth();

  // Update active section when URL changes
  useEffect(() => {
    if (section) {
      setActiveSection(section);
    } else {
      setActiveSection("dashboard");
    }
  }, [section]);

  const timeRangeOptions = [
    "Last 1 Hour",
    "Last 6 Hours",
    "Last 12 Hours",
    "Last 24 Hours",
    "Last 7 Days",
    "Last 30 Days",
  ];

  const handleSidebarClick = (section: string) => {
    setActiveSection(section);
    // Navigate to the section route
    if (section === "dashboard") {
      navigate("/dashboard");
    } else {
      navigate(`/dashboard/${section}`);
    }
  };

  // Render section content based on active section
  const renderSectionContent = () => {
    switch (activeSection) {
      case "alerts":
        return renderAlertsSection();
      case "monitoring":
        return renderMonitoringSection();
      case "verifications":
        return renderVerificationsSection();
      case "signatures":
        return renderSignaturesSection();
      case "endpoints":
        return renderEndpointsSection();
      case "keys":
        return renderKeysSection();
      case "users":
        return renderUsersSection();
      case "reports":
        return renderReportsSection();
      case "settings":
        return renderSettingsSection();
      default:
        return (
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-[#00D9D9]/10 border border-[#00D9D9]/30 flex items-center justify-center">
                <Shield className="w-10 h-10 text-[#00D9D9]" />
              </div>
              <h2 className="text-2xl font-bold text-white mb-3">
                {activeSection.charAt(0).toUpperCase() + activeSection.slice(1)}
              </h2>
              <p className="text-[#8B95A7] text-sm mb-6 max-w-md">
                This section is under development.
              </p>
              <button
                onClick={() => handleSidebarClick("dashboard")}
                className="px-6 py-3 bg-[#00D9D9]/10 text-[#00D9D9] border border-[#00D9D9]/30 rounded-lg text-sm font-medium hover:bg-[#00D9D9]/20 transition-colors"
              >
                ← Back to Dashboard
              </button>
            </div>
          </div>
        );
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    console.log("Searching for:", searchQuery);
    // Add search logic here
  };

  return (
    <div className="min-h-screen bg-[#0A0E17] font-sans text-white flex">
      {/* ---------- SIDEBAR ---------- */}
      <aside className="w-60 bg-[#0D111B] border-r border-[#1F2533] flex flex-col">
        {/* Logo */}
        <div className="px-5 py-6 border-b border-[#1F2533]">
          <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00D9D9] to-[#0891B2] flex items-center justify-center">
              <Shield className="w-5 h-5 text-[#0A0E17]" strokeWidth={2.5} />
            </div>
            <div>
              <div className="font-bold text-[15px] tracking-tight">QuantumBridge</div>
              <div className="text-[10px] text-[#5A6478] uppercase tracking-widest -mt-0.5">
                Security Suite
              </div>
            </div>
          </Link>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          <div className="text-[10px] text-[#5A6478] uppercase tracking-widest px-4 pb-2 font-semibold">
            Main
          </div>
          <SidebarItem
            icon={LayoutDashboard}
            label="Dashboard"
            active={activeSection === "dashboard"}
            onClick={() => handleSidebarClick("dashboard")}
          />
          <SidebarItem
            icon={AlertTriangle}
            label="Alerts"
            badge={3}
            active={activeSection === "alerts"}
            onClick={() => handleSidebarClick("alerts")}
          />
          <SidebarItem
            icon={Activity}
            label="Live Monitoring"
            active={activeSection === "monitoring"}
            onClick={() => handleSidebarClick("monitoring")}
          />
          <SidebarItem
            icon={Eye}
            label="Verifications"
            active={activeSection === "verifications"}
            onClick={() => handleSidebarClick("verifications")}
          />
          <div className="text-[10px] text-[#5A6478] uppercase tracking-widest px-4 pb-2 pt-5 font-semibold">
            Quantum Security
          </div>
          <SidebarItem
            icon={Lock}
            label="Signatures"
            active={activeSection === "signatures"}
            onClick={() => handleSidebarClick("signatures")}
          />
          <SidebarItem
            icon={Server}
            label="Endpoints"
            active={activeSection === "endpoints"}
            onClick={() => handleSidebarClick("endpoints")}
          />
          <SidebarItem
            icon={Database}
            label="Key Management"
            active={activeSection === "keys"}
            onClick={() => handleSidebarClick("keys")}
          />
          <div className="text-[10px] text-[#5A6478] uppercase tracking-widest px-4 pb-2 pt-5 font-semibold">
            Management
          </div>
          <SidebarItem
            icon={Users}
            label="Users"
            active={activeSection === "users"}
            onClick={() => handleSidebarClick("users")}
          />
          <SidebarItem
            icon={FileText}
            label="Reports"
            active={activeSection === "reports"}
            onClick={() => handleSidebarClick("reports")}
          />
          <SidebarItem
            icon={Settings}
            label="Settings"
            active={activeSection === "settings"}
            onClick={() => handleSidebarClick("settings")}
          />
        </nav>

        {/* Status footer */}
        <div className="px-4 py-4 border-t border-[#1F2533]">
          <div className="bg-[#141823] rounded-lg p-3 border border-[#1F2533]">
            <div className="flex items-center gap-2 mb-1.5">
              <div className="w-2 h-2 rounded-full bg-[#34D399] shadow-[0_0_8px_#34D399]" />
              <span className="text-xs text-white font-medium">Systems Online</span>
            </div>
            <div className="text-[10px] text-[#5A6478]">All defenses operational</div>
          </div>
        </div>
      </aside>

      {/* ---------- MAIN ---------- */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top header */}
        <header className="h-[72px] border-b border-[#1F2533] bg-[#0D111B] flex items-center justify-between px-6 gap-6">
          <div>
            <h1 className="text-[20px] font-bold text-white tracking-tight">
              Quantum Security Operations Center
            </h1>
            <p className="text-[12px] text-[#8B95A7] mt-0.5">
              Real-time post-quantum cryptography monitoring & analytics
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Search */}
            <form onSubmit={handleSearch} className="relative">
              <Search className="w-4 h-4 text-[#5A6478] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search threats, IPs, incidents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-[280px] bg-[#141823] border border-[#1F2533] rounded-lg pl-10 pr-4 py-2.5 text-sm placeholder:text-[#5A6478] focus:outline-none focus:border-[#00D9D9]/50 text-white"
              />
            </form>

            {/* Time range */}
            <div className="relative">
              <button
                onClick={() => setShowTimeRangeDropdown(!showTimeRangeDropdown)}
                className="flex items-center gap-2 bg-[#141823] border border-[#1F2533] rounded-lg px-3.5 py-2.5 text-sm hover:border-[#00D9D9]/30 transition-colors"
              >
                <Calendar className="w-4 h-4 text-[#00D9D9]" />
                <span className="text-white">{timeRange}</span>
                <ChevronDown className={`w-3.5 h-3.5 text-[#8B95A7] transition-transform ${showTimeRangeDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showTimeRangeDropdown && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setShowTimeRangeDropdown(false)}
                  />
                  <div className="absolute right-0 top-full mt-2 w-48 bg-[#0D111B] border border-[#1F2533] rounded-lg shadow-2xl z-20 py-2">
                    {timeRangeOptions.map((option) => (
                      <button
                        key={option}
                        onClick={() => {
                          setTimeRange(option);
                          setShowTimeRangeDropdown(false);
                        }}
                        className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                          timeRange === option
                            ? "bg-[#00D9D9]/10 text-[#00D9D9]"
                            : "text-[#8B95A7] hover:bg-[#141823] hover:text-white"
                        }`}
                      >
                        {option}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Notifications */}
            <button className="w-10 h-10 rounded-lg bg-[#141823] border border-[#1F2533] flex items-center justify-center hover:border-[#00D9D9]/30 relative transition-colors">
              <Bell className="w-[18px] h-[18px] text-[#8B95A7]" />
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#EF4444] shadow-[0_0_8px_#EF4444]" />
            </button>

            {/* User */}
            <div className="relative flex items-center gap-2.5 pl-3 border-l border-[#1F2533]">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2.5 hover:opacity-80 transition-opacity"
              >
                <div className="w-9 h-9 rounded-full bg-gradient-to-br from-[#00D9D9] to-[#3B82F6] flex items-center justify-center text-xs font-bold text-[#0A0E17]">
                  JS
                </div>
                <div>
                  <div className="text-[13px] font-semibold text-white">John Smith</div>
                  <div className="text-[10px] text-[#8B95A7]">SOC Manager</div>
                </div>
                <ChevronDown className={`w-4 h-4 text-[#8B95A7] transition-transform ${showUserMenu ? 'rotate-180' : ''}`} />
              </button>

              {showUserMenu && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setShowUserMenu(false)}
                  />
                  <div className="absolute right-0 top-full mt-2 w-56 bg-[#0D111B] border border-[#1F2533] rounded-lg shadow-2xl z-20 py-2">
                    <div className="px-4 py-3 border-b border-[#1F2533]">
                      <div className="text-[13px] font-semibold text-white">John Smith</div>
                      <div className="text-[11px] text-[#8B95A7]">john.smith@quantumbridge.io</div>
                    </div>

                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        handleSidebarClick("help");
                      }}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-[#8B95A7] hover:bg-[#141823] hover:text-white transition-colors"
                    >
                      <HelpCircle className="w-4 h-4" />
                      <span>Help & Support</span>
                    </button>

                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        handleSidebarClick("settings");
                      }}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-[#8B95A7] hover:bg-[#141823] hover:text-white transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                      <span>Account Settings</span>
                    </button>

                    <div className="h-px bg-[#1F2533] my-2" />

                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        logout();
                      }}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Logout</span>
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Content area */}
        <div className="flex-1 overflow-auto p-6 space-y-6">
          {activeSection === "dashboard" ? (
            <>
              {/* ---------- TOP STAT CARDS ---------- */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
                <StatCard
                  icon={Target}
                  label="API Requests"
                  value="18,247"
                  change="+12.3%"
                  trend="up"
                  accent="text-[#00D9D9]"
                  iconBg="bg-[#00D9D9]/10"
                />
                <StatCard
                  icon={ShieldCheck}
                  label="Signatures Verified"
                  value="18,189"
                  change="+12.1%"
                  trend="up"
                  accent="text-[#34D399]"
                  iconBg="bg-[#10B981]/10"
                />
                <StatCard
                  icon={ShieldAlert}
                  label="Failed Verifications"
                  value="58"
                  change="-8.4%"
                  trend="down"
                  accent="text-[#FBBF24]"
                  iconBg="bg-[#F59E0B]/10"
                />
                <StatCard
                  icon={Timer}
                  label="Avg Response Time"
                  value="47ms"
                  change="-15.2%"
                  trend="down"
                  accent="text-[#60A5FA]"
                  iconBg="bg-[#3B82F6]/10"
                />
              </div>

              {/* ---------- THREAT ACTIVITY + CATEGORIES ---------- */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Quantum Activity Over Time */}
                <div className="lg:col-span-2 bg-[#141823] border border-[#1F2533] rounded-xl p-6">
                  <div className="flex items-start justify-between mb-6">
                    <div>
                      <h3 className="text-[15px] font-bold text-white">API Request Activity</h3>
                      <p className="text-[12px] text-[#8B95A7] mt-1">
                        Requests, verifications & failures across last 24h
                      </p>
                    </div>
                    <div className="flex items-center gap-4 text-xs">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#00D9D9]" />
                        <span className="text-[#8B95A7]">Requests</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                        <span className="text-[#8B95A7]">Verified</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
                        <span className="text-[#8B95A7]">Failed</span>
                      </div>
                    </div>
                  </div>
                  <div className="h-[280px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart
                        data={quantumActivityData}
                        margin={{ top: 5, right: 5, left: -10, bottom: 0 }}
                      >
                        <defs>
                          <linearGradient id="requestsGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#00D9D9" stopOpacity={0.5} />
                            <stop offset="100%" stopColor="#00D9D9" stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="verifiedGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#10B981" stopOpacity={0.4} />
                            <stop offset="100%" stopColor="#10B981" stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="failedGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#EF4444" stopOpacity={0.3} />
                            <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1F2533" vertical={false} />
                        <XAxis
                          dataKey="time"
                          stroke="#5A6478"
                          tick={{ fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          stroke="#5A6478"
                          tick={{ fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0D111B",
                            border: "1px solid #1F2533",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "#8B95A7" }}
                        />
                        <Area
                          type="monotone"
                          dataKey="requests"
                          stroke="#00D9D9"
                          strokeWidth={2.5}
                          fill="url(#requestsGrad)"
                        />
                        <Area
                          type="monotone"
                          dataKey="verified"
                          stroke="#10B981"
                          strokeWidth={2}
                          fill="url(#verifiedGrad)"
                        />
                        <Area
                          type="monotone"
                          dataKey="failed"
                          stroke="#EF4444"
                          strokeWidth={2}
                          fill="url(#failedGrad)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Signature Types Donut */}
                <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
                  <div className="mb-4">
                    <h3 className="text-[15px] font-bold text-white">Signature Distribution</h3>
                    <p className="text-[12px] text-[#8B95A7] mt-1">By cryptographic algorithm</p>
                  </div>
                  <div className="h-[180px] relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={signatureTypesData}
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={80}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {signatureTypesData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} stroke="none" />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0D111B",
                            border: "1px solid #1F2533",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <div className="text-[26px] font-bold text-white leading-none">18.2K</div>
                      <div className="text-[10px] text-[#8B95A7] uppercase tracking-wider mt-1">
                        Total
                      </div>
                    </div>
                    <div className="space-y-2.5 mt-5">
                      {signatureTypesData.map((c) => (
                        <div key={c.name} className="flex items-center justify-between text-[12px]">
                          <div className="flex items-center gap-2">
                            <div
                              className="w-2.5 h-2.5 rounded-sm"
                              style={{ backgroundColor: c.color }}
                            />
                            <span className="text-[#D1D5DB]">{c.name}</span>
                          </div>
                          <span className="font-semibold text-white">{c.value}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* ---------- INCIDENTS + TOP SOURCES ---------- */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Recent Verifications */}
                <div className="lg:col-span-2 bg-[#141823] border border-[#1F2533] rounded-xl">
                  <div className="flex items-center justify-between px-6 py-5 border-b border-[#1F2533]">
                    <div>
                      <h3 className="text-[15px] font-bold text-white">Recent Signature Verifications</h3>
                      <p className="text-[12px] text-[#8B95A7] mt-1">
                        Latest cryptographic verification events
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-1.5 text-[11px] text-[#34D399]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#34D399] animate-pulse" />
                        LIVE
                      </div>
                      <button
                        onClick={() => handleSidebarClick("verifications")}
                        className="text-[12px] text-[#00D9D9] hover:text-[#00F5F5] font-medium transition-colors"
                      >
                        View All →
                      </button>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-[11px] text-[#5A6478] uppercase tracking-wider border-b border-[#1F2533]">
                          <th className="text-left font-semibold px-6 py-3">Verification ID</th>
                          <th className="text-left font-semibold px-3 py-3">Result</th>
                          <th className="text-left font-semibold px-3 py-3">Type</th>
                          <th className="text-left font-semibold px-3 py-3">Endpoint</th>
                          <th className="text-left font-semibold px-3 py-3">Status</th>
                          <th className="text-left font-semibold px-3 py-3">Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentVerifications.map((i) => (
                          <tr
                            key={i.id}
                            onClick={() => console.log("Viewing verification:", i.id)}
                            className="border-b border-[#1F2533] last:border-0 hover:bg-[#0D111B] transition-colors cursor-pointer"
                          >
                            <td className="px-6 py-3.5 font-mono text-[12px] text-[#00D9D9]">
                              {i.id}
                            </td>
                            <td className="px-3 py-3.5">
                              <span
                                className={`text-[10px] uppercase tracking-wider font-bold px-2.5 py-1 rounded border ${
                                  severityStyles[i.severity]
                                }`}
                              >
                                {i.severity}
                              </span>
                            </td>
                            <td className="px-3 py-3.5 text-[13px] text-[#D1D5DB] font-medium">
                              {i.type}
                            </td>
                            <td className="px-3 py-3.5 font-mono text-[12px] text-[#8B95A7]">
                              {i.endpoint}
                            </td>
                            <td className="px-3 py-3.5">
                              <span className={`text-[12px] font-semibold ${statusStyles[i.status]}`}>
                                {i.status}
                              </span>
                            </td>
                            <td className="px-6 py-3.5 text-[12px] text-[#8B95A7]">
                              {i.time}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Top Endpoints */}
                <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <h3 className="text-[15px] font-bold text-white">Top API Endpoints</h3>
                      <p className="text-[12px] text-[#8B95A7] mt-1">By request volume</p>
                    </div>
                    <Globe className="w-4 h-4 text-[#00D9D9]" />
                  </div>
                  <div className="space-y-4">
                    {topEndpoints.map((s) => (
                      <div
                        key={s.name}
                        onClick={() => console.log("Viewing endpoint:", s.name)}
                        className="cursor-pointer hover:bg-[#0D111B]/50 p-2 rounded-lg transition-colors"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2.5">
                            <span className="text-[13px] text-white font-medium font-mono">{s.name}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-[11px] text-[#8B95A7]">{s.latency}ms</span>
                            <span className="text-[12px] font-semibold text-[#D1D5DB]">
                              {s.requests.toLocaleString()}
                            </span>
                          </div>
                        </div>
                        <div className="h-1.5 bg-[#0D111B] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${
                              s.status === "healthy"
                                ? "bg-gradient-to-r from-[#00D9D9] to-[#10B981]"
                                : s.status === "warning"
                                  ? "bg-gradient-to-r from-[#F59E0B] to-[#EF4444]"
                                  : "bg-gradient-to-r from-[#000000] to-[#000000]"
                            }`}
                            style={{ width: `${(s.requests / 5000) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* ---------- NETWORK TRAFFIC + SYSTEM HEALTH ---------- */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* API Request Analysis */}
                <div className="lg:col-span-2 bg-[#141823] border border-[#1F2533] rounded-xl p-6">
                  <div className="flex items-start justify-between mb-6">
                    <div>
                      <h3 className="text-[15px] font-bold text-white">API Request Analysis</h3>
                      <p className="text-[12px] text-[#8B95A7] mt-1">
                        Total requests, verified & rejected signatures
                      </p>
                    </div>
                    <div className="flex items-center gap-4 text-xs">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#00D9D9]" />
                        <span className="text-[#8B95A7]">Requests</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                        <span className="text-[#8B95A7]">Verified</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
                        <span className="text-[#8B95A7]">Rejected</span>
                      </div>
                    </div>
                  </div>
                  <div className="h-[240px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart
                        data={networkTrafficData}
                        margin={{ top: 5, right: 5, left: -10, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1F2533" vertical={false} />
                        <XAxis
                          dataKey="time"
                          stroke="#5A6478"
                          tick={{ fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          stroke="#5A6478"
                          tick={{ fontSize: 11 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0D111B",
                            border: "1px solid #1F2533",
                            borderRadius: "8px",
                            fontSize: "12px",
                          }}
                          labelStyle={{ color: "#8B95A7" }}
                        />
                        <Line
                          type="monotone"
                          dataKey="requests"
                          stroke="#00D9D9"
                          strokeWidth={2.5}
                          dot={{ fill: "#00D9D9", r: 3 }}
                          activeDot={{ r: 5 }}
                        />
                        <Line
                          type="monotone"
                          dataKey="verified"
                          stroke="#10B981"
                          strokeWidth={2.5}
                          dot={{ fill: "#10B981", r: 3 }}
                          activeDot={{ r: 5 }}
                        />
                        <Line
                          type="monotone"
                          dataKey="rejected"
                          stroke="#EF4444"
                          strokeWeight={2.5}
                          dot={{ fill: "#EF4444", r: 3 }}
                          activeDot={{ r: 5 }}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* System Health */}
                <div className="bg-[#141823] border border-[#1F2533] rounded-xl p-6">
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <h3 className="text-[15px] font-bold text-white">System Health</h3>
                      <p className="text-[12px] text-[#8B95A7] mt-1">Defense layer status</p>
                    </div>
                    <Cpu className="w-4 h-4 text-[#00D9D9]" />
                  </div>
                  <div className="space-y-4">
                    {systemHealthData.map((s) => (
                      <div key={s.name}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-[13px] text-white font-medium">{s.name}</span>
                          <span className="text-[13px] font-bold" style={{ color: s.fill }}>
                            {s.value}%
                          </span>
                        </div>
                        <div className="h-2 bg:#0D111B rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${s.value}%`,
                              backgroundColor: s.fill,
                              boxShadow: `0 0 8px ${s.fill}`,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Mini summary */}
                  <div className="mt-6 pt-5 border-t border-[#1F2533] grid grid-cols-2 gap-3">
                    <div className="bg:#0D111B rounded-lg p-3">
                      <div className="text-[10px] text-[#8B95A7] uppercase tracking-wider mb-1">
                        Uptime
                      </div>
                      <div className="text-[16px] font-bold text-[#34D399]">99.98%</div>
                    </div>
                    <div className="bg:#0D111B rounded-lg p-3">
                      <div className="text-[10px] text-[#8B95A7] uppercase tracking-wider mb-1">
                        Health
                      </div>
                      <div className="text-[16px] font-bold text-[#00D9D9]">93/100</div>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            renderSectionContent()
          )}
        </div>
      </main>
    </div>
  );
}
