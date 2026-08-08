/**
 * LiveMonitoringSection Component
 * 
 * Real-time activity feed displaying API requests and signature verification events.
 * Implements dark cyberpunk theme with cyan accents.
 * 
 * Features:
 * - Auto-refresh with configurable intervals (5s, 10s, 30s, 60s)
 * - Pause/resume controls
 * - Real-time event feed with color-coded event types
 * - System health metrics with progress bars
 * - Network statistics cards
 * - Relative timestamps using date-fns
 * - Max 50 events display (oldest removed on new arrival)
 * - Mock data fallback when backend unavailable
 */

import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  Activity, 
  Pause, 
  Play, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertCircle,
  Server,
  Cpu,
  Shield,
  Network
} from 'lucide-react';
import { 
  mockMonitoringEvents, 
  mockSystemHealth, 
  mockNetworkStats,
  MonitoringEvent,
  SystemHealth
} from '@/mocks/monitoring';
import Badge from '@/components/ui/Badge';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';

type RefreshInterval = 5000 | 10000 | 30000 | 60000;

export default function LiveMonitoringSection() {
  const [refreshInterval, setRefreshInterval] = useState<RefreshInterval>(10000);
  const [isPaused, setIsPaused] = useState(false);
  const queryClient = useQueryClient();

  // Fetch monitoring events
  const { data: events = mockMonitoringEvents.slice(0, 50) } = useQuery<MonitoringEvent[]>({
    queryKey: ['monitoring'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      // For now, return mock data (first 50 events)
      return mockMonitoringEvents.slice(0, 50);
    },
    staleTime: refreshInterval,
    refetchInterval: isPaused ? false : refreshInterval,
    refetchOnWindowFocus: !isPaused,
  });

  // Fetch system health
  const { data: systemHealth = mockSystemHealth } = useQuery<SystemHealth>({
    queryKey: ['systemHealth'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      return mockSystemHealth;
    },
    staleTime: refreshInterval,
    refetchInterval: isPaused ? false : refreshInterval,
  });

  // Fetch network stats
  const { data: networkStats = mockNetworkStats } = useQuery({
    queryKey: ['networkStats'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      return mockNetworkStats;
    },
    staleTime: refreshInterval,
    refetchInterval: isPaused ? false : refreshInterval,
  });

  // Toggle pause/resume
  const togglePause = () => {
    setIsPaused((prev) => !prev);
  };

  // Get event type styling
  const getEventTypeStyles = (type: MonitoringEvent['type']) => {
    switch (type) {
      case 'api_request':
        return {
          bg: 'bg-[#3B82F6]/15',
          text: 'text-[#60A5FA]',
          border: 'border-[#3B82F6]/30',
          icon: Network,
        };
      case 'signature_verification':
        return {
          bg: 'bg-[#8B5CF6]/15',
          text: 'text-[#A78BFA]',
          border: 'border-[#8B5CF6]/30',
          icon: Shield,
        };
      case 'system_alert':
        return {
          bg: 'bg-[#F59E0B]/15',
          text: 'text-[#FBBF24]',
          border: 'border-[#F59E0B]/30',
          icon: AlertCircle,
        };
      default:
        return {
          bg: 'bg-[#8B95A7]/15',
          text: 'text-[#8B95A7]',
          border: 'border-[#8B95A7]/30',
          icon: Activity,
        };
    }
  };

  // Get verification result badge styling
  const getVerificationBadge = (result?: 'verified' | 'rejected' | 'pending') => {
    if (!result) return null;

    switch (result) {
      case 'verified':
        return (
          <Badge variant="success" className="ml-2 inline-flex items-center">
            <CheckCircle className="h-3 w-3 mr-1" />
            Verified
          </Badge>
        );
      case 'rejected':
        return (
          <Badge variant="danger" className="ml-2 inline-flex items-center">
            <XCircle className="h-3 w-3 mr-1" />
            Rejected
          </Badge>
        );
      case 'pending':
        return (
          <Badge variant="warning" className="ml-2 inline-flex items-center">
            <Clock className="h-3 w-3 mr-1" />
            Pending
          </Badge>
        );
    }
  };

  // Get status code color
  const getStatusCodeColor = (statusCode?: number) => {
    if (!statusCode) return 'text-[#8B95A7]';
    if (statusCode >= 200 && statusCode < 300) return 'text-[#10B981]';
    if (statusCode >= 400 && statusCode < 500) return 'text-[#F59E0B]';
    if (statusCode >= 500) return 'text-[#EF4444]';
    return 'text-[#8B95A7]';
  };

  return (
    <div className="space-y-6">
      {/* Header with controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="h-6 w-6 text-[#00D9D9]" />
            Live Monitoring
          </h2>
          <p className="text-[#8B95A7] text-sm mt-1">
            Real-time system activity and verification events
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Refresh interval selector */}
          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value) as RefreshInterval)}
            className="px-3 py-2 bg-[#141823] border border-white/[0.06] rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-[#00D9D9]/50 transition-all"
            disabled={isPaused}
          >
            <option value={5000}>5s refresh</option>
            <option value={10000}>10s refresh</option>
            <option value={30000}>30s refresh</option>
            <option value={60000}>60s refresh</option>
          </select>

          {/* Pause/Resume button */}
          <button
            onClick={togglePause}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all",
              isPaused
                ? "bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30 hover:bg-[#10B981]/25"
                : "bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30 hover:bg-[#F59E0B]/25"
            )}
          >
            {isPaused ? (
              <>
                <Play className="h-4 w-4" />
                <span className="hidden sm:inline">Resume</span>
              </>
            ) : (
              <>
                <Pause className="h-4 w-4" />
                <span className="hidden sm:inline">Pause</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* System Health Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Quantum Bridge */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-[#00D9D9]" />
              <span className="text-white font-medium">Quantum Bridge</span>
            </div>
            <span className="text-lg font-bold text-[#00D9D9]">{systemHealth.quantumBridge}%</span>
          </div>
          <div className="w-full bg-[#0A0E17] rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[#00D9D9] to-[#8B5CF6] transition-all duration-500"
              style={{ width: `${systemHealth.quantumBridge}%` }}
            />
          </div>
        </div>

        {/* ML-DSA-65 Engine */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-[#8B5CF6]" />
              <span className="text-white font-medium">ML-DSA-65</span>
            </div>
            <span className="text-lg font-bold text-[#8B5CF6]">{systemHealth.mlDsa65Engine}%</span>
          </div>
          <div className="w-full bg-[#0A0E17] rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-[#8B5CF6] transition-all duration-500"
              style={{ width: `${systemHealth.mlDsa65Engine}%` }}
            />
          </div>
        </div>

        {/* ECDSA P-256 Engine */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-[#10B981]" />
              <span className="text-white font-medium">ECDSA P-256</span>
            </div>
            <span className="text-lg font-bold text-[#10B981]">{systemHealth.ecdsaP256Engine}%</span>
          </div>
          <div className="w-full bg-[#0A0E17] rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-[#10B981] transition-all duration-500"
              style={{ width: `${systemHealth.ecdsaP256Engine}%` }}
            />
          </div>
        </div>

        {/* API Gateway */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Cpu className="h-5 w-5 text-[#3B82F6]" />
              <span className="text-white font-medium">API Gateway</span>
            </div>
            <span className="text-lg font-bold text-[#3B82F6]">{systemHealth.apiGateway}%</span>
          </div>
          <div className="w-full bg-[#0A0E17] rounded-full h-2 overflow-hidden">
            <div
              className="h-full bg-[#3B82F6] transition-all duration-500"
              style={{ width: `${systemHealth.apiGateway}%` }}
            />
          </div>
        </div>
      </div>

      {/* Network Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="text-[#8B95A7] text-sm mb-1">Total Requests</div>
          <div className="text-2xl font-bold text-white">{networkStats.totalRequests.toLocaleString()}</div>
        </div>

        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="text-[#8B95A7] text-sm mb-1">Verified</div>
          <div className="text-2xl font-bold text-[#10B981]">{networkStats.verified.toLocaleString()}</div>
        </div>

        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="text-[#8B95A7] text-sm mb-1">Rejected</div>
          <div className="text-2xl font-bold text-[#EF4444]">{networkStats.rejected.toLocaleString()}</div>
        </div>

        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="text-[#8B95A7] text-sm mb-1">Requests/Min</div>
          <div className="text-2xl font-bold text-[#00D9D9]">{networkStats.requestsPerMinute}</div>
        </div>

        <div className="bg-[#141823] border border-white/[0.06] rounded-lg p-4">
          <div className="text-[#8B95A7] text-sm mb-1">Avg Response</div>
          <div className="text-2xl font-bold text-[#8B5CF6]">{networkStats.averageResponseTime}ms</div>
        </div>
      </div>

      {/* Live Event Feed */}
      <div className="bg-[#141823] border border-white/[0.06] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-white/[0.06]">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Activity className="h-5 w-5 text-[#00D9D9]" />
            Live Activity Feed
            {isPaused && (
              <Badge variant="warning" className="ml-2">
                Paused
              </Badge>
            )}
          </h3>
          <p className="text-[#8B95A7] text-sm mt-1">
            Showing latest {events.length} events (max 50)
          </p>
        </div>

        <div className="divide-y divide-white/[0.06] max-h-[600px] overflow-y-auto">
          {events.map((event) => {
            const styles = getEventTypeStyles(event.type);
            const EventIcon = styles.icon;

            return (
              <div
                key={event._id}
                className="px-6 py-4 hover:bg-white/[0.02] transition-colors"
              >
                <div className="flex items-start gap-3">
                  {/* Event icon */}
                  <div className={cn(
                    "p-2 rounded-lg border mt-0.5",
                    styles.bg,
                    styles.border
                  )}>
                    <EventIcon className={cn("h-4 w-4", styles.text)} />
                  </div>

                  {/* Event details */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-white font-medium">{event.eventId}</span>
                        <Badge 
                          variant="info"
                          className={cn(styles.bg, styles.text, styles.border, "border")}
                        >
                          {event.type.replace('_', ' ').toUpperCase()}
                        </Badge>
                        {event.method && (
                          <Badge variant="info" className="font-mono text-xs">
                            {event.method}
                          </Badge>
                        )}
                        {event.statusCode && (
                          <span className={cn("font-mono text-sm font-medium", getStatusCodeColor(event.statusCode))}>
                            {event.statusCode}
                          </span>
                        )}
                        {getVerificationBadge(event.verificationResult)}
                      </div>
                      <div className="flex items-center text-xs text-[#8B95A7] whitespace-nowrap">
                        <Clock className="h-3 w-3 mr-1" />
                        {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                      </div>
                    </div>

                    {event.endpoint && (
                      <div className="text-[#8B95A7] text-sm font-mono mb-1">
                        {event.endpoint}
                      </div>
                    )}

                    <div className="flex items-center gap-4 text-xs text-[#8B95A7]">
                      {event.algorithm && (
                        <span>Algorithm: <span className="text-[#00D9D9]">{event.algorithm}</span></span>
                      )}
                      {event.duration !== undefined && (
                        <span>Duration: <span className="text-white">{event.duration}ms</span></span>
                      )}
                      {event.requestId && (
                        <span className="font-mono">Request: {event.requestId.substring(0, 8)}...</span>
                      )}
                    </div>

                    {event.errorMessage && (
                      <div className="mt-2 text-xs text-[#EF4444] bg-[#EF4444]/10 border border-[#EF4444]/30 rounded px-2 py-1">
                        {event.errorMessage}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
