import { useQuery } from '@tanstack/react-query';
import * as analyticsApi from '../api/analytics';
import type { ProxyLogsParams } from '../api/analytics';

// Query key factory for analytics
export const analyticsKeys = {
  all: ['analytics'] as const,
  summary: (orgId: string) => [...analyticsKeys.all, 'summary', orgId] as const,
  timeseries: (
    orgId: string,
    params: { startDate: string; endDate: string; granularity: 'hourly' | 'daily' }
  ) => [...analyticsKeys.all, 'timeseries', orgId, params] as const,
  logs: (orgId: string, params?: ProxyLogsParams) =>
    [...analyticsKeys.all, 'logs', orgId, params] as const,
};

/**
 * Hook to fetch analytics summary for an organization
 */
export function useAnalyticsSummary(orgId: string, options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: analyticsKeys.summary(orgId),
    queryFn: () => analyticsApi.getSummary(orgId),
    enabled: !!orgId,
    refetchInterval: options?.refetchInterval,
  });
}

/**
 * Hook to fetch timeseries data for charts
 */
export function useTimeseries(
  orgId: string,
  params: { startDate: string; endDate: string; granularity: 'hourly' | 'daily' }
) {
  return useQuery({
    queryKey: analyticsKeys.timeseries(orgId, params),
    queryFn: () => analyticsApi.getTimeseries(orgId, params),
    enabled: !!orgId && !!params.startDate && !!params.endDate,
  });
}

/**
 * Hook to fetch proxy logs with pagination and filtering
 */
export function useProxyLogs(orgId: string, params?: ProxyLogsParams) {
  return useQuery({
    queryKey: analyticsKeys.logs(orgId, params),
    queryFn: () => analyticsApi.getProxyLogs(orgId, params),
    enabled: !!orgId,
    placeholderData: (previousData) => previousData, // Keep previous data while fetching new page
  });
}

/**
 * Hook to export logs as CSV
 * Note: This is not a query hook since it triggers a download
 * Use this function directly in your component
 */
export async function exportLogsAsCSV(orgId: string) {
  const blob = await analyticsApi.exportLogs(orgId, 'csv');
  
  // Create download link
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `proxy-logs-${orgId}-${new Date().toISOString()}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}
