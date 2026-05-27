import apiClient from './client';

export interface ProxyLog {
  _id: string;
  requestId: string;
  endpointId: string;
  timestamp: string;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
  keyVersion: number;
  clientIp: string;
}

export interface AnalyticsSummary {
  requestsToday: number;
  threatsToday: number;
  avgLatency: number;
  monthlyRequestCount: number;
  quota: number;
}

export interface TimeseriesDataPoint {
  timestamp: string;
  requestCount: number;
  ecdsaVerificationRate: number;
  dilithiumVerificationRate: number;
  threatFlagRate: number;
}

export interface ProxyLogsParams {
  page?: number;
  limit?: number;
  threatFlag?: boolean;
  endpointId?: string;
  startDate?: string;
  endDate?: string;
}

export interface ProxyLogsResponse {
  logs: ProxyLog[];
  total: number;
  page: number;
  hasMore: boolean;
}

/** GET /orgs/:orgId/analytics/summary — get summary metrics */
export async function getSummary(orgId: string): Promise<AnalyticsSummary> {
  const { data } = await apiClient.get<AnalyticsSummary>(`/orgs/${orgId}/analytics/summary`);
  return data;
}

/** GET /orgs/:orgId/analytics/timeseries — get timeseries data for charts */
export async function getTimeseries(
  orgId: string,
  params: { startDate: string; endDate: string; granularity: 'hourly' | 'daily' }
): Promise<TimeseriesDataPoint[]> {
  const { data } = await apiClient.get<TimeseriesDataPoint[]>(
    `/orgs/${orgId}/analytics/timeseries`,
    { params }
  );
  return data;
}

/** GET /orgs/:orgId/logs — get proxy logs with pagination and filtering */
export async function getProxyLogs(
  orgId: string,
  params?: ProxyLogsParams
): Promise<ProxyLogsResponse> {
  const { data } = await apiClient.get<ProxyLogsResponse>(`/orgs/${orgId}/logs`, { params });
  return data;
}

/** GET /orgs/:orgId/logs/export — export logs as CSV */
export async function exportLogs(orgId: string, format: 'csv' = 'csv'): Promise<Blob> {
  const { data } = await apiClient.get(`/orgs/${orgId}/logs/export`, {
    params: { format },
    responseType: 'blob',
  });
  return data;
}
