import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as analytics from './analytics';
import apiClient from './client';

vi.mock('./client');

describe('Analytics API', () => {
  const mockOrgId = 'test-org-id';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getSummary', () => {
    it('should fetch analytics summary', async () => {
      const mockResponse = {
        requestsToday: 1500,
        threatsToday: 5,
        avgLatency: 45.2,
        monthlyRequestCount: 45000,
        quota: 100000,
      };
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await analytics.getSummary(mockOrgId);

      expect(apiClient.get).toHaveBeenCalledWith(
        `/orgs/${mockOrgId}/analytics/summary`
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getTimeseries', () => {
    it('should fetch timeseries data', async () => {
      const mockResponse: any[] = [
        {
          timestamp: '2023-01-01T00:00:00Z',
          requestCount: 100,
          ecdsaVerificationRate: 0.95,
          dilithiumVerificationRate: 0.88,
          threatFlagRate: 0.02,
        },
        {
          timestamp: '2023-01-01T01:00:00Z',
          requestCount: 120,
          ecdsaVerificationRate: 0.93,
          dilithiumVerificationRate: 0.90,
          threatFlagRate: 0.01,
        },
      ];
      const params = { startDate: '2023-01-01', endDate: '2023-01-02', granularity: 'hourly' };
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await analytics.getTimeseries(mockOrgId, params);

      expect(apiClient.get).toHaveBeenCalledWith(
        `/orgs/${mockOrgId}/analytics/timeseries`,
        { params }
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getProxyLogs', () => {
    it('should fetch proxy logs with pagination', async () => {
      const mockResponse = {
        logs: [
          {
            _id: 'log1',
            requestId: 'req1',
            endpointId: 'ep1',
            timestamp: '2023-01-01T10:00:00Z',
            method: 'GET',
            path: '/api/test',
            statusCode: 200,
            latencyMs: 45,
            ecdsaVerified: true,
            dilithiumVerified: false,
            threatFlag: false,
            keyVersion: 1,
            clientIp: '192.168.1.1',
          },
        ],
        total: 1,
        page: 1,
        hasMore: false,
      };
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await analytics.getProxyLogs(mockOrgId, { page: 1, limit: 10 });

      expect(apiClient.get).toHaveBeenCalledWith(
        `/orgs/${mockOrgId}/logs`,
        { params: { page: 1, limit: 10 } }
      );
      expect(result).toEqual(mockResponse);
    });

    it('should fetch proxy logs with filters', async () => {
      const mockResponse = {
        logs: [],
        total: 0,
        page: 1,
        hasMore: false,
      };
      const params = {
        threatFlag: true,
        endpointId: 'ep1',
        startDate: '2023-01-01',
        endDate: '2023-01-02',
      };
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await analytics.getProxyLogs(mockOrgId, params);

      expect(apiClient.get).toHaveBeenCalledWith(
        `/orgs/${mockOrgId}/logs`,
        { params }
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('exportLogs', () => {
    it('should export logs as CSV blob', async () => {
      const mockBlob = new Blob(['col1,col2\nval1,val2'], { type: 'text/csv' });
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockBlob });

      const result = await analytics.exportLogs(mockOrgId, 'csv');

      expect(apiClient.get).toHaveBeenCalledWith(
        `/orgs/${mockOrgId}/logs/export`,
        {
          params: { format: 'csv' },
          responseType: 'blob',
        }
      );
      expect(result).toBe(mockBlob);
      expect(result.size).toBeGreaterThan(0);
    });
  });
});