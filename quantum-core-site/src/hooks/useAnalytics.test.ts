import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as analytics from './useAnalytics';
import * as analyticsApi from '../api/analytics';

vi.mock('../api/analytics');

describe('useAnalytics Hook', () => {
  const wrapper = ({ children }: { children: React.ReactNode }) => {
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('useAnalyticsSummary', () => {
    it('should fetch analytics summary', async () => {
      const mockOrgId = 'test-org-id';
      const mockSummary = {
        requestsToday: 1500,
        threatsToday: 5,
        avgLatency: 45,
        monthlyRequestCount: 45000,
        quota: 100000,
      };
      vi.mocked(analyticsApi.getSummary).mockResolvedValue(mockSummary);

      const { result } = renderHook(
        () => analytics.useAnalyticsSummary(mockOrgId),
        { wrapper }
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(analyticsApi.getSummary).toHaveBeenCalledWith(mockOrgId);
      expect(result.current.data).toEqual(mockSummary);
    });

    it('should be disabled and not fetch without an orgId', () => {
      const { result } = renderHook(() => analytics.useAnalyticsSummary(''), {
        wrapper,
      });

      // Should be disabled and not fetch
      expect(analyticsApi.getSummary).not.toHaveBeenCalled();
      expect(result.current.isFetching).toBe(false);
    });
  });

  describe('useTimeseries', () => {
    const mockOrgId = 'test-org-id';
    const mockParams = {
      startDate: '2023-01-01',
      endDate: '2023-01-02',
      granularity: 'hourly' as const,
    };

    it('should fetch timeseries data', async () => {
      const mockTimeseries = [
        {
          timestamp: '2023-01-01T00:00:00Z',
          requestCount: 100,
          ecdsaVerificationRate: 0.95,
          dilithiumVerificationRate: 0.88,
          threatFlagRate: 0.02,
        },
      ];
      vi.mocked(analyticsApi.getTimeseries).mockResolvedValue(mockTimeseries);

      const { result } = renderHook(
        () => analytics.useTimeseries(mockOrgId, mockParams),
        { wrapper }
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(analyticsApi.getTimeseries).toHaveBeenCalledWith(
        mockOrgId,
        mockParams
      );
      expect(result.current.data).toEqual(mockTimeseries);
    });

    it('should be disabled when missing required params', () => {
      const { result } = renderHook(
        () => analytics.useTimeseries('test-org', {
          startDate: '',
          endDate: '2023-01-02',
          granularity: 'hourly'
        }),
        { wrapper }
      );

      expect(analyticsApi.getTimeseries).not.toHaveBeenCalled();
      expect(result.current.isFetching).toBe(false);
    });
  });

  describe('useProxyLogs', () => {
    const mockOrgId = 'test-org-id';

    it('should fetch proxy logs', async () => {
      const mockLogsResponse = {
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
      vi.mocked(analyticsApi.getProxyLogs).mockResolvedValue(mockLogsResponse);

      const { result } = renderHook(
        () => analytics.useProxyLogs(mockOrgId),
        { wrapper }
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(analyticsApi.getProxyLogs).toHaveBeenCalledWith(
        mockOrgId,
        undefined
      );
      expect(result.current.data).toEqual(mockLogsResponse);
    });

    it('should pass params correctly', async () => {
      const mockParams = { page: 2, limit: 10, threatFlag: true };
      const mockLogsResponse = { logs: [], total: 0, page: 2, hasMore: false };
      vi.mocked(analyticsApi.getProxyLogs).mockResolvedValue(mockLogsResponse);

      const { result } = renderHook(
        () => analytics.useProxyLogs(mockOrgId, mockParams),
        { wrapper }
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(analyticsApi.getProxyLogs).toHaveBeenCalledWith(
        mockOrgId,
        mockParams
      );
    });
  });

  describe('exportLogsAsCSV', () => {
    const mockOrgId = 'test-org-id';

    it('should export logs as CSV', async () => {
      const mockBlob = new Blob(['col1,col2\nval1,val2'], { type: 'text/csv' });
      vi.mocked(analyticsApi.exportLogs).mockResolvedValue(mockBlob);

      // Mock browser APIs
      const createObjectURLSpy = vi.spyOn(URL, 'createObjectURL');
      const revokeObjectURLSpy = vi.spyOn(URL, 'revokeObjectURL');
      const appendChildSpy = vi.spyOn(Document.prototype, 'appendChild');
      const removeChildSpy = vi.spyOn(Document.prototype, 'removeChild');
      const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click');

      createObjectURLSpy.mockReturnValue('fake-url');
      appendChildSpy.mockReturnValue(undefined);
      removeChildSpy.mockReturnValue(undefined);

      await analytics.exportLogsAsCSV(mockOrgId);

      expect(analyticsApi.exportLogs).toHaveBeenCalledWith(mockOrgId, 'csv');
      expect(createObjectURLSpy).toHaveBeenCalledWith(mockBlob);
      expect(clickSpy).toHaveBeenCalled();
      expect(revokeObjectURLSpy).toHaveBeenCalledWith('fake-url');
    });
  });
});
