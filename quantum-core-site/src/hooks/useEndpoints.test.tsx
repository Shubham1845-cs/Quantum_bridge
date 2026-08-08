import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  useEndpoints,
  useEndpoint,
  useCreateEndpoint,
  useUpdateEndpoint,
  useDeleteEndpoint,
  useRegenerateApiKey,
} from './useEndpoints';
import * as endpointsApi from '../api/endpoints';

vi.mock('../api/endpoints');

describe('useEndpoints hooks', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    vi.clearAllMocks();
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });
  });

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );

  describe('useEndpoints', () => {
    it('should fetch endpoints for an organization', async () => {
      const mockEndpoints = [
        { _id: 'ep1', name: 'API 1', orgId: 'org1', targetUrl: 'https://api1.com', proxySlug: 'api1', apiKey: 'key1', isActive: true, ipAllowlist: [], requestCount: 0, createdAt: '' },
      ];
      vi.mocked(endpointsApi.listEndpoints).mockResolvedValue(mockEndpoints);

      const { result } = renderHook(() => useEndpoints('org1'), { wrapper });

      await waitFor(() => {
        expect(result.current.data).toEqual(mockEndpoints);
      });

      expect(endpointsApi.listEndpoints).toHaveBeenCalledWith('org1');
    });

    it('should not fetch when orgId is empty', () => {
      const { result } = renderHook(() => useEndpoints(''), { wrapper });

      expect(result.current.data).toBeUndefined();
      expect(endpointsApi.listEndpoints).not.toHaveBeenCalled();
    });
  });

  describe('useEndpoint', () => {
    it('should fetch a single endpoint', async () => {
      const mockEndpoint = {
        _id: 'ep1',
        name: 'API 1',
        orgId: 'org1',
        targetUrl: 'https://api1.com',
        proxySlug: 'api1',
        apiKey: 'key1',
        isActive: true,
        ipAllowlist: [],
        requestCount: 0,
        createdAt: '',
      };
      vi.mocked(endpointsApi.getEndpoint).mockResolvedValue(mockEndpoint);

      const { result } = renderHook(() => useEndpoint('org1', 'ep1'), { wrapper });

      await waitFor(() => {
        expect(result.current.data).toEqual(mockEndpoint);
      });

      expect(endpointsApi.getEndpoint).toHaveBeenCalledWith('org1', 'ep1');
    });

    it('should not fetch when orgId or endpointId is empty', () => {
      const { result } = renderHook(() => useEndpoint('', 'ep1'), { wrapper });

      expect(result.current.data).toBeUndefined();
      expect(endpointsApi.getEndpoint).not.toHaveBeenCalled();
    });
  });

  describe('useCreateEndpoint', () => {
    it('should create a new endpoint', async () => {
      const newEndpoint = {
        _id: 'ep2',
        name: 'New API',
        orgId: 'org1',
        targetUrl: 'https://newapi.com',
        proxySlug: 'new-api',
        apiKey: 'key2',
        isActive: true,
        ipAllowlist: [],
        requestCount: 0,
        createdAt: '',
      };
      vi.mocked(endpointsApi.createEndpoint).mockResolvedValue(newEndpoint);

      const { result } = renderHook(() => useCreateEndpoint('org1'), { wrapper });

      const createData = {
        name: 'New API',
        targetUrl: 'https://newapi.com',
      };

      result.current.mutate(createData);

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(endpointsApi.createEndpoint).toHaveBeenCalledWith('org1', createData);
    });
  });

  describe('useUpdateEndpoint', () => {
    it('should update an endpoint', async () => {
      const updatedEndpoint = {
        _id: 'ep1',
        name: 'Updated API',
        orgId: 'org1',
        targetUrl: 'https://updated.com',
        proxySlug: 'updated-api',
        apiKey: 'key1',
        isActive: true,
        ipAllowlist: [],
        requestCount: 0,
        createdAt: '',
      };
      vi.mocked(endpointsApi.updateEndpoint).mockResolvedValue(updatedEndpoint);

      const { result } = renderHook(() => useUpdateEndpoint('org1', 'ep1'), { wrapper });

      const updates = { name: 'Updated API', targetUrl: 'https://updated.com' };
      result.current.mutate(updates);

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(endpointsApi.updateEndpoint).toHaveBeenCalledWith('org1', 'ep1', updates);
    });
  });

  describe('useDeleteEndpoint', () => {
    it('should delete an endpoint', async () => {
      vi.mocked(endpointsApi.deleteEndpoint).mockResolvedValue(undefined);

      const { result } = renderHook(() => useDeleteEndpoint('org1'), { wrapper });

      result.current.mutate('ep1');

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(endpointsApi.deleteEndpoint).toHaveBeenCalledWith('org1', 'ep1');
    });
  });

  describe('useRegenerateApiKey', () => {
    it('should regenerate API key', async () => {
      const newKey = { apiKey: 'new-key-123' };
      vi.mocked(endpointsApi.regenerateApiKey).mockResolvedValue(newKey);

      const { result } = renderHook(() => useRegenerateApiKey('org1', 'ep1'), { wrapper });

      result.current.mutate();

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(endpointsApi.regenerateApiKey).toHaveBeenCalledWith('org1', 'ep1');
    });
  });
});
