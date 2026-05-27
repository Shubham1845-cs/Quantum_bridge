import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as endpointsApi from '../api/endpoints';
import type { CreateEndpointRequest } from '../api/endpoints';

// Query key factory for consistent cache management
export const endpointKeys = {
  all: ['endpoints'] as const,
  lists: () => [...endpointKeys.all, 'list'] as const,
  list: (orgId: string) => [...endpointKeys.lists(), orgId] as const,
  details: () => [...endpointKeys.all, 'detail'] as const,
  detail: (orgId: string, endpointId: string) => [...endpointKeys.details(), orgId, endpointId] as const,
};

/**
 * Hook to fetch all endpoints for an organization
 */
export function useEndpoints(orgId: string) {
  return useQuery({
    queryKey: endpointKeys.list(orgId),
    queryFn: () => endpointsApi.listEndpoints(orgId),
    enabled: !!orgId,
  });
}

/**
 * Hook to fetch a single endpoint
 */
export function useEndpoint(orgId: string, endpointId: string) {
  return useQuery({
    queryKey: endpointKeys.detail(orgId, endpointId),
    queryFn: () => endpointsApi.getEndpoint(orgId, endpointId),
    enabled: !!orgId && !!endpointId,
  });
}

/**
 * Hook to create a new endpoint
 */
export function useCreateEndpoint(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateEndpointRequest) => endpointsApi.createEndpoint(orgId, data),
    onSuccess: () => {
      // Invalidate endpoint list to refetch
      queryClient.invalidateQueries({ queryKey: endpointKeys.list(orgId) });
    },
  });
}

/**
 * Hook to update an endpoint
 */
export function useUpdateEndpoint(orgId: string, endpointId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (updates: Partial<endpointsApi.Endpoint>) =>
      endpointsApi.updateEndpoint(orgId, endpointId, updates),
    onSuccess: (updatedEndpoint) => {
      // Update the specific endpoint in cache
      queryClient.setQueryData(endpointKeys.detail(orgId, endpointId), updatedEndpoint);
      // Invalidate list to ensure consistency
      queryClient.invalidateQueries({ queryKey: endpointKeys.list(orgId) });
    },
  });
}

/**
 * Hook to delete an endpoint
 */
export function useDeleteEndpoint(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (endpointId: string) => endpointsApi.deleteEndpoint(orgId, endpointId),
    onSuccess: (_, endpointId) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: endpointKeys.detail(orgId, endpointId) });
      // Invalidate list
      queryClient.invalidateQueries({ queryKey: endpointKeys.list(orgId) });
    },
  });
}

/**
 * Hook to regenerate an endpoint's API key
 */
export function useRegenerateApiKey(orgId: string, endpointId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => endpointsApi.regenerateApiKey(orgId, endpointId),
    onSuccess: () => {
      // Invalidate endpoint detail to refetch updated data
      queryClient.invalidateQueries({ queryKey: endpointKeys.detail(orgId, endpointId) });
    },
  });
}
