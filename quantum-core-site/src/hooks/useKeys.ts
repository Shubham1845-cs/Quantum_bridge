import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as keysApi from '../api/keys';

// Query key factory for key management
export const keyKeys = {
  all: ['keys'] as const,
  list: (orgId: string) => [...keyKeys.all, 'list', orgId] as const,
};

/**
 * Hook to fetch all key versions for an organization
 */
export function useKeys(orgId: string) {
  return useQuery({
    queryKey: keyKeys.list(orgId),
    queryFn: () => keysApi.getKeys(orgId),
    enabled: !!orgId,
  });
}

/**
 * Hook to manually rotate keys
 */
export function useRotateKeys(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => keysApi.rotateKeys(orgId),
    onSuccess: () => {
      // Invalidate keys to refetch updated key versions
      queryClient.invalidateQueries({ queryKey: keyKeys.list(orgId) });
    },
  });
}
