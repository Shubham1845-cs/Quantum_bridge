import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as webhooksApi from '../api/webhooks';

// Query key factory for webhooks
export const webhookKeys = {
  all: ['webhooks'] as const,
  lists: () => [...webhookKeys.all, 'list'] as const,
  list: (orgId: string) => [...webhookKeys.lists(), orgId] as const,
  deliveries: (orgId: string, webhookId: string) =>
    [...webhookKeys.all, 'deliveries', orgId, webhookId] as const,
};

/**
 * Hook to fetch all webhooks for an organization
 */
export function useWebhooks(orgId: string) {
  return useQuery({
    queryKey: webhookKeys.list(orgId),
    queryFn: () => webhooksApi.listWebhooks(orgId),
    enabled: !!orgId,
  });
}

/**
 * Hook to fetch webhook delivery log
 */
export function useWebhookDeliveries(orgId: string, webhookId: string) {
  return useQuery({
    queryKey: webhookKeys.deliveries(orgId, webhookId),
    queryFn: () => webhooksApi.getWebhookDeliveries(orgId, webhookId),
    enabled: !!orgId && !!webhookId,
  });
}

/**
 * Hook to create a new webhook
 */
export function useCreateWebhook(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (url: string) => webhooksApi.createWebhook(orgId, url),
    onSuccess: () => {
      // Invalidate webhook list to refetch
      queryClient.invalidateQueries({ queryKey: webhookKeys.list(orgId) });
    },
  });
}

/**
 * Hook to delete a webhook
 */
export function useDeleteWebhook(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (webhookId: string) => webhooksApi.deleteWebhook(orgId, webhookId),
    onSuccess: (_, webhookId) => {
      // Remove deliveries from cache
      queryClient.removeQueries({ queryKey: webhookKeys.deliveries(orgId, webhookId) });
      // Invalidate webhook list
      queryClient.invalidateQueries({ queryKey: webhookKeys.list(orgId) });
    },
  });
}
