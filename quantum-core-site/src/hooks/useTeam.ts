import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as teamApi from '../api/team';

// Query key factory for team management
export const teamKeys = {
  all: ['team'] as const,
  list: (orgId: string) => [...teamKeys.all, 'list', orgId] as const,
};

/**
 * Hook to fetch all members of an organization
 */
export function useTeamMembers(orgId: string) {
  return useQuery({
    queryKey: teamKeys.list(orgId),
    queryFn: () => teamApi.listMembers(orgId),
    enabled: !!orgId,
  });
}

/**
 * Hook to invite a new member
 */
export function useInviteMember(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (inviteData: { email: string; role: 'admin' | 'viewer' }) =>
      teamApi.inviteMember(orgId, inviteData),
    onSuccess: () => {
      // Invalidate team list to refetch with new member
      queryClient.invalidateQueries({ queryKey: teamKeys.list(orgId) });
    },
  });
}

/**
 * Hook to remove a member
 */
export function useRemoveMember(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (userId: string) => teamApi.removeMember(orgId, userId),
    onSuccess: () => {
      // Invalidate team list to refetch
      queryClient.invalidateQueries({ queryKey: teamKeys.list(orgId) });
    },
  });
}

/**
 * Hook to update a member's role
 */
export function useUpdateMemberRole(orgId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: 'admin' | 'viewer' }) =>
      teamApi.updateMemberRole(orgId, userId, role),
    onSuccess: () => {
      // Invalidate team list to refetch with updated role
      queryClient.invalidateQueries({ queryKey: teamKeys.list(orgId) });
    },
  });
}
