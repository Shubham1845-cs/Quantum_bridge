import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { OrgMember, removeMember } from '../../api/team';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { getRoleColor, getRoleDisplayName } from '../../lib/utils';
import { useToast } from '../../hooks/useToast';

interface MemberTableProps {
  members: OrgMember[];
  orgId: string;
  currentUserId?: string;
  currentUserRole?: 'owner' | 'admin' | 'viewer';
  isLoading?: boolean;
}

export default function MemberTable({
  members,
  orgId,
  currentUserId,
  currentUserRole,
  isLoading,
}: MemberTableProps) {
  const [removingId, setRemovingId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const toast = useToast();

  const removeMutation = useMutation({
    mutationFn: (userId: string) => removeMember(orgId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['members', orgId] });
      toast.success('Member removed successfully');
      setRemovingId(null);
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to remove member');
      setRemovingId(null);
    },
  });

  const handleRemove = (userId: string, email: string) => {
    if (window.confirm(`Are you sure you want to remove ${email} from this organization?`)) {
      setRemovingId(userId);
      removeMutation.mutate(userId);
    }
  };

  const canRemoveMember = (member: OrgMember) => {
    // Can't remove yourself
    if (member.userId._id === currentUserId) return false;
    // Only owners and admins can remove members
    if (currentUserRole === 'viewer') return false;
    // Owners can remove anyone, admins can't remove owners
    if (currentUserRole === 'admin' && member.role === 'owner') return false;
    return true;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-white/10">
      <table className="w-full text-sm">
        <thead className="bg-white/[0.02] border-b border-white/10">
          <tr className="text-left text-white/40">
            <th className="px-4 py-3 font-medium">Email</th>
            <th className="px-4 py-3 font-medium">Role</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Joined</th>
            <th className="px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {members.length === 0 ? (
            <tr>
              <td colSpan={5} className="px-4 py-8 text-center text-white/40">
                No members found
              </td>
            </tr>
          ) : (
            members.map((member) => {
              const email = member.inviteEmail || member.userId?.email || 'Unknown';
              const isCurrentUser = member.userId?._id === currentUserId;
              
              return (
                <tr
                  key={member._id}
                  className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-white/80">{email}</span>
                      {isCurrentUser && (
                        <span className="text-xs text-cyber-cyan">(You)</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      variant="default"
                      className={getRoleColor(member.role)}
                    >
                      {getRoleDisplayName(member.role)}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      variant={member.status === 'active' ? 'success' : 'warning'}
                    >
                      {member.status === 'active' ? 'Active' : 'Pending'}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-white/60">
                    {new Date(member.createdAt).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                  </td>
                  <td className="px-4 py-3">
                    {canRemoveMember(member) ? (
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => handleRemove(member.userId._id, email)}
                        isLoading={removingId === member.userId._id}
                        disabled={removingId !== null}
                      >
                        Remove
                      </Button>
                    ) : (
                      <span className="text-white/20 text-xs">—</span>
                    )}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
