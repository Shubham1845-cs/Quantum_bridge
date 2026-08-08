import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import Modal from './Modal';
import Input from '../ui/Input';
import Button from '../ui/Button';
import { inviteMember } from '../../api/team';
import { useToast } from '../../hooks/useToast';

interface InviteMemberModalProps {
  isOpen: boolean;
  onClose: () => void;
  orgId: string;
}

export default function InviteMemberModal({ isOpen, onClose, orgId }: InviteMemberModalProps) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'admin' | 'viewer'>('viewer');
  const [error, setError] = useState('');
  
  const queryClient = useQueryClient();
  const toast = useToast();

  const inviteMutation = useMutation({
    mutationFn: () => inviteMember(orgId, { email, role }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['members', orgId] });
      toast.success('Invitation sent successfully');
      handleClose();
    },
    onError: (err: any) => {
      setError(err.response?.data?.error || 'Failed to send invitation');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!email || !email.includes('@')) {
      setError('Please enter a valid email address');
      return;
    }

    inviteMutation.mutate();
  };

  const handleClose = () => {
    if (!inviteMutation.isPending) {
      onClose();
      setEmail('');
      setRole('viewer');
      setError('');
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="Invite Team Member">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Email Address"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="colleague@example.com"
          error={error}
          autoFocus
        />

        <div>
          <label className="block text-sm font-medium text-white/60 mb-2">
            Role
          </label>
          <div className="space-y-2">
            <label className="flex items-center gap-3 p-3 rounded-lg border border-white/10 cursor-pointer hover:bg-white/[0.02] transition-colors">
              <input
                type="radio"
                name="role"
                value="admin"
                checked={role === 'admin'}
                onChange={(e) => setRole(e.target.value as 'admin')}
                className="text-cyber-cyan focus:ring-cyber-cyan focus:ring-offset-black"
              />
              <div>
                <div className="font-medium text-white">Admin</div>
                <div className="text-sm text-white/40">
                  Can manage endpoints, view analytics, and invite members
                </div>
              </div>
            </label>
            
            <label className="flex items-center gap-3 p-3 rounded-lg border border-white/10 cursor-pointer hover:bg-white/[0.02] transition-colors">
              <input
                type="radio"
                name="role"
                value="viewer"
                checked={role === 'viewer'}
                onChange={(e) => setRole(e.target.value as 'viewer')}
                className="text-cyber-cyan focus:ring-cyber-cyan focus:ring-offset-black"
              />
              <div>
                <div className="font-medium text-white">Viewer</div>
                <div className="text-sm text-white/40">
                  Can only view analytics and logs (read-only access)
                </div>
              </div>
            </label>
          </div>
        </div>

        <div className="flex gap-3 pt-4">
          <Button
            type="button"
            variant="secondary"
            onClick={handleClose}
            disabled={inviteMutation.isPending}
            className="flex-1"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            isLoading={inviteMutation.isPending}
            disabled={!email || inviteMutation.isPending}
            className="flex-1"
          >
            Send Invitation
          </Button>
        </div>
      </form>
    </Modal>
  );
}
