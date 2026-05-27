import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import Modal from './Modal';
import Input from '../ui/Input';
import Button from '../ui/Button';
import { createOrg } from '../../api/orgs';
import { useToast } from '../../hooks/useToast';

interface CreateOrgModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function CreateOrgModal({ isOpen, onClose }: CreateOrgModalProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();

  const createMutation = useMutation({
    mutationFn: createOrg,
    onSuccess: (org) => {
      queryClient.invalidateQueries({ queryKey: ['orgs'] });
      toast.success('Organization created successfully');
      onClose();
      setName('');
      setError('');
      navigate(`/org/${org._id}/overview`);
    },
    onError: (err: any) => {
      if (err.response?.status === 409) {
        setError('An organization with this name already exists');
      } else {
        setError(err.response?.data?.error || 'Failed to create organization');
      }
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (name.length < 3) {
      setError('Organization name must be at least 3 characters');
      return;
    }

    createMutation.mutate(name);
  };

  const handleClose = () => {
    if (!createMutation.isPending) {
      onClose();
      setName('');
      setError('');
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="Create Organization">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Organization Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My Organization"
          error={error}
          helperText="This will be used to generate your organization's unique URL"
          autoFocus
        />

        <div className="flex gap-3 pt-4">
          <Button
            type="button"
            variant="secondary"
            onClick={handleClose}
            disabled={createMutation.isPending}
            className="flex-1"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            isLoading={createMutation.isPending}
            disabled={!name || createMutation.isPending}
            className="flex-1"
          >
            Create Organization
          </Button>
        </div>
      </form>
    </Modal>
  );
}
