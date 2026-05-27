import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import Modal from './Modal';
import Input from '../ui/Input';
import Button from '../ui/Button';
import ApiKeyModal from './ApiKeyModal';
import { createEndpoint } from '../../api/endpoints';
import { useToast } from '../../hooks/useToast';

interface CreateEndpointModalProps {
  isOpen: boolean;
  onClose: () => void;
  orgId: string;
}

export default function CreateEndpointModal({ isOpen, onClose, orgId }: CreateEndpointModalProps) {
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [ipAllowlist, setIpAllowlist] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [apiKey, setApiKey] = useState<string | null>(null);
  
  const queryClient = useQueryClient();
  const toast = useToast();

  const createMutation = useMutation({
    mutationFn: () => createEndpoint(orgId, {
      name,
      targetUrl,
      ipAllowlist: ipAllowlist ? ipAllowlist.split(',').map(ip => ip.trim()).filter(Boolean) : undefined,
    }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['endpoints', orgId] });
      toast.success('Endpoint created successfully');
      setApiKey(data.apiKey);
    },
    onError: (err: any) => {
      if (err.response?.status === 402) {
        setErrors({ general: 'Plan limit reached. Please upgrade to add more endpoints.' });
      } else if (err.response?.status === 422) {
        setErrors({ targetUrl: 'Target URL must be a valid HTTPS URL' });
      } else {
        setErrors({ general: err.response?.data?.error || 'Failed to create endpoint' });
      }
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    const newErrors: Record<string, string> = {};
    
    if (!name || name.length < 3) {
      newErrors.name = 'Name must be at least 3 characters';
    }
    
    if (!targetUrl) {
      newErrors.targetUrl = 'Target URL is required';
    } else if (!targetUrl.startsWith('https://')) {
      newErrors.targetUrl = 'Target URL must use HTTPS';
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    createMutation.mutate();
  };

  const handleClose = () => {
    if (!createMutation.isPending) {
      onClose();
      setName('');
      setTargetUrl('');
      setIpAllowlist('');
      setErrors({});
    }
  };

  const handleApiKeyModalClose = () => {
    setApiKey(null);
    handleClose();
  };

  return (
    <>
      <Modal isOpen={isOpen && !apiKey} onClose={handleClose} title="Create Endpoint" maxWidth="lg">
        <form onSubmit={handleSubmit} className="space-y-4">
          {errors.general && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {errors.general}
            </div>
          )}

          <Input
            label="Endpoint Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My API"
            error={errors.name}
            helperText="A friendly name for this endpoint"
            autoFocus
          />

          <Input
            label="Target URL"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://api.example.com"
            error={errors.targetUrl}
            helperText="The HTTPS URL of your legacy API"
          />

          <div>
            <label className="block text-sm font-medium text-white/60 mb-2">
              IP Allowlist (Optional)
            </label>
            <textarea
              value={ipAllowlist}
              onChange={(e) => setIpAllowlist(e.target.value)}
              placeholder="192.168.1.1, 10.0.0.1"
              rows={3}
              className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-xl text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-cyber-cyan/50 focus:border-cyber-cyan resize-none"
            />
            <p className="mt-1 text-sm text-white/40">
              Comma-separated list of IP addresses allowed to access this endpoint
            </p>
          </div>

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
              disabled={!name || !targetUrl || createMutation.isPending}
              className="flex-1"
            >
              Create Endpoint
            </Button>
          </div>
        </form>
      </Modal>

      {apiKey && (
        <ApiKeyModal
          isOpen={!!apiKey}
          onClose={handleApiKeyModalClose}
          apiKey={apiKey}
        />
      )}
    </>
  );
}
