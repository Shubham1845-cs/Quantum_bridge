import { useState } from 'react';
import { motion } from 'framer-motion';
import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { listWebhooks, createWebhook, deleteWebhook, type Webhook } from '../../api/webhooks';
import { useToast } from '../../hooks/useToast';
import Badge from '../../components/ui/Badge';
import Button from '../../components/ui/Button';
import LoadingSpinner from '../../components/ui/LoadingSpinner';
import { formatDateTime } from '../../lib/utils';

export default function WebhooksPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [createError, setCreateError] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { data: webhooks, isLoading } = useQuery({
    queryKey: ['webhooks', orgId],
    queryFn: () => listWebhooks(orgId!),
    enabled: !!orgId,
  });

  const createMutation = useMutation({
    mutationFn: (url: string) => createWebhook(orgId!, url),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks', orgId] });
      setShowCreateModal(false);
      setNewWebhookUrl('');
      setCreateError('');
      toast.success('Webhook created successfully');
    },
    onError: (err: any) => {
      const status = err.response?.status;
      const message = err.response?.data?.error;
      
      if (status === 422) {
        setCreateError('Webhook URL must be a valid HTTPS endpoint.');
      } else {
        setCreateError(message || 'Failed to create webhook');
      }
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (webhookId: string) => deleteWebhook(orgId!, webhookId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks', orgId] });
      toast.success('Webhook deleted successfully');
      setDeletingId(null);
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to delete webhook');
      setDeletingId(null);
    },
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWebhookUrl.trim()) return;
    createMutation.mutate(newWebhookUrl);
  };

  const handleDelete = (webhook: Webhook) => {
    if (window.confirm(`Are you sure you want to delete this webhook?\n\n${webhook.url}`)) {
      setDeletingId(webhook._id);
      deleteMutation.mutate(webhook._id);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight mb-1">Webhooks</h2>
          <p className="text-white/40 text-sm">
            Configure HTTPS endpoints to receive automated threat alerts
          </p>
        </div>
        <Button
          onClick={() => setShowCreateModal(true)}
          variant="primary"
          size="sm"
        >
          + Add Webhook
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : webhooks?.length === 0 ? (
        <div className="p-8 text-center rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <div className="text-4xl mb-4">🔔</div>
          <p className="text-white/40 text-sm mb-4">
            No webhooks configured yet
          </p>
          <p className="text-white/30 text-xs mb-6">
            Webhooks allow you to receive real-time notifications when threats are detected
          </p>
          <Button onClick={() => setShowCreateModal(true)} variant="primary">
            Add Your First Webhook
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {webhooks?.map((webhook) => (
            <div
              key={webhook._id}
              className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] hover:border-white/10 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-white font-medium truncate">
                      {webhook.url}
                    </h3>
                    <Badge
                      variant={webhook.status === 'active' ? 'success' : 'danger'}
                    >
                      {webhook.status === 'active' ? 'Active' : 'Failed'}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-white/40">
                    <span>
                      Created {new Date(webhook.createdAt).toLocaleDateString()}
                    </span>
                    {webhook.lastDeliveryAt && (
                      <span>
                        Last delivery: {formatDateTime(webhook.lastDeliveryAt)}
                      </span>
                    )}
                  </div>
                </div>
                <Button
                  onClick={() => handleDelete(webhook)}
                  variant="danger"
                  size="sm"
                  isLoading={deletingId === webhook._id}
                  disabled={deletingId !== null}
                >
                  Delete
                </Button>
              </div>

              {webhook.status === 'failed' && (
                <div className="mt-4 p-3 rounded-lg bg-red-500/5 border border-red-500/20 text-red-400 text-xs">
                  ⚠️ This webhook is currently failing. Check your endpoint configuration.
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create Webhook Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-[#111111] border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-2xl"
          >
            <h3 className="text-xl font-bold mb-2">Add Webhook</h3>
            <p className="text-white/40 text-xs mb-6">
              Enter an HTTPS endpoint to receive threat notifications
            </p>

            {createError && (
              <div className="mb-4 text-red-400 text-sm bg-red-400/10 p-3 rounded-lg border border-red-500/20">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreate}>
              <div className="mb-6">
                <label className="block text-white/60 text-xs mb-2">
                  Webhook URL
                </label>
                <input
                  type="url"
                  required
                  value={newWebhookUrl}
                  onChange={(e) => setNewWebhookUrl(e.target.value)}
                  className="w-full bg-black border border-white/10 rounded-xl p-3 text-sm text-white placeholder-white/20 focus:border-cyber-cyan focus:outline-none transition-colors"
                  placeholder="https://your-domain.com/webhooks/quantumbridge"
                  autoFocus
                />
                <p className="mt-2 text-white/30 text-xs">
                  Must be a valid HTTPS URL
                </p>
              </div>
              <div className="flex justify-end gap-3">
                <Button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    setCreateError('');
                    setNewWebhookUrl('');
                  }}
                  variant="secondary"
                  size="sm"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  isLoading={createMutation.isPending}
                  disabled={!newWebhookUrl.trim() || createMutation.isPending}
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Webhook'}
                </Button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </motion.div>
  );
}
