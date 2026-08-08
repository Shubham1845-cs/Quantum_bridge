import { useState } from 'react';
import { motion } from 'framer-motion';
import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Webhook, Bell, Trash2, AlertTriangle } from 'lucide-react';
import { listWebhooks, createWebhook, deleteWebhook, type Webhook as WebhookT } from '../../api/webhooks';
import { useToast } from '../../hooks/useToast';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime } from '../../lib/utils';
import { PageHeader } from '../../components/ui/PageHeader';
import { Card } from '../../components/ui/Card';
import { Modal } from '../../components/ui/Modal';
import Badge from '../../components/ui/Badge';
import Button from '../../components/ui/Button';
import LoadingSpinner from '../../components/ui/LoadingSpinner';

export default function WebhooksPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { loading: authLoading } = useAuth();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [createError, setCreateError] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { data: webhooks, isLoading } = useQuery({
    queryKey: ['webhooks', orgId],
    queryFn: () => listWebhooks(orgId!),
    enabled: !!orgId && !authLoading,
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
      if (status === 422) {
        setCreateError('Webhook URL must be a valid HTTPS endpoint.');
      } else {
        setCreateError(err.response?.data?.error || 'Failed to create webhook');
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

  const handleDelete = (webhook: WebhookT) => {
    if (window.confirm(`Are you sure you want to delete this webhook?\n\n${webhook.url}`)) {
      setDeletingId(webhook._id);
      deleteMutation.mutate(webhook._id);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
      <PageHeader
        title="Webhooks"
        description="Configure HTTPS endpoints to receive automated threat alerts"
        actions={
          <Button onClick={() => setShowCreateModal(true)} variant="primary" size="sm">
            <Bell size={15} className="mr-1.5" />
            Add Webhook
          </Button>
        }
      />

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : webhooks?.length === 0 ? (
        <Card className="p-16 text-center">
          <Webhook className="mx-auto mb-4 text-white/20" size={32} />
          <p className="mb-1 text-sm text-white/50">No webhooks configured yet</p>
          <p className="mb-6 text-xs text-white/30">Receive real-time notifications when threats are detected.</p>
          <Button onClick={() => setShowCreateModal(true)} variant="primary">Add Your First Webhook</Button>
        </Card>
      ) : (
        <div className="space-y-4">
          {webhooks?.map((webhook) => (
            <Card key={webhook._id} variant="interactive" className="p-6">
              <div className="mb-4 flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <div className="mb-2 flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-qb-cyan/20 bg-qb-cyan/5 text-qb-cyan">
                      <Webhook size={16} />
                    </div>
                    <h3 className="truncate font-medium text-white">{webhook.url}</h3>
                    <Badge variant={webhook.status === 'active' ? 'success' : 'danger'}>
                      {webhook.status === 'active' ? 'Active' : 'Failed'}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-white/40">
                    <span>Created {new Date(webhook.createdAt).toLocaleDateString()}</span>
                    {webhook.lastDeliveryAt && (
                      <span>Last delivery: {formatDateTime(webhook.lastDeliveryAt)}</span>
                    )}
                  </div>
                </div>
                <Button
                  onClick={() => handleDelete(webhook)}
                  variant="danger"
                  size="sm"
                  disabled={deletingId !== null}
                >
                  <Trash2 size={13} className="mr-1.5" />
                  {deletingId === webhook._id ? 'Deleting…' : 'Delete'}
                </Button>
              </div>

              {webhook.status === 'failed' && (
                <div className="mt-4 flex items-center gap-2 rounded-lg border border-qb-rose/20 bg-qb-rose/5 p-3 text-xs text-qb-rose">
                  <AlertTriangle size={14} />
                  This webhook is currently failing. Check your endpoint configuration.
                </div>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Create Webhook Modal */}
      <Modal
        open={showCreateModal}
        onOpenChange={(o) => {
          setShowCreateModal(o);
          if (!o) {
            setNewWebhookUrl('');
            setCreateError('');
          }
        }}
        title="Add Webhook"
        description="Enter an HTTPS endpoint to receive threat notifications"
        footer={
          <>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setShowCreateModal(false);
                setCreateError('');
                setNewWebhookUrl('');
              }}
            >
              Cancel
            </Button>
            <Button type="submit" form="create-webhook-form" variant="primary" size="sm" disabled={!newWebhookUrl.trim() || createMutation.isPending}>
              {createMutation.isPending ? 'Creating…' : 'Create Webhook'}
            </Button>
          </>
        }
      >
        {createError && (
          <div className="mb-4 rounded-lg border border-qb-rose/20 bg-qb-rose/5 p-3 text-sm text-qb-rose">{createError}</div>
        )}
        <form id="create-webhook-form" onSubmit={handleCreate} className="space-y-2">
          <label className="block text-xs text-white/60">Webhook URL</label>
          <input
            type="url"
            required
            value={newWebhookUrl}
            onChange={(e) => setNewWebhookUrl(e.target.value)}
            className="qb-input-focus w-full rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-white placeholder-white/20"
            placeholder="https://your-domain.com/webhooks/quantumbridge"
            autoFocus
          />
          <p className="text-xs text-white/30">Must be a valid HTTPS URL</p>
        </form>
      </Modal>
    </motion.div>
  );
}
