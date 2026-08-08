/**
 * AlertsSection Component
 * 
 * Displays and manages security alerts with filtering, search, status updates, and detail viewing.
 * Implements dark cyberpunk theme with cyan accents.
 * 
 * Features:
 * - Filter by priority (Critical, High, Medium, Low) and status (Active, Resolved, Dismissed)
 * - Debounced search (300ms) by alert ID, title, or endpoint
 * - Detail modal with full alert information
 * - Status update actions: "Mark as Resolved" and "Dismiss"
 * - Toast notifications for successful updates
 * - Responsive layout for mobile, tablet, and desktop
 * - Mock data fallback when backend unavailable
 */

import { useState, useMemo, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, Filter, AlertTriangle, CheckCircle, XCircle, Clock } from 'lucide-react';
import { mockAlerts, Alert } from '@/mocks/alerts';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import Button from '@/components/ui/Button';
import Badge from '@/components/ui/Badge';
import { useToast } from '@/hooks/useToast';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';

type PriorityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type StatusFilter = 'all' | 'active' | 'resolved' | 'dismissed';

export default function AlertsSection() {
  const [priorityFilter, setPriorityFilter] = useState<PriorityFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);

  // Debounce search query (300ms)
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearchQuery(searchQuery);
    }, 300);

    return () => {
      clearTimeout(handler);
    };
  }, [searchQuery]);

  const queryClient = useQueryClient();
  const toast = useToast();

  // Fetch alerts (using mock data as fallback)
  const { data: alerts = mockAlerts, isLoading } = useQuery<Alert[]>({
    queryKey: ['alerts'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      // For now, return mock data
      return mockAlerts;
    },
    staleTime: 30000, // 30 seconds
    refetchOnWindowFocus: true,
  });

  // Filter and search alerts
  const filteredAlerts = useMemo(() => {
    let filtered = [...alerts];

    // Filter by priority
    if (priorityFilter !== 'all') {
      filtered = filtered.filter((alert) => alert.priority === priorityFilter);
    }

    // Filter by status
    if (statusFilter !== 'all') {
      filtered = filtered.filter((alert) => alert.status === statusFilter);
    }

    // Search by alert ID, title, or endpoint (using debounced search query)
    if (debouncedSearchQuery.trim()) {
      const query = debouncedSearchQuery.toLowerCase();
      filtered = filtered.filter(
        (alert) =>
          alert.alertId.toLowerCase().includes(query) ||
          alert.title.toLowerCase().includes(query) ||
          alert.affectedEndpoint.toLowerCase().includes(query)
      );
    }

    // Sort by timestamp (newest first)
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return filtered;
  }, [alerts, priorityFilter, statusFilter, debouncedSearchQuery]);

  // Count active alerts for badge
  const activeAlertsCount = alerts.filter((alert) => alert.status === 'active').length;

  // Mutation for updating alert status
  const updateAlertMutation = useMutation({
    mutationFn: async ({
      alertId,
      status,
    }: {
      alertId: string;
      status: 'resolved' | 'dismissed';
    }) => {
      // TODO: Replace with actual API call
      // Simulate API delay
      await new Promise((resolve) => setTimeout(resolve, 500));

      // Update local mock data (for demo purposes)
      const alertIndex = mockAlerts.findIndex((a) => a._id === alertId);
      if (alertIndex !== -1) {
        mockAlerts[alertIndex].status = status;
        if (status === 'resolved') {
          mockAlerts[alertIndex].resolvedAt = new Date().toISOString();
          mockAlerts[alertIndex].resolvedBy = 'current-user';
        } else if (status === 'dismissed') {
          mockAlerts[alertIndex].dismissedAt = new Date().toISOString();
          mockAlerts[alertIndex].dismissedBy = 'current-user';
        }
      }

      return { alertId, status };
    },
    onSuccess: (data) => {
      // Invalidate alerts query to refresh data
      queryClient.invalidateQueries({ queryKey: ['alerts'] });

      // Show success toast
      const message =
        data.status === 'resolved'
          ? 'Alert marked as resolved'
          : 'Alert dismissed successfully';
      toast.success(message);

      // Close modal
      setShowDetailModal(false);
      setSelectedAlert(null);
    },
    onError: () => {
      toast.error('Failed to update alert status');
    },
  });

  // Handle alert row click
  const handleAlertClick = (alert: Alert) => {
    setSelectedAlert(alert);
    setShowDetailModal(true);
  };

  // Handle mark as resolved
  const handleMarkAsResolved = () => {
    if (selectedAlert) {
      updateAlertMutation.mutate({
        alertId: selectedAlert._id,
        status: 'resolved',
      });
    }
  };

  // Handle dismiss
  const handleDismiss = () => {
    if (selectedAlert) {
      updateAlertMutation.mutate({
        alertId: selectedAlert._id,
        status: 'dismissed',
      });
    }
  };

  // Get priority badge styling
  const getPriorityBadge = (priority: Alert['priority']) => {
    const styles = {
      critical: 'bg-[#EF4444]/15 text-[#FF6B6B] border-[#EF4444]/30',
      high: 'bg-[#F59E0B]/15 text-[#FBBF24] border-[#F59E0B]/30',
      medium: 'bg-[#3B82F6]/15 text-[#60A5FA] border-[#3B82F6]/30',
      low: 'bg-[#10B981]/15 text-[#34D399] border-[#10B981]/30',
    };

    return (
      <span
        className={cn(
          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border uppercase',
          styles[priority]
        )}
      >
        {priority}
      </span>
    );
  };

  // Get status badge styling
  const getStatusBadge = (status: Alert['status']) => {
    const styles = {
      active: 'bg-[#EF4444]/15 text-[#FF6B6B] border-[#EF4444]/30',
      resolved: 'bg-[#10B981]/15 text-[#34D399] border-[#10B981]/30',
      dismissed: 'bg-[#8B95A7]/15 text-[#8B95A7] border-[#8B95A7]/30',
    };

    const icons = {
      active: <AlertTriangle className="h-3 w-3 mr-1" />,
      resolved: <CheckCircle className="h-3 w-3 mr-1" />,
      dismissed: <XCircle className="h-3 w-3 mr-1" />,
    };

    return (
      <span
        className={cn(
          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border capitalize',
          styles[status]
        )}
      >
        {icons[status]}
        {status}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-[#0A0E17] p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">Security Alerts</h1>
              <p className="text-[#8B95A7]">
                Monitor and manage security alerts across your organization
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="danger" className="text-base px-4 py-2">
                {activeAlertsCount} Active
              </Badge>
            </div>
          </div>
        </div>

        {/* Filters and Search */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-xl p-4 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="md:col-span-1">
              <label htmlFor="search" className="block text-sm font-medium text-[#8B95A7] mb-2">
                Search
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-[#8B95A7]" />
                <input
                  id="search"
                  type="text"
                  placeholder="Alert ID, title, or endpoint..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white placeholder-[#8B95A7] focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent"
                />
              </div>
            </div>

            {/* Priority Filter */}
            <div>
              <label htmlFor="priority" className="block text-sm font-medium text-[#8B95A7] mb-2">
                <Filter className="inline h-4 w-4 mr-1" />
                Priority
              </label>
              <select
                id="priority"
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value as PriorityFilter)}
                className="w-full px-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent cursor-pointer"
              >
                <option value="all">All Priorities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Status Filter */}
            <div>
              <label htmlFor="status" className="block text-sm font-medium text-[#8B95A7] mb-2">
                <Filter className="inline h-4 w-4 mr-1" />
                Status
              </label>
              <select
                id="status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
                className="w-full px-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="active">Active</option>
                <option value="resolved">Resolved</option>
                <option value="dismissed">Dismissed</option>
              </select>
            </div>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-xl overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00D9D9]"></div>
              <span className="ml-3 text-[#8B95A7]">Loading alerts...</span>
            </div>
          ) : filteredAlerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12">
              <AlertTriangle className="h-12 w-12 text-[#8B95A7] mb-4" />
              <p className="text-[#8B95A7] text-lg">No alerts found</p>
              <p className="text-[#8B95A7] text-sm mt-2">
                Try adjusting your filters or search query
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-white/[0.06]">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Alert ID
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Priority
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Title
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Affected Endpoint
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Time
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {filteredAlerts.map((alert) => (
                    <tr
                      key={alert._id}
                      onClick={() => handleAlertClick(alert)}
                      className="hover:bg-white/[0.02] cursor-pointer transition-colors"
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-[#00D9D9] font-mono text-sm">{alert.alertId}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getPriorityBadge(alert.priority)}
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-white">{alert.title}</div>
                        <div className="text-sm text-[#8B95A7] truncate max-w-md">
                          {alert.description}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-[#8B95A7] font-mono">
                          {alert.affectedEndpoint}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getStatusBadge(alert.status)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center text-sm text-[#8B95A7]">
                          <Clock className="h-4 w-4 mr-1" />
                          {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Results count */}
        {filteredAlerts.length > 0 && (
          <div className="mt-4 text-center text-sm text-[#8B95A7]">
            Showing {filteredAlerts.length} of {alerts.length} alerts
          </div>
        )}
      </div>

      {/* Alert Detail Modal */}
      <Dialog open={showDetailModal} onOpenChange={setShowDetailModal}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <span className="text-[#00D9D9] font-mono">{selectedAlert?.alertId}</span>
              {selectedAlert && getPriorityBadge(selectedAlert.priority)}
              {selectedAlert && getStatusBadge(selectedAlert.status)}
            </DialogTitle>
            <DialogDescription>Alert Details and Actions</DialogDescription>
          </DialogHeader>

          {selectedAlert && (
            <div className="space-y-6">
              {/* Title */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Title</h3>
                <p className="text-white text-lg">{selectedAlert.title}</p>
              </div>

              {/* Description */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Description</h3>
                <p className="text-white">{selectedAlert.description}</p>
              </div>

              {/* Affected Endpoint */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Affected Endpoint</h3>
                <p className="text-[#00D9D9] font-mono">{selectedAlert.affectedEndpoint}</p>
              </div>

              {/* Timestamp */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Timestamp</h3>
                <p className="text-white">
                  {new Date(selectedAlert.timestamp).toLocaleString()}
                  <span className="text-[#8B95A7] ml-2">
                    ({formatDistanceToNow(new Date(selectedAlert.timestamp), { addSuffix: true })})
                  </span>
                </p>
              </div>

              {/* Metadata */}
              {selectedAlert.metadata && Object.keys(selectedAlert.metadata).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Additional Details</h3>
                  <div className="bg-[#0A0E17] border border-white/[0.06] rounded-lg p-4">
                    <pre className="text-sm text-white whitespace-pre-wrap font-mono">
                      {JSON.stringify(selectedAlert.metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* Resolution/Dismissal Info */}
              {selectedAlert.status === 'resolved' && selectedAlert.resolvedAt && (
                <div className="bg-[#10B981]/10 border border-[#10B981]/30 rounded-lg p-4">
                  <p className="text-[#34D399] text-sm">
                    <CheckCircle className="inline h-4 w-4 mr-1" />
                    Resolved {formatDistanceToNow(new Date(selectedAlert.resolvedAt), { addSuffix: true })}
                  </p>
                </div>
              )}

              {selectedAlert.status === 'dismissed' && selectedAlert.dismissedAt && (
                <div className="bg-[#8B95A7]/10 border border-[#8B95A7]/30 rounded-lg p-4">
                  <p className="text-[#8B95A7] text-sm">
                    <XCircle className="inline h-4 w-4 mr-1" />
                    Dismissed {formatDistanceToNow(new Date(selectedAlert.dismissedAt), { addSuffix: true })}
                  </p>
                </div>
              )}
            </div>
          )}

          <DialogFooter>
            <div className="flex gap-3 w-full justify-end">
              <Button variant="ghost" onClick={() => setShowDetailModal(false)}>
                Close
              </Button>
              {selectedAlert?.status === 'active' && (
                <>
                  <Button
                    variant="secondary"
                    onClick={handleDismiss}
                    isLoading={updateAlertMutation.isPending}
                    disabled={updateAlertMutation.isPending}
                  >
                    Dismiss
                  </Button>
                  <Button
                    variant="primary"
                    onClick={handleMarkAsResolved}
                    isLoading={updateAlertMutation.isPending}
                    disabled={updateAlertMutation.isPending}
                  >
                    Mark as Resolved
                  </Button>
                </>
              )}
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
