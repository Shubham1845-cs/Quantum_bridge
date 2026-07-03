/**
 * SignaturesSection Component
 * 
 * Manages cryptographic signatures with CRUD operations for ML-DSA-65 and ECDSA P-256 algorithms.
 * Implements dark cyberpunk theme with cyan accents.
 * 
 * Features:
 * - Filter by algorithm (ML-DSA-65, ECDSA P-256)
 * - Debounced search (300ms) by signature ID or endpoint name
 * - Create signature modal with endpoint selection and algorithm choice
 * - Detail modal with full signature information
 * - Revoke signature with confirmation dialog
 * - Toast notifications for mutations
 * - Optimistic updates with React Query
 * - Responsive layout for mobile, tablet, and desktop
 * - Mock data fallback when backend unavailable
 */

import { useState, useMemo, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, Filter, Plus, Shield, Key, Clock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { mockSignatures, Signature } from '@/mocks/signatures';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import Button from '@/components/ui/Button';
import Badge from '@/components/ui/Badge';
import { useToast } from '@/hooks/useToast';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';

type AlgorithmFilter = 'all' | 'ML-DSA-65' | 'ECDSA P-256';

interface CreateSignatureForm {
  endpointId: string;
  algorithm: 'ML-DSA-65' | 'ECDSA P-256';
}

// Mock endpoints for the dropdown
const mockEndpoints = [
  { id: 'ep-001', name: 'Production API' },
  { id: 'ep-002', name: 'Staging Gateway' },
  { id: 'ep-003', name: 'Development Server' },
  { id: 'ep-004', name: 'Payment Processor' },
  { id: 'ep-005', name: 'Authentication Service' },
  { id: 'ep-006', name: 'Data Pipeline' },
  { id: 'ep-007', name: 'Mobile API' },
  { id: 'ep-008', name: 'Web Dashboard' },
  { id: 'ep-009', name: 'Analytics Service' },
  { id: 'ep-010', name: 'Notification Service' },
];

export default function SignaturesSection() {
  const [algorithmFilter, setAlgorithmFilter] = useState<AlgorithmFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [selectedSignature, setSelectedSignature] = useState<Signature | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showRevokeDialog, setShowRevokeDialog] = useState(false);
  const [createFormData, setCreateFormData] = useState<CreateSignatureForm>({
    endpointId: '',
    algorithm: 'ML-DSA-65',
  });

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

  // Fetch signatures (using mock data as fallback)
  const { data: signatures = mockSignatures, isLoading } = useQuery<Signature[]>({
    queryKey: ['signatures'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      // For now, return mock data
      return mockSignatures;
    },
    staleTime: 30000, // 30 seconds
    refetchOnWindowFocus: true,
  });

  // Filter and search signatures
  const filteredSignatures = useMemo(() => {
    let filtered = [...signatures];

    // Filter by algorithm
    if (algorithmFilter !== 'all') {
      filtered = filtered.filter((sig) => sig.algorithm === algorithmFilter);
    }

    // Search by signature ID or endpoint name (using debounced search query)
    if (debouncedSearchQuery.trim()) {
      const query = debouncedSearchQuery.toLowerCase();
      filtered = filtered.filter(
        (sig) =>
          sig.signatureId.toLowerCase().includes(query) ||
          sig.endpointName.toLowerCase().includes(query)
      );
    }

    // Sort: active first, then by creation date (newest first)
    filtered.sort((a, b) => {
      if (a.isActive && !b.isActive) return -1;
      if (!a.isActive && b.isActive) return 1;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });

    return filtered;
  }, [signatures, algorithmFilter, debouncedSearchQuery]);

  // Statistics
  const activeCount = signatures.filter((s) => s.isActive).length;
  const revokedCount = signatures.filter((s) => s.isRevoked).length;
  const expiredCount = signatures.filter((s) => !s.isActive && !s.isRevoked).length;

  // Create signature mutation with optimistic update
  const createSignatureMutation = useMutation({
    mutationFn: async (formData: CreateSignatureForm) => {
      // TODO: Replace with actual API call
      // Simulate API delay
      await new Promise((resolve) => setTimeout(resolve, 800));

      const selectedEndpoint = mockEndpoints.find((ep) => ep.id === formData.endpointId);
      const newSignature: Signature = {
        _id: `sig-${Date.now()}`,
        signatureId: `SIG-${1000 + signatures.length + 1}`,
        algorithm: formData.algorithm,
        endpointId: formData.endpointId,
        endpointName: selectedEndpoint?.name ?? 'Unknown',
        publicKeyHash: `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
        privateKeyHash: `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
        isActive: true,
        isRevoked: false,
      };

      // Add to mock data (for demo purposes)
      mockSignatures.unshift(newSignature);

      return newSignature;
    },
    onMutate: async (formData) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['signatures'] });

      // Snapshot previous value
      const previousSignatures = queryClient.getQueryData<Signature[]>(['signatures']);

      // Optimistically update
      const selectedEndpoint = mockEndpoints.find((ep) => ep.id === formData.endpointId);
      const optimisticSignature: Signature = {
        _id: `sig-optimistic-${Date.now()}`,
        signatureId: `SIG-${1000 + (previousSignatures?.length ?? signatures.length) + 1}`,
        algorithm: formData.algorithm,
        endpointId: formData.endpointId,
        endpointName: selectedEndpoint?.name ?? 'Unknown',
        publicKeyHash: 'pending...',
        privateKeyHash: 'pending...',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
        isActive: true,
        isRevoked: false,
      };

      queryClient.setQueryData<Signature[]>(['signatures'], (old) =>
        old ? [optimisticSignature, ...old] : [optimisticSignature]
      );

      return { previousSignatures };
    },
    onSuccess: (newSignature) => {
      // Replace optimistic signature with real one
      queryClient.setQueryData<Signature[]>(['signatures'], (old) =>
        old
          ? old.map((s) => (s._id.startsWith('sig-optimistic-') ? newSignature : s))
          : [newSignature]
      );

      toast.success(`Signature ${newSignature.signatureId} created successfully`);
      setShowCreateModal(false);
      resetCreateForm();
    },
    onError: (_error, _formData, context) => {
      // Rollback to previous state
      if (context?.previousSignatures) {
        queryClient.setQueryData(['signatures'], context.previousSignatures);
      }
      toast.error('Failed to create signature');
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
  });

  // Revoke signature mutation with optimistic update
  const revokeSignatureMutation = useMutation({
    mutationFn: async ({ signatureId }: { signatureId: string }) => {
      // TODO: Replace with actual API call
      await new Promise((resolve) => setTimeout(resolve, 500));

      // Update local mock data
      const sigIndex = mockSignatures.findIndex((s) => s._id === signatureId);
      if (sigIndex !== -1) {
        mockSignatures[sigIndex].isRevoked = true;
        mockSignatures[sigIndex].isActive = false;
        mockSignatures[sigIndex].revokedAt = new Date().toISOString();
        mockSignatures[sigIndex].revokedBy = 'current-user';
        mockSignatures[sigIndex].revokedReason = 'Manually revoked by admin';
      }

      return { signatureId };
    },
    onMutate: async ({ signatureId }) => {
      await queryClient.cancelQueries({ queryKey: ['signatures'] });

      const previousSignatures = queryClient.getQueryData<Signature[]>(['signatures']);

      // Optimistically update
      queryClient.setQueryData<Signature[]>(['signatures'], (old) =>
        old
          ? old.map((s) =>
              s._id === signatureId
                ? {
                    ...s,
                    isRevoked: true,
                    isActive: false,
                    revokedAt: new Date().toISOString(),
                    revokedBy: 'current-user',
                    revokedReason: 'Manually revoked by admin',
                  }
                : s
            )
          : old
      );

      return { previousSignatures };
    },
    onSuccess: () => {
      toast.success('Signature revoked successfully');
      setShowRevokeDialog(false);
      setShowDetailModal(false);
      setSelectedSignature(null);
    },
    onError: (_error, _variables, context) => {
      if (context?.previousSignatures) {
        queryClient.setQueryData(['signatures'], context.previousSignatures);
      }
      toast.error('Failed to revoke signature');
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
  });

  // Reset create form
  const resetCreateForm = () => {
    setCreateFormData({
      endpointId: '',
      algorithm: 'ML-DSA-65',
    });
  };

  // Handle create form field changes
  const handleCreateFormChange = (field: keyof CreateSignatureForm, value: string) => {
    setCreateFormData((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  // Handle signature row click (detail view)
  const handleSignatureClick = (signature: Signature) => {
    setSelectedSignature(signature);
    setShowDetailModal(true);
  };

  // Handle create form submit
  const handleCreateSubmit = () => {
    if (!createFormData.endpointId) {
      toast.error('Please select an endpoint');
      return;
    }
    createSignatureMutation.mutate(createFormData);
  };

  // Handle revoke confirmation
  const handleRevokeConfirm = () => {
    if (selectedSignature) {
      revokeSignatureMutation.mutate({ signatureId: selectedSignature._id });
    }
  };

  // Get algorithm badge
  const getAlgorithmBadge = (algorithm: Signature['algorithm']) => {
    const styles = {
      'ML-DSA-65': 'bg-[#00D9D9]/15 text-[#00D9D9] border-[#00D9D9]/30',
      'ECDSA P-256': 'bg-[#F59E0B]/15 text-[#FBBF24] border-[#F59E0B]/30',
    };

    const icons = {
      'ML-DSA-65': <Shield className="h-3 w-3 mr-1" />,
      'ECDSA P-256': <Key className="h-3 w-3 mr-1" />,
    };

    return (
      <span
        className={cn(
          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
          styles[algorithm]
        )}
      >
        {icons[algorithm]}
        {algorithm}
      </span>
    );
  };

  // Get status badge
  const getStatusBadge = (signature: Signature) => {
    if (signature.isRevoked) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-[#EF4444]/15 text-[#FF6B6B] border-[#EF4444]/30">
          <XCircle className="h-3 w-3 mr-1" />
          Revoked
        </span>
      );
    }

    const isExpired = new Date(signature.expiresAt).getTime() < Date.now();
    if (isExpired && !signature.isActive) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-[#8B95A7]/15 text-[#8B95A7] border-[#8B95A7]/30">
          <Clock className="h-3 w-3 mr-1" />
          Expired
        </span>
      );
    }

    if (signature.isActive) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-[#10B981]/15 text-[#34D399] border-[#10B981]/30">
          <CheckCircle className="h-3 w-3 mr-1" />
          Active
        </span>
      );
    }

    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-[#8B95A7]/15 text-[#8B95A7] border-[#8B95A7]/30">
        Unknown
      </span>
    );
  };
