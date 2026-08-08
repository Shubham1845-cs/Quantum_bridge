/**
 * VerificationsSection Component
 * 
 * Historical audit of signature verification requests with search, filtering, pagination, and CSV export.
 * Implements dark cyberpunk theme with cyan accents.
 * 
 * Features:
 * - Filter by result status (Verified, Rejected, Pending)
 * - Search by verification ID or endpoint
 * - Date range filtering
 * - Sortable table columns (timestamp, endpoint, algorithm, result)
 * - Pagination with configurable page size (10, 25, 50, 100)
 * - CSV export of current filtered view
 * - Detail modal with full verification data
 * - Responsive layout for mobile, tablet, and desktop
 * - Mock data fallback when backend unavailable
 */

import { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Search, 
  Filter, 
  Download, 
  ChevronLeft, 
  ChevronRight, 
  ChevronsLeft, 
  ChevronsRight,
  ArrowUp,
  ArrowDown,
  CheckCircle,
  XCircle,
  Clock,
  Calendar
} from 'lucide-react';
import { mockVerifications, Verification } from '@/mocks/verifications';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import Button from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';

type ResultFilter = 'all' | 'verified' | 'rejected' | 'pending';
type SortColumn = 'timestamp' | 'endpoint' | 'algorithm' | 'result';
type SortDirection = 'asc' | 'desc';
type PageSize = 10 | 25 | 50 | 100;

export default function VerificationsSection() {
  const [resultFilter, setResultFilter] = useState<ResultFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [dateRange, setDateRange] = useState<{ start: string; end: string } | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState<PageSize>(25);
  const [sortColumn, setSortColumn] = useState<SortColumn>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [selectedVerification, setSelectedVerification] = useState<Verification | null>(null);
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

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [resultFilter, debouncedSearchQuery, dateRange, pageSize]);

  // Fetch verifications (using mock data as fallback)
  const { data: verifications = mockVerifications, isLoading } = useQuery<Verification[]>({
    queryKey: ['verifications'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      // For now, return mock data
      return mockVerifications;
    },
    staleTime: 30000, // 30 seconds
  });

  // Filter, search, and sort verifications
  const filteredAndSortedVerifications = useMemo(() => {
    let filtered = [...verifications];

    // Filter by result status
    if (resultFilter !== 'all') {
      filtered = filtered.filter((verification) => verification.result === resultFilter);
    }

    // Search by verification ID or endpoint (using debounced search query)
    if (debouncedSearchQuery.trim()) {
      const query = debouncedSearchQuery.toLowerCase();
      filtered = filtered.filter(
        (verification) =>
          verification.verificationId.toLowerCase().includes(query) ||
          verification.endpoint.toLowerCase().includes(query)
      );
    }

    // Filter by date range
    if (dateRange) {
      const startTime = new Date(dateRange.start).getTime();
      const endTime = new Date(dateRange.end).getTime();
      filtered = filtered.filter((verification) => {
        const timestamp = new Date(verification.timestamp).getTime();
        return timestamp >= startTime && timestamp <= endTime;
      });
    }

    // Sort by selected column
    filtered.sort((a, b) => {
      let comparison = 0;

      switch (sortColumn) {
        case 'timestamp':
          comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
          break;
        case 'endpoint':
          comparison = a.endpoint.localeCompare(b.endpoint);
          break;
        case 'algorithm':
          comparison = a.algorithm.localeCompare(b.algorithm);
          break;
        case 'result':
          comparison = a.result.localeCompare(b.result);
          break;
      }

      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [verifications, resultFilter, debouncedSearchQuery, dateRange, sortColumn, sortDirection]);

  // Paginate results
  const totalPages = Math.ceil(filteredAndSortedVerifications.length / pageSize);
  const paginatedVerifications = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return filteredAndSortedVerifications.slice(startIndex, endIndex);
  }, [filteredAndSortedVerifications, currentPage, pageSize]);

  // Handle column sort
  const handleSort = (column: SortColumn) => {
    if (sortColumn === column) {
      // Toggle direction if same column
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new column with default descending
      setSortColumn(column);
      setSortDirection('desc');
    }
  };

  // Handle verification row click
  const handleVerificationClick = (verification: Verification) => {
    setSelectedVerification(verification);
    setShowDetailModal(true);
  };

  // Export to CSV
  const exportToCSV = () => {
    const headers = ['Verification ID', 'Timestamp', 'Endpoint', 'Algorithm', 'Result', 'Signature Hash', 'Response Time (ms)', 'Error Code', 'Error Details'];
    const rows = filteredAndSortedVerifications.map(v => [
      v.verificationId,
      new Date(v.timestamp).toISOString(),
      v.endpoint,
      v.algorithm,
      v.result,
      v.signatureHash,
      v.responseTime?.toString() || '',
      v.errorCode || '',
      v.errorDetails || ''
    ]);

    const csvContent = [headers, ...rows]
      .map(row => row.map(cell => `"${cell}"`).join(','))
      .join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `verifications-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Get result badge styling
  const getResultBadge = (result: Verification['result']) => {
    const styles = {
      verified: 'bg-[#10B981]/15 text-[#34D399] border-[#10B981]/30',
      rejected: 'bg-[#EF4444]/15 text-[#FF6B6B] border-[#EF4444]/30',
      pending: 'bg-[#F59E0B]/15 text-[#FBBF24] border-[#F59E0B]/30',
    };

    const icons = {
      verified: <CheckCircle className="h-3 w-3 mr-1" />,
      rejected: <XCircle className="h-3 w-3 mr-1" />,
      pending: <Clock className="h-3 w-3 mr-1" />,
    };

    return (
      <span
        className={cn(
          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border capitalize',
          styles[result]
        )}
      >
        {icons[result]}
        {result}
      </span>
    );
  };

  // Get algorithm badge styling
  const getAlgorithmBadge = (algorithm: Verification['algorithm']) => {
    const styles = {
      'ML-DSA-65': 'bg-[#8B5CF6]/15 text-[#A78BFA] border-[#8B5CF6]/30',
      'ECDSA P-256': 'bg-[#00D9D9]/15 text-[#00D9D9] border-[#00D9D9]/30',
      'Dual': 'bg-[#3B82F6]/15 text-[#60A5FA] border-[#3B82F6]/30',
    };

    return (
      <span
        className={cn(
          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
          styles[algorithm]
        )}
      >
        {algorithm}
      </span>
    );
  };

  // Render sort icon
  const renderSortIcon = (column: SortColumn) => {
    if (sortColumn !== column) return null;

    return sortDirection === 'asc' ? (
      <ArrowUp className="h-4 w-4 ml-1 inline" />
    ) : (
      <ArrowDown className="h-4 w-4 ml-1 inline" />
    );
  };

  return (
    <div className="min-h-screen bg-[#0A0E17] p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">Verification History</h1>
              <p className="text-[#8B95A7]">
                Historical audit of signature verification requests
              </p>
            </div>
            <Button
              variant="primary"
              onClick={exportToCSV}
              className="flex items-center gap-2"
              disabled={filteredAndSortedVerifications.length === 0}
            >
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
          </div>
        </div>

        {/* Filters and Search */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-xl p-4 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div>
              <label htmlFor="search" className="block text-sm font-medium text-[#8B95A7] mb-2">
                Search
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-[#8B95A7]" />
                <input
                  id="search"
                  type="text"
                  placeholder="Verification ID or endpoint..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white placeholder-[#8B95A7] focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent"
                />
              </div>
            </div>

            {/* Result Filter */}
            <div>
              <label htmlFor="result" className="block text-sm font-medium text-[#8B95A7] mb-2">
                <Filter className="inline h-4 w-4 mr-1" />
                Result Status
              </label>
              <select
                id="result"
                value={resultFilter}
                onChange={(e) => setResultFilter(e.target.value as ResultFilter)}
                className="w-full px-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent cursor-pointer"
              >
                <option value="all">All Results</option>
                <option value="verified">Verified</option>
                <option value="rejected">Rejected</option>
                <option value="pending">Pending</option>
              </select>
            </div>

            {/* Date Range - Simplified for now */}
            <div>
              <label htmlFor="dateRange" className="block text-sm font-medium text-[#8B95A7] mb-2">
                <Calendar className="inline h-4 w-4 mr-1" />
                Date Range
              </label>
              <select
                id="dateRange"
                onChange={(e) => {
                  const value = e.target.value;
                  if (value === 'all') {
                    setDateRange(null);
                  } else {
                    const now = new Date();
                    const days = parseInt(value);
                    const start = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
                    setDateRange({
                      start: start.toISOString(),
                      end: now.toISOString(),
                    });
                  }
                }}
                className="w-full px-4 py-2 bg-[#0A0E17] border border-white/[0.06] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent cursor-pointer"
              >
                <option value="all">All Time</option>
                <option value="1">Last 24 Hours</option>
                <option value="7">Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
              </select>
            </div>
          </div>
        </div>

        {/* Verifications Table */}
        <div className="bg-[#141823] border border-white/[0.06] rounded-xl overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00D9D9]"></div>
              <span className="ml-3 text-[#8B95A7]">Loading verifications...</span>
            </div>
          ) : paginatedVerifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12">
              <Clock className="h-12 w-12 text-[#8B95A7] mb-4" />
              <p className="text-[#8B95A7] text-lg">No verifications found</p>
              <p className="text-[#8B95A7] text-sm mt-2">
                Try adjusting your filters or search query
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-white/[0.06]">
                  <tr>
                    <th
                      className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider cursor-pointer hover:text-[#00D9D9] transition-colors"
                      onClick={() => handleSort('timestamp')}
                    >
                      Timestamp {renderSortIcon('timestamp')}
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Verification ID
                    </th>
                    <th
                      className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider cursor-pointer hover:text-[#00D9D9] transition-colors"
                      onClick={() => handleSort('endpoint')}
                    >
                      Endpoint {renderSortIcon('endpoint')}
                    </th>
                    <th
                      className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider cursor-pointer hover:text-[#00D9D9] transition-colors"
                      onClick={() => handleSort('algorithm')}
                    >
                      Algorithm {renderSortIcon('algorithm')}
                    </th>
                    <th
                      className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider cursor-pointer hover:text-[#00D9D9] transition-colors"
                      onClick={() => handleSort('result')}
                    >
                      Result {renderSortIcon('result')}
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-[#8B95A7] uppercase tracking-wider">
                      Response Time
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {paginatedVerifications.map((verification) => (
                    <tr
                      key={verification._id}
                      onClick={() => handleVerificationClick(verification)}
                      className="hover:bg-white/[0.02] cursor-pointer transition-colors"
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center text-sm text-[#8B95A7]">
                          <Clock className="h-4 w-4 mr-1" />
                          {formatDistanceToNow(new Date(verification.timestamp), { addSuffix: true })}
                        </div>
                        <div className="text-xs text-[#8B95A7]/70 mt-1">
                          {new Date(verification.timestamp).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-[#00D9D9] font-mono text-sm">{verification.verificationId}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-white font-mono">
                          {verification.endpoint}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getAlgorithmBadge(verification.algorithm)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getResultBadge(verification.result)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {verification.responseTime ? (
                          <span className="text-sm text-[#8B95A7]">
                            {verification.responseTime}ms
                          </span>
                        ) : (
                          <span className="text-sm text-[#8B95A7]/50">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Pagination Controls */}
        {filteredAndSortedVerifications.length > 0 && (
          <div className="mt-6 flex items-center justify-between">
            {/* Page size selector */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-[#8B95A7]">Show</span>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(parseInt(e.target.value) as PageSize)}
                className="px-3 py-1 bg-[#141823] border border-white/[0.06] rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-[#00D9D9] focus:border-transparent cursor-pointer"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <span className="text-sm text-[#8B95A7]">entries</span>
            </div>

            {/* Results info */}
            <div className="text-sm text-[#8B95A7]">
              Showing {((currentPage - 1) * pageSize) + 1} to{' '}
              {Math.min(currentPage * pageSize, filteredAndSortedVerifications.length)} of{' '}
              {filteredAndSortedVerifications.length} verifications
            </div>

            {/* Page navigation */}
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="p-2"
              >
                <ChevronsLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setCurrentPage(currentPage - 1)}
                disabled={currentPage === 1}
                className="p-2"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              
              <span className="text-sm text-white px-3">
                Page {currentPage} of {totalPages}
              </span>
              
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setCurrentPage(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="p-2"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage === totalPages}
                className="p-2"
              >
                <ChevronsRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Verification Detail Modal */}
      <Dialog open={showDetailModal} onOpenChange={setShowDetailModal}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <span className="text-[#00D9D9] font-mono">{selectedVerification?.verificationId}</span>
              {selectedVerification && getResultBadge(selectedVerification.result)}
              {selectedVerification && getAlgorithmBadge(selectedVerification.algorithm)}
            </DialogTitle>
            <DialogDescription>Verification Details</DialogDescription>
          </DialogHeader>

          {selectedVerification && (
            <div className="space-y-6">
              {/* Timestamp */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Timestamp</h3>
                <p className="text-white">
                  {new Date(selectedVerification.timestamp).toLocaleString()}
                  <span className="text-[#8B95A7] ml-2">
                    ({formatDistanceToNow(new Date(selectedVerification.timestamp), { addSuffix: true })})
                  </span>
                </p>
              </div>

              {/* Endpoint */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Endpoint</h3>
                <p className="text-[#00D9D9] font-mono">{selectedVerification.endpoint}</p>
              </div>

              {/* Signature Hash */}
              <div>
                <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Signature Hash</h3>
                <div className="bg-[#0A0E17] border border-white/[0.06] rounded-lg p-3">
                  <p className="text-white font-mono text-sm break-all">{selectedVerification.signatureHash}</p>
                </div>
              </div>

              {/* Public Key Hash */}
              {selectedVerification.publicKeyHash && (
                <div>
                  <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Public Key Hash</h3>
                  <div className="bg-[#0A0E17] border border-white/[0.06] rounded-lg p-3">
                    <p className="text-white font-mono text-sm break-all">{selectedVerification.publicKeyHash}</p>
                  </div>
                </div>
              )}

              {/* Response Time */}
              {selectedVerification.responseTime && (
                <div>
                  <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Response Time</h3>
                  <p className="text-white">{selectedVerification.responseTime}ms</p>
                </div>
              )}

              {/* Error Details */}
              {selectedVerification.result === 'rejected' && (selectedVerification.errorCode || selectedVerification.errorDetails) && (
                <div className="bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-[#FF6B6B] mb-2">Error Details</h3>
                  {selectedVerification.errorCode && (
                    <p className="text-white font-mono text-sm mb-2">
                      Code: {selectedVerification.errorCode}
                    </p>
                  )}
                  {selectedVerification.errorDetails && (
                    <p className="text-white text-sm">
                      {selectedVerification.errorDetails}
                    </p>
                  )}
                </div>
              )}

              {/* Request Payload */}
              {selectedVerification.requestPayload && Object.keys(selectedVerification.requestPayload).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-[#8B95A7] mb-2">Request Payload</h3>
                  <div className="bg-[#0A0E17] border border-white/[0.06] rounded-lg p-4 max-h-64 overflow-auto">
                    <pre className="text-sm text-white whitespace-pre-wrap font-mono">
                      {JSON.stringify(selectedVerification.requestPayload, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}

          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowDetailModal(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
