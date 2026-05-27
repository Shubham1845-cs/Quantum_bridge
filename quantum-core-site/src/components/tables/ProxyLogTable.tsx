import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getProxyLogs, type ProxyLog } from '../../api/analytics';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { formatDateTime, copyToClipboard } from '../../lib/utils';
import { useToast } from '../../hooks/useToast';

interface ProxyLogTableProps {
  orgId: string;
  endpointId?: string;
}

export default function ProxyLogTable({ orgId, endpointId }: ProxyLogTableProps) {
  const [page, setPage] = useState(1);
  const [threatOnly, setThreatOnly] = useState(false);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const toast = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ['proxyLogs', orgId, page, threatOnly, endpointId],
    queryFn: () => getProxyLogs(orgId, { page, limit: 20, threatFlag: threatOnly ? true : undefined, endpointId }),
    enabled: !!orgId,
  });

  const handleCopyRequestId = async (requestId: string) => {
    const success = await copyToClipboard(requestId);
    if (success) {
      toast.success('Request ID copied');
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-white/60 cursor-pointer">
          <input
            type="checkbox"
            checked={threatOnly}
            onChange={(e) => {
              setThreatOnly(e.target.checked);
              setPage(1);
            }}
            className="rounded border-white/20 bg-black/50 text-cyber-cyan focus:ring-cyber-cyan focus:ring-offset-black"
          />
          Show only threats
        </label>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-white/10">
        <table className="w-full text-sm">
          <thead className="bg-white/[0.02] border-b border-white/10">
            <tr className="text-left text-white/40">
              <th className="px-4 py-3 font-medium">Request ID</th>
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Method</th>
              <th className="px-4 py-3 font-medium">Path</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Latency</th>
              <th className="px-4 py-3 font-medium">ECDSA</th>
              <th className="px-4 py-3 font-medium">ML-DSA</th>
              <th className="px-4 py-3 font-medium">Threat</th>
            </tr>
          </thead>
          <tbody>
            {!data?.logs || data.logs.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-white/40">
                  No logs found
                </td>
              </tr>
            ) : (
              data.logs.map((log: ProxyLog) => (
                <>
                  <tr
                    key={log._id}
                    onClick={() => setExpandedRow(expandedRow === log._id ? null : log._id)}
                    className={`border-b border-white/5 cursor-pointer hover:bg-white/[0.02] transition-colors ${
                      log.threatFlag ? 'bg-red-500/[0.02]' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopyRequestId(log.requestId);
                        }}
                        className="font-mono text-xs text-cyber-cyan hover:text-cyber-cyan/80 flex items-center gap-1"
                      >
                        {log.requestId.slice(0, 8)}...
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </td>
                    <td className="px-4 py-3 text-white/60">{formatDateTime(log.timestamp)}</td>
                    <td className="px-4 py-3">
                      <Badge variant="default">{log.method}</Badge>
                    </td>
                    <td className="px-4 py-3 text-white/80 font-mono text-xs truncate max-w-[200px]">
                      {log.path}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={log.statusCode < 400 ? 'success' : 'danger'}>
                        {log.statusCode}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-white/80">{log.latencyMs}ms</td>
                    <td className="px-4 py-3">
                      {log.ecdsaVerified ? (
                        <span className="text-green-400">✓</span>
                      ) : (
                        <span className="text-red-400">✗</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {log.dilithiumVerified ? (
                        <span className="text-green-400">✓</span>
                      ) : (
                        <span className="text-red-400">✗</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {log.threatFlag && <Badge variant="danger">Threat</Badge>}
                    </td>
                  </tr>
                  {expandedRow === log._id && (
                    <tr className="bg-white/[0.01]">
                      <td colSpan={9} className="px-4 py-4">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-white/40">Full Request ID:</span>
                            <p className="font-mono text-xs text-white/80 mt-1">{log.requestId}</p>
                          </div>
                          <div>
                            <span className="text-white/40">Client IP:</span>
                            <p className="text-white/80 mt-1">{log.clientIp}</p>
                          </div>
                          <div>
                            <span className="text-white/40">Key Version:</span>
                            <p className="text-white/80 mt-1">{log.keyVersion}</p>
                          </div>
                          <div>
                            <span className="text-white/40">Endpoint ID:</span>
                            <p className="font-mono text-xs text-white/80 mt-1">{log.endpointId}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.logs.length > 0 && (
        <div className="flex items-center justify-between">
          <Button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            variant="secondary"
            size="sm"
          >
            Previous
          </Button>
          <span className="text-sm text-white/40">Page {page}</span>
          <Button
            onClick={() => setPage((p) => p + 1)}
            disabled={!data.hasMore}
            variant="secondary"
            size="sm"
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
