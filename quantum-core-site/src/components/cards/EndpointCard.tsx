import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import Badge from '../ui/Badge';
import type { Endpoint } from '../../api/endpoints';

interface EndpointCardProps {
  endpoint: Endpoint;
  orgId: string;
  orgSlug?: string;
}

export default function EndpointCard({ endpoint, orgId, orgSlug }: EndpointCardProps) {
  const proxyUrl = `proxy.quantumbridge.io/${orgSlug || 'org'}/${endpoint.proxySlug}/`;

  return (
    <Link to={`/org/${orgId}/endpoints/${endpoint._id}`}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        whileHover={{ scale: 1.02 }}
        transition={{ duration: 0.2 }}
        className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl hover:border-cyber-cyan/30 transition-all cursor-pointer"
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <h3 className="text-lg font-bold text-white mb-1">{endpoint.name}</h3>
            <p className="text-sm text-white/40 font-mono">{proxyUrl}</p>
          </div>
          <Badge variant={endpoint.isActive ? 'success' : 'default'}>
            {endpoint.isActive ? 'Active' : 'Inactive'}
          </Badge>
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-white/60">Target URL:</span>
            <span className="text-white/80 font-mono text-xs truncate max-w-[200px]">
              {endpoint.targetUrl}
            </span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-white/60">Requests Today:</span>
            <span className="text-cyber-cyan font-medium">{endpoint.requestCount || 0}</span>
          </div>
          
          <div className="flex justify-between">
            <span className="text-white/60">IP Allowlist:</span>
            <span className="text-white/80">
              {endpoint.ipAllowlist?.length > 0
                ? `${endpoint.ipAllowlist.length} IP${endpoint.ipAllowlist.length > 1 ? 's' : ''}`
                : 'None'}
            </span>
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-white/5">
          <span className="text-xs text-white/40">
            Created {new Date(endpoint.createdAt).toLocaleDateString()}
          </span>
        </div>
      </motion.div>
    </Link>
  );
}
