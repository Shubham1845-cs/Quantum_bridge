import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';
import { listOrgs, createOrg, type Organization } from '../../api/orgs';
import { useToast } from '../../hooks/useToast';

const ease = [0.22, 1, 0.36, 1] as const;

export default function DashboardPage() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Create Org State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState('');

  const fetchOrgs = () => {
    setLoading(true);
    listOrgs()
      .then(setOrgs)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchOrgs();
  }, []);

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    
    setIsCreating(true);
    setCreateError('');
    
    try {
      const newOrg = await createOrg(newOrgName);
      setShowCreateModal(false);
      setNewOrgName('');
      toast.success('Organization created successfully');
      fetchOrgs();
      // Navigate to the new org
      navigate(`/org/${newOrg._id}/overview`);
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create organization');
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Top bar */}
      <header className="fixed top-0 left-0 right-0 z-50 px-6 py-4 backdrop-blur-xl bg-black/60 border-b border-white/[0.06]">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-1 group">
            <span className="text-2xl font-bold tracking-tighter text-white">
              Quantum
              <span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">
                Bridge
              </span>
            </span>
          </Link>

          <div className="flex items-center gap-4">
            <span className="text-white/20 text-xs tracking-[0.2em] uppercase font-medium hidden sm:block">
              Dashboard
            </span>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.97 }}
              onClick={logout}
              className="px-5 py-2 rounded-full text-xs font-bold border border-white/10 text-white/50 hover:text-white hover:border-red-500/30 hover:bg-red-500/5 transition-all duration-300 tracking-wider uppercase"
            >
              Sign Out
            </motion.button>
          </div>
        </div>
      </header>

      {/* Background */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[400px] rounded-full opacity-[0.04] blur-[150px] bg-gradient-to-br from-cyber-cyan to-neon-purple" />
      </div>

      {/* Main content */}
      <main className="relative z-10 pt-28 pb-16 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease }}
          >
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-3">
              <span className="bg-gradient-to-r from-cyber-cyan to-neon-purple bg-clip-text text-transparent">
                Dashboard
              </span>
            </h1>
            <p className="text-white/35 text-lg font-light mb-12">
              Manage your quantum-safe API infrastructure
            </p>
          </motion.div>

          {/* Stats overview */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.6, ease }}
            className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-12"
          >
            {[
              {
                label: 'Organizations',
                val: loading ? '—' : String(orgs.length),
                color: '#00FFFF',
              },
              {
                label: 'Active Endpoints',
                val: '—',
                color: '#8A2BE2',
              },
              {
                label: 'Requests (24h)',
                val: '—',
                color: '#00FFFF',
              },
            ].map((stat) => (
              <div
                key={stat.label}
                className="p-6 rounded-2xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-sm"
              >
                <div
                  className="text-3xl font-bold tracking-tight mb-2"
                  style={{ color: stat.color }}
                >
                  {stat.val}
                </div>
                <div className="text-white/30 text-[10px] uppercase tracking-[0.3em] font-medium">
                  {stat.label}
                </div>
              </div>
            ))}
          </motion.div>

          {/* Organizations list */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6, ease }}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Your Organizations
                </h2>
                <span className="text-white/15 text-[10px] tracking-[0.3em] uppercase font-medium">
                  {orgs.length} total
                </span>
              </div>
              <button 
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-lg text-sm font-medium hover:bg-cyber-cyan/20 transition-colors"
              >
                + Create Organization
              </button>
            </div>

            {loading ? (
              <div className="flex justify-center py-16">
                <div className="w-8 h-8 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
              </div>
            ) : error ? (
              <div className="px-6 py-8 rounded-2xl border border-red-500/15 bg-red-500/5 text-center">
                <p className="text-red-400 text-sm mb-2">{error}</p>
                <p className="text-white/20 text-xs">
                  Make sure the backend server is running on port 3000
                </p>
              </div>
            ) : orgs.length === 0 ? (
              <div className="px-6 py-16 rounded-2xl border border-white/[0.06] bg-white/[0.02] text-center">
                <div className="text-4xl mb-4">🚀</div>
                <p className="text-white/40 text-sm mb-4">
                  No organizations yet
                </p>
                <button 
                  onClick={() => setShowCreateModal(true)}
                  className="px-6 py-3 bg-cyber-cyan text-black rounded-xl text-sm font-bold shadow-[0_0_15px_rgba(0,255,255,0.2)] hover:shadow-[0_0_25px_rgba(0,255,255,0.4)] transition-all"
                >
                  Create Your First Organization
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {orgs.map((org, i) => (
                  <motion.div
                    key={org._id}
                    onClick={() => navigate(`/org/${org._id}/overview`)}
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 + i * 0.08, duration: 0.5, ease }}
                    className="group p-6 rounded-2xl border border-white/[0.06] bg-white/[0.02] hover:border-cyber-cyan/20 hover:bg-cyber-cyan/[0.02] transition-all duration-300 cursor-pointer"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-white font-bold text-base tracking-tight group-hover:text-cyber-cyan transition-colors">
                          {org.name}
                        </h3>
                        <span
                          className="inline-block mt-1 px-3 py-0.5 rounded-full text-[9px] font-bold tracking-[0.2em] uppercase border"
                          style={{
                            borderColor:
                              org.plan === 'enterprise'
                                ? '#8A2BE230'
                                : org.plan === 'pro'
                                ? '#00FFFF30'
                                : '#ffffff15',
                            color:
                              org.plan === 'enterprise'
                                ? '#8A2BE2'
                                : org.plan === 'pro'
                                ? '#00FFFF'
                                : '#ffffff40',
                            background:
                              org.plan === 'enterprise'
                                ? '#8A2BE208'
                                : org.plan === 'pro'
                                ? '#00FFFF08'
                                : '#ffffff04',
                          }}
                        >
                          {org.plan}
                        </span>
                      </div>
                      <div className="w-8 h-8 rounded-lg bg-cyber-cyan/5 border border-cyber-cyan/10 flex items-center justify-center text-cyber-cyan text-sm opacity-0 group-hover:opacity-100 transition-opacity">
                        →
                      </div>
                    </div>
                    <div className="text-white/15 text-[10px] font-light">
                      ID: {org._id.slice(-8)}
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </motion.div>
        </div>
      </main>

      {/* Create Organization Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-[#111111] border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-2xl relative"
          >
            <h3 className="text-xl font-bold mb-2">Create Organization</h3>
            <p className="text-white/40 text-xs mb-6">Organizations let you manage endpoints, keys, and team members.</p>
            
            {createError && (
              <div className="mb-4 text-red-400 text-sm bg-red-400/10 p-3 rounded-lg border border-red-500/20">
                {createError}
              </div>
            )}
            
            <form onSubmit={handleCreateOrg}>
              <div className="mb-6">
                <label className="block text-white/60 text-xs mb-2">Organization Name</label>
                <input 
                  type="text" 
                  required
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  className="w-full bg-black border border-white/10 rounded-xl p-3 text-sm text-white placeholder-white/20 focus:border-cyber-cyan focus:outline-none transition-colors" 
                  placeholder="e.g. Acme Corp"
                  autoFocus
                />
              </div>
              <div className="flex justify-end gap-3">
                <button 
                  type="button" 
                  onClick={() => {
                    setShowCreateModal(false);
                    setCreateError('');
                    setNewOrgName('');
                  }}
                  className="px-4 py-2 text-sm text-white/60 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={isCreating || !newOrgName.trim()}
                  className="px-5 py-2 bg-cyber-cyan text-black rounded-lg text-sm font-bold hover:bg-cyber-cyan/80 disabled:opacity-50 transition-colors"
                >
                  {isCreating ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
}
