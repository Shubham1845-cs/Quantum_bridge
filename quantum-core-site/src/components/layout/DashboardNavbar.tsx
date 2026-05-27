import { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';
import { useOrg } from '../../context/OrgContext';
import Button from '../ui/Button';

export default function DashboardNavbar() {
  const [orgSelectorOpen, setOrgSelectorOpen] = useState(false);
  const { logout } = useAuth();
  const { currentOrg, orgs, setCurrentOrg } = useOrg();

  const handleOrgChange = (org: any) => {
    setCurrentOrg(org);
    setOrgSelectorOpen(false);
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 px-6 py-4 backdrop-blur-xl bg-black/60 border-b border-white/[0.06]">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-1 group">
          <span className="text-2xl font-bold tracking-tighter text-white">
            NEX
            <span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">
              U
            </span>
            S
          </span>
          <span className="relative flex h-2 w-2 ml-0.5 -mt-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-cyan opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-cyan shadow-neon-cyan" />
          </span>
        </Link>

        {/* Organization Selector & Actions */}
        <div className="flex items-center gap-4">
          {/* Organization Selector */}
          {currentOrg && orgs.length > 0 && (
            <div className="relative">
              <button
                onClick={() => setOrgSelectorOpen(!orgSelectorOpen)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/[0.02] border border-white/10 hover:border-cyber-cyan/30 transition-all text-sm text-white/80 hover:text-white"
                aria-label="Select organization"
              >
                <span className="hidden sm:inline">{currentOrg.name}</span>
                <svg
                  className={`w-4 h-4 transition-transform ${orgSelectorOpen ? 'rotate-180' : ''}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* Dropdown */}
              <AnimatePresence>
                {orgSelectorOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="absolute top-full mt-2 right-0 w-64 bg-black border border-white/10 rounded-xl shadow-2xl overflow-hidden"
                  >
                    <div className="p-2">
                      {orgs.map((org) => (
                        <button
                          key={org._id}
                          onClick={() => handleOrgChange(org)}
                          className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                            org._id === currentOrg._id
                              ? 'bg-cyber-cyan/10 text-cyber-cyan'
                              : 'text-white/60 hover:text-white hover:bg-white/[0.04]'
                          }`}
                        >
                          {org.name}
                        </button>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* All Orgs Link */}
          <Link
            to="/dashboard"
            className="hidden sm:block text-white/50 hover:text-white text-xs tracking-[0.2em] uppercase font-medium transition-colors"
          >
            All Orgs
          </Link>

          {/* Logout Button */}
          <Button
            variant="secondary"
            size="sm"
            onClick={logout}
            className="hover:border-red-500/30 hover:bg-red-500/5 hover:text-red-400"
          >
            Sign Out
          </Button>
        </div>
      </div>
    </header>
  );
}
