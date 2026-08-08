import { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, LogOut, LayoutGrid, Check } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useOrg } from '../../context/OrgContext';
import { cn } from '../../lib/utils';
import Button from '../ui/Button';

const planBadge: Record<string, string> = {
  free: 'text-white/40 border-white/15 bg-white/5',
  pro: 'text-qb-cyan border-qb-cyan/30 bg-qb-cyan/10',
  enterprise: 'text-qb-violet border-qb-violet/30 bg-qb-violet/10',
};

function Logo() {
  return (
    <Link to="/" className="group flex items-center gap-1">
      <span className="text-2xl font-bold tracking-tighter text-white">
        NEX
        <span className="text-qb-cyan transition-all duration-300 group-hover:drop-shadow-[0_0_8px_#22d3ee]">
          U
        </span>
        S
      </span>
      <span className="relative -mt-3 ml-0.5 flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-qb-cyan opacity-75" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-qb-cyan shadow-[0_0_8px_#22d3ee]" />
      </span>
    </Link>
  );
}

export default function DashboardNavbar() {
  const [orgSelectorOpen, setOrgSelectorOpen] = useState(false);
  const { logout } = useAuth();
  const { currentOrg, orgs, setCurrentOrg } = useOrg();

  const handleOrgChange = (org: typeof currentOrg) => {
    if (org) setCurrentOrg(org);
    setOrgSelectorOpen(false);
  };

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-white/[0.06] bg-black/60 px-6 py-4 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between">
        <Logo />

        <div className="flex items-center gap-3">
          {/* Organization selector */}
          {currentOrg && orgs.length > 0 && (
            <div className="relative">
              <button
                onClick={() => setOrgSelectorOpen((o) => !o)}
                className="flex items-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white/85 transition-all hover:border-qb-cyan/30 hover:bg-white/[0.05] focus:outline-none focus-visible:ring-2 focus-visible:ring-qb-cyan/40"
                aria-label="Select organization"
              >
                <div className="flex h-6 w-6 items-center justify-center rounded-md bg-gradient-to-br from-qb-cyan/30 to-qb-violet/30 text-[10px] font-bold uppercase text-white">
                  {currentOrg.name.charAt(0)}
                </div>
                <span className="hidden max-w-[140px] truncate sm:inline">
                  {currentOrg.name}
                </span>
                {(planBadge as any)[currentOrg.plan] && (
                  <span
                    className={cn(
                      'hidden rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider md:inline-block',
                      (planBadge as any)[currentOrg.plan],
                    )}
                  >
                    {currentOrg.plan}
                  </span>
                )}
                <ChevronDown
                  size={14}
                  className={cn('text-white/40 transition-transform', orgSelectorOpen && 'rotate-180')}
                />
              </button>

              <AnimatePresence>
                {orgSelectorOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 mt-2 w-72 overflow-hidden rounded-xl border border-white/10 bg-[#0b1120]/95 shadow-premium-3 backdrop-blur-xl"
                  >
                    <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/30">
                      Your organizations
                    </div>
                    <div className="px-2 pb-2">
                      {orgs.map((org) => {
                        const isActive = org._id === currentOrg._id;
                        return (
                          <button
                            key={org._id}
                            onClick={() => handleOrgChange(org)}
                            className={cn(
                              'flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-colors',
                              isActive
                                ? 'bg-qb-cyan/10 text-qb-cyan'
                                : 'text-white/65 hover:bg-white/[0.04] hover:text-white',
                            )}
                          >
                            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-gradient-to-br from-qb-cyan/20 to-qb-violet/20 text-[10px] font-bold uppercase">
                              {org.name.charAt(0)}
                            </div>
                            <span className="flex-1 truncate">{org.name}</span>
                            {isActive && <Check size={14} />}
                          </button>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          <Link
            to="/dashboard"
            className="hidden items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.02] px-3 py-2 text-xs font-medium uppercase tracking-[0.15em] text-white/50 transition-colors hover:border-white/20 hover:text-white sm:flex"
          >
            <LayoutGrid size={13} />
            All Orgs
          </Link>

          <Button
            variant="secondary"
            size="sm"
            onClick={logout}
            className="hover:border-qb-rose/30 hover:bg-qb-rose/5 hover:text-qb-rose"
          >
            <LogOut size={14} className="mr-1.5" />
            Sign Out
          </Button>
        </div>
      </div>
    </header>
  );
}
