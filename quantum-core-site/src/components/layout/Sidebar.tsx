import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Network,
  BarChart3,
  KeyRound,
  Users,
  CreditCard,
  Webhook,
  BookOpen,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface SidebarProps {
  orgId: string;
}

interface NavItem {
  name: string;
  path: string;
  icon: typeof LayoutDashboard;
  /** Routes where `startsWith` should match index/overview siblings. */
  match: string;
}

const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: 'Monitor',
    items: [
      { name: 'Overview', path: 'overview', icon: LayoutDashboard, match: '/overview' },
      { name: 'Endpoints', path: 'endpoints', icon: Network, match: '/endpoints' },
      { name: 'Analytics', path: 'analytics', icon: BarChart3, match: '/analytics' },
    ],
  },
  {
    section: 'Configure',
    items: [
      { name: 'Keys', path: 'keys', icon: KeyRound, match: '/keys' },
      { name: 'Team', path: 'team', icon: Users, match: '/team' },
      { name: 'Billing', path: 'billing', icon: CreditCard, match: '/billing' },
      { name: 'Webhooks', path: 'webhooks', icon: Webhook, match: '/webhooks' },
    ],
  },
  {
    section: 'Resources',
    items: [{ name: 'Docs', path: 'docs', icon: BookOpen, match: '/docs' }],
  },
];

export default function Sidebar({ orgId }: SidebarProps) {
  const location = useLocation();

  return (
    <aside className="w-full shrink-0 md:w-60">
      <nav className="flex flex-col gap-7">
        {NAV.map((group) => (
          <div key={group.section}>
            <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/30">
              {group.section}
            </div>
            <div className="flex flex-col gap-1">
              {group.items.map((item) => {
                const fullPath = `/org/${orgId}/${item.path}`;
                const isActive = location.pathname.startsWith(fullPath);
                const Icon = item.icon;
                return (
                  <Link key={item.name} to={fullPath} className="relative">
                    <motion.div
                      whileHover={{ x: 3 }}
                      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                      className={cn(
                        'group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all duration-200',
                        isActive
                          ? 'bg-qb-cyan/[0.08] font-medium text-qb-cyan'
                          : 'text-white/55 hover:bg-white/[0.04] hover:text-white',
                      )}
                    >
                      {/* Active indicator bar */}
                      <span
                        className={cn(
                          'absolute left-0 top-1/2 h-5 -translate-y-1/2 rounded-r-full bg-qb-cyan transition-all duration-300',
                          isActive ? 'w-0.5 opacity-100 shadow-[0_0_8px_#22d3ee]' : 'w-0 opacity-0',
                        )}
                      />
                      <Icon
                        size={18}
                        className={cn(
                          'shrink-0 transition-colors',
                          isActive ? 'text-qb-cyan' : 'text-white/40 group-hover:text-white/70',
                        )}
                      />
                      <span>{item.name}</span>
                    </motion.div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
    </aside>
  );
}
