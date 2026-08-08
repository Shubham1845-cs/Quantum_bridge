import { Outlet, useParams } from 'react-router-dom';
import DashboardNavbar from './DashboardNavbar';
import Sidebar from './Sidebar';

export default function OrgLayout() {
  const { orgId } = useParams<{ orgId: string }>();

  if (!orgId) {
    return <div className="grid min-h-screen place-items-center text-white/40">Invalid organization</div>;
  }

  return (
    <div className="qb-ambient qb-grain relative min-h-screen text-white">
      {/* Top Navigation */}
      <DashboardNavbar />

      {/* Soft top glow */}
      <div className="pointer-events-none fixed inset-x-0 top-0 z-0 h-64">
        <div className="absolute left-1/2 top-0 h-72 w-[820px] -translate-x-1/2 rounded-full bg-gradient-to-br from-qb-cyan/10 to-qb-violet/10 opacity-40 blur-[120px]" />
      </div>

      {/* Main content */}
      <main className="relative z-10 px-6 pb-20 pt-28">
        <div className="mx-auto flex max-w-7xl flex-col gap-8 md:flex-row">
          <Sidebar orgId={orgId} />
          <div className="min-w-0 flex-1">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
