import { Outlet, useParams } from 'react-router-dom';
import DashboardNavbar from './DashboardNavbar';
import Sidebar from './Sidebar';

export default function OrgLayout() {
  const { orgId } = useParams<{ orgId: string }>();

  if (!orgId) {
    return <div>Invalid organization</div>;
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Top Navigation */}
      <DashboardNavbar />

      {/* Background Effect */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[400px] rounded-full opacity-[0.04] blur-[150px] bg-gradient-to-br from-cyber-cyan to-neon-purple" />
      </div>

      {/* Main Content */}
      <main className="relative z-10 pt-28 pb-16 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row gap-8">
          {/* Sidebar */}
          <Sidebar orgId={orgId} />

          {/* Content Area */}
          <div className="flex-1 min-w-0">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
