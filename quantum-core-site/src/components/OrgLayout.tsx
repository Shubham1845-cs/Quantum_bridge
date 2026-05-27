import { Link, Outlet, useLocation, useParams } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "../context/AuthContext";

export default function OrgLayout() {
  const { logout } = useAuth();
  const { orgId } = useParams<{ orgId: string }>();
  const location = useLocation();

  const navItems = [
    { name: "Overview", path: `/org/${orgId}/overview` },
    { name: "Endpoints", path: `/org/${orgId}/endpoints` },
    { name: "Analytics", path: `/org/${orgId}/analytics` },
    { name: "Keys", path: `/org/${orgId}/keys` },
    { name: "Team", path: `/org/${orgId}/team` },
    { name: "Billing", path: `/org/${orgId}/billing` },
    { name: "Docs", path: `/org/${orgId}/docs` },
  ];

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Top bar */}
      <header className="fixed top-0 left-0 right-0 z-50 px-6 py-4 backdrop-blur-xl bg-black/60 border-b border-white/[0.06]">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-1 group">
            <span className="text-2xl font-bold tracking-tighter text-white">
              NEX<span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">U</span>S
            </span>
            <span className="relative flex h-2 w-2 ml-0.5 -mt-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-cyan opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-cyan shadow-neon-cyan" />
            </span>
          </Link>

          <div className="flex items-center gap-4">
            <Link to="/dashboard" className="text-white/50 hover:text-white text-xs tracking-[0.2em] uppercase font-medium hidden sm:block transition-colors">
              All Orgs
            </Link>
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

      <main className="relative z-10 pt-28 pb-16 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row gap-8">
          {/* Sidebar */}
          <aside className="w-full md:w-48 flex-shrink-0">
            <div className="text-[11px] text-white/40 tracking-[0.2em] font-medium uppercase mb-4 px-3">
              Organization
            </div>
            <nav className="flex flex-col gap-1">
              {navItems.map((item) => {
                const isActive = location.pathname.startsWith(item.path);
                return (
                  <Link
                    key={item.name}
                    to={item.path}
                    className={`px-3 py-2 rounded-lg text-sm transition-all duration-200 ${
                      isActive
                        ? "bg-cyber-cyan/[0.08] text-cyber-cyan font-medium border border-cyber-cyan/20"
                        : "text-white/60 hover:text-white hover:bg-white/[0.04] border border-transparent"
                    }`}
                  >
                    {item.name}
                  </Link>
                );
              })}
            </nav>
          </aside>

          {/* Content Area */}
          <div className="flex-1 min-w-0">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
