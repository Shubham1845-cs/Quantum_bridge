import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Activity,
  Layers,
  Plus,
  Lock,
  Zap,
  AlertCircle,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { listOrgs, createOrg, type Organization } from "../api/orgs";
import { Card } from "../components/ui/Card";
import { StatCard } from "../components/ui/StatCard";
import { Modal } from "../components/ui/Modal";
import Button from "../components/ui/Button";

const ease = [0.22, 1, 0.36, 1] as const;

const PLAN_CHIP: Record<Organization["plan"], string> = {
  free: "border-white/15 text-white/40 bg-white/5",
  pro: "border-qb-cyan/30 text-qb-cyan bg-qb-cyan/10",
  enterprise: "border-qb-violet/30 text-qb-violet bg-qb-violet/10",
};

export default function DashboardPage() {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Create Org
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState("");

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
    setCreateError("");
    try {
      await createOrg(newOrgName);
      setShowCreateModal(false);
      setNewOrgName("");
      fetchOrgs();
    } catch (err: any) {
      setCreateError(err.message || "Failed to create organization");
    } finally {
      setIsCreating(false);
    }
  };

  // Auth-aware top-right action: Login when logged out, Sign Out when logged in.
  // ProtectedRoute already bounces unauthenticated visitors to /login, but the
  // button must always reflect real auth state rather than a hardcoded label.
  const handleAuthClick = () => {
    if (isAuthenticated) logout();
    else navigate("/login");
  };

  return (
    <div className="qb-ambient qb-grain relative min-h-screen text-white">
      {/* Top bar */}
      <header className="fixed inset-x-0 top-0 z-50 border-b border-white/[0.06] bg-black/60 px-6 py-4 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between">
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

          <div className="flex items-center gap-4">
            <span className="hidden text-[10px] font-medium uppercase tracking-[0.2em] text-white/25 sm:block">
              Dashboard
            </span>
            <motion.button
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.97 }}
              onClick={handleAuthClick}
              id="logout-btn"
              className={
                isAuthenticated
                  ? "rounded-full border border-white/10 px-5 py-2 text-xs font-bold uppercase tracking-wider text-white/50 transition-all duration-300 hover:border-qb-rose/30 hover:bg-qb-rose/5 hover:text-qb-rose"
                  : "rounded-full border border-qb-cyan/30 bg-qb-cyan/10 px-5 py-2 text-xs font-bold uppercase tracking-wider text-qb-cyan transition-all duration-300 hover:bg-qb-cyan/20 hover:shadow-[0_0_20px_rgba(34,211,238,0.25)]"
              }
            >
              {isAuthenticated ? "Sign Out" : "Login"}
            </motion.button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="relative z-10 px-6 pb-16 pt-28">
        <div className="mx-auto max-w-7xl">
          {/* Hero */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease }}
            className="mb-12"
          >
            <div className="mb-4 flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-qb-emerald opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-qb-emerald" />
              </span>
              <span className="text-xs font-medium uppercase tracking-[0.25em] text-qb-emerald/80">
                Systems Operational
              </span>
            </div>

            <h1 className="mb-3 text-4xl font-bold tracking-tight md:text-5xl">
              <span className="text-gradient-premium">Command Center</span>
            </h1>
            <p className="mb-6 text-lg font-light text-white/40">
              Monitor and orchestrate your quantum-secured infrastructure
            </p>

            <div className="flex flex-wrap gap-2">
              {[
                { icon: ShieldCheck, label: "Dual-Signature Active" },
                { icon: Lock, label: "AES-256-GCM" },
                { icon: Zap, label: "ML-DSA-65" },
              ].map((tag) => {
                const Icon = tag.icon;
                return (
                  <span
                    key={tag.label}
                    className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.02] px-3 py-1.5 text-[11px] font-medium uppercase tracking-wider text-white/55"
                  >
                    <Icon size={12} className="text-qb-cyan" />
                    {tag.label}
                  </span>
                );
              })}
            </div>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.6, ease }}
            className="mb-12 grid grid-cols-1 gap-4 sm:grid-cols-3"
          >
            <StatCard label="Organizations" value={loading ? "—" : String(orgs.length)} hint="Active workspaces" icon={Layers} tone="cyan" />
            <StatCard label="Active Endpoints" value="—" hint="Proxied & verified" icon={Activity} tone="violet" />
            <StatCard label="Threats Blocked" value="—" hint="Last 24h" icon={ShieldCheck} tone="cyan" />
          </motion.div>

          {/* Organizations */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6, ease }}
          >
            <div className="mb-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-bold tracking-tight text-white">Your Organizations</h2>
                <span className="text-[10px] font-medium uppercase tracking-[0.3em] text-white/15">
                  {orgs.length} total
                </span>
              </div>
              <Button onClick={() => setShowCreateModal(true)} variant="primary" size="sm">
                <Plus size={15} className="mr-1.5" />
                Create Organization
              </Button>
            </div>

            {loading ? (
              <div className="flex justify-center py-16">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-qb-cyan/30 border-t-qb-cyan" />
              </div>
            ) : error ? (
              <Card className="p-8 text-center">
                <AlertCircle className="mx-auto mb-3 text-qb-rose" size={28} />
                <p className="mb-1 text-sm text-qb-rose">{error}</p>
                <p className="text-xs text-white/20">Make sure the backend server is running on port 3000</p>
              </Card>
            ) : orgs.length === 0 ? (
              <Card className="p-16 text-center">
                <div className="mb-4 text-4xl">🚀</div>
                <p className="mb-1 text-sm text-white/40">No organizations yet</p>
                <p className="mb-6 text-xs text-white/20">Create your first workspace to start proxying endpoints.</p>
                <Button onClick={() => setShowCreateModal(true)} variant="primary">
                  Create Your First Organization
                </Button>
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                {orgs.map((org, i) => (
                  <motion.div
                    key={org._id}
                    onClick={() => navigate(`/org/${org._id}`)}
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.25 + i * 0.06, duration: 0.5, ease }}
                    className="cursor-pointer"
                  >
                    <Card variant="interactive" className="h-full p-6">
                      <div className="mb-4 flex items-start justify-between">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-qb-cyan/20 to-qb-violet/20 text-sm font-bold uppercase text-white">
                            {org.name.charAt(0)}
                          </div>
                          <div>
                            <h3 className="text-base font-bold tracking-tight text-white transition-colors group-hover:text-qb-cyan">
                              {org.name}
                            </h3>
                            <span className={`mt-1 inline-block rounded-full border px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.2em] ${PLAN_CHIP[org.plan]}`}>
                              {org.plan}
                            </span>
                          </div>
                        </div>
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-qb-cyan/10 bg-qb-cyan/5 text-qb-cyan opacity-0 transition-opacity group-hover:opacity-100">
                          →
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-light text-white/20">
                        <span className="font-mono-qb">ID: {org._id.slice(-8)}</span>
                        <span>{org.monthlyRequestCount?.toLocaleString() ?? 0} req/mo</span>
                      </div>
                    </Card>
                  </motion.div>
                ))}
              </div>
            )}
          </motion.div>
        </div>
      </main>

      {/* Create Organization Modal */}
      <Modal
        open={showCreateModal}
        onOpenChange={(o) => {
          setShowCreateModal(o);
          if (!o) {
            setCreateError("");
            setNewOrgName("");
          }
        }}
        title="Create Organization"
        description="Organizations let you manage endpoints, keys, and team members."
        footer={
          <>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setShowCreateModal(false);
                setCreateError("");
                setNewOrgName("");
              }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="create-org-form"
              variant="primary"
              size="sm"
              disabled={isCreating || !newOrgName.trim()}
            >
              {isCreating ? "Creating…" : "Create"}
            </Button>
          </>
        }
      >
        {createError && (
          <div className="mb-4 rounded-lg border border-qb-rose/20 bg-qb-rose/5 p-3 text-sm text-qb-rose">
            {createError}
          </div>
        )}
        <form id="create-org-form" onSubmit={handleCreateOrg} className="space-y-2">
          <label className="block text-xs text-white/60">Organization Name</label>
          <input
            type="text"
            required
            value={newOrgName}
            onChange={(e) => setNewOrgName(e.target.value)}
            className="qb-input-focus w-full rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-white placeholder-white/20"
            placeholder="e.g. Acme Corp"
            autoFocus
          />
        </form>
      </Modal>
    </div>
  );
}
