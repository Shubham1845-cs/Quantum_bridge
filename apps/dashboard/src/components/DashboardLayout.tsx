/**
 * DashboardLayout — auth guard + sidebar navigation (Req 12.4)
 *
 * - Redirects unauthenticated users to /login
 * - Renders sidebar nav + <Outlet /> for nested routes
 */
import { Outlet, Navigate, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const NAV_LINKS = [
  { to: '/dashboard',            label: 'Overview'   },
  { to: '/dashboard/endpoints',  label: 'Endpoints'  },
  { to: '/dashboard/analytics',  label: 'Analytics'  },
  { to: '/dashboard/keys',       label: 'Keys'       },
  { to: '/dashboard/team',       label: 'Team'       },
  { to: '/dashboard/billing',    label: 'Billing'    },
  { to: '/dashboard/docs',       label: 'Docs'       },
];

const styles = {
  layout: {
    display: 'flex',
    minHeight: '100vh',
    fontFamily: 'system-ui, sans-serif',
  } as React.CSSProperties,
  sidebar: {
    width: 220,
    background: '#0f172a',
    color: '#e2e8f0',
    display: 'flex',
    flexDirection: 'column' as const,
    padding: '24px 0',
    flexShrink: 0,
  } as React.CSSProperties,
  brand: {
    padding: '0 20px 24px',
    fontSize: 18,
    fontWeight: 700,
    color: '#38bdf8',
    letterSpacing: '-0.5px',
  } as React.CSSProperties,
  nav: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    gap: 2,
  } as React.CSSProperties,
  main: {
    flex: 1,
    padding: 32,
    background: '#f8fafc',
    overflowY: 'auto' as const,
  } as React.CSSProperties,
  footer: {
    padding: '16px 20px 0',
    borderTop: '1px solid #1e293b',
    marginTop: 'auto',
  } as React.CSSProperties,
  logoutBtn: {
    background: 'none',
    border: 'none',
    color: '#94a3b8',
    cursor: 'pointer',
    padding: '8px 0',
    fontSize: 14,
    textAlign: 'left' as const,
    width: '100%',
  } as React.CSSProperties,
};

const activeLinkStyle = {
  background: '#1e293b',
  color: '#38bdf8',
  borderLeft: '3px solid #38bdf8',
  paddingLeft: 17,
};

const linkStyle = {
  display: 'block',
  padding: '9px 20px',
  color: '#94a3b8',
  textDecoration: 'none',
  fontSize: 14,
  borderLeft: '3px solid transparent',
  transition: 'background 0.15s',
};

export default function DashboardLayout() {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();

  // Req 12.4 — redirect unauthenticated users to /login
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  async function handleLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div style={styles.layout}>
      <aside style={styles.sidebar} aria-label="Sidebar navigation">
        <div style={styles.brand}>QuantumBridge</div>

        <nav style={styles.nav}>
          {NAV_LINKS.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/dashboard'}
              style={({ isActive }) =>
                isActive ? { ...linkStyle, ...activeLinkStyle } : linkStyle
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div style={styles.footer}>
          {user && (
            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 8, wordBreak: 'break-all' }}>
              {user.email}
            </p>
          )}
          <button style={styles.logoutBtn} onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </aside>

      <main style={styles.main}>
        <Outlet />
      </main>
    </div>
  );
}
