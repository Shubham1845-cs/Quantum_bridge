import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

interface Props {
  children: React.ReactNode;
}

/**
 * Wraps a route that requires authentication.
 * Shows a loading spinner while checking tokens, then redirects to /login if unauthenticated.
 */
export default function ProtectedRoute({ children }: Props) {
  const { loading, isAuthenticated } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin" />
          <span className="text-white/30 text-xs tracking-[0.3em] uppercase font-medium">
            Authenticating…
          </span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
