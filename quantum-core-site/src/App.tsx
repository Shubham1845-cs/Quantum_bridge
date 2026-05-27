import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { OrgProvider } from './context/OrgContext';
import ProtectedRoute from './components/ProtectedRoute';

// Lazy load pages
const HomePage = lazy(() => import('./pages/HomePage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const VerifyEmailPage = lazy(() => import('./pages/auth/VerifyEmailPage'));
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const OrgLayout = lazy(() => import('./components/OrgLayout'));
const OrgOverviewPage = lazy(() => import('./pages/OrgOverviewPage'));
const EndpointsPage = lazy(() => import('./pages/EndpointsPage'));
const EndpointDetailPage = lazy(() => import('./pages/EndpointDetailPage'));
const AnalyticsPage = lazy(() => import('./pages/AnalyticsPage'));
const KeysPage = lazy(() => import('./pages/KeysPage'));
const TeamPage = lazy(() => import('./pages/TeamPage'));
const BillingPage = lazy(() => import('./pages/BillingPage'));
const WebhooksPage = lazy(() => import('./pages/dashboard/WebhooksPage'));
const DocsPage = lazy(() => import('./pages/dashboard/DocsPage'));
const PublicVerifyPage = lazy(() => import('./pages/PublicVerifyPage'));

// Loading fallback component
function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-black">
      <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-cyber-cyan" />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Suspense fallback={<LoadingScreen />}>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/verify-email" element={<VerifyEmailPage />} />
            <Route path="/verify/:requestId" element={<PublicVerifyPage />} />

            {/* Protected routes */}
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <OrgProvider>
                    <DashboardPage />
                  </OrgProvider>
                </ProtectedRoute>
              }
            />

            {/* Org routes */}
            <Route
              path="/org/:orgId"
              element={
                <ProtectedRoute>
                  <OrgProvider>
                    <OrgLayout />
                  </OrgProvider>
                </ProtectedRoute>
              }
            >
              <Route index element={<Navigate to="overview" replace />} />
              <Route path="overview" element={<OrgOverviewPage />} />
              <Route path="endpoints" element={<EndpointsPage />} />
              <Route path="endpoints/:endpointId" element={<EndpointDetailPage />} />
              <Route path="analytics" element={<AnalyticsPage />} />
              <Route path="keys" element={<KeysPage />} />
              <Route path="team" element={<TeamPage />} />
              <Route path="billing" element={<BillingPage />} />
              <Route path="webhooks" element={<WebhooksPage />} />
              <Route path="docs" element={<DocsPage />} />
            </Route>
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  );
}
