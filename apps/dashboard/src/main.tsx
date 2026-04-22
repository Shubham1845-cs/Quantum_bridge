import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Auth pages (task 7.4)
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import VerifyEmailPage from './pages/auth/VerifyEmailPage';

// Dashboard layout + pages (tasks 7.5–7.13)
import DashboardLayout from './components/DashboardLayout';
import OverviewPage from './pages/dashboard/OverviewPage';
import EndpointsPage from './pages/dashboard/EndpointsPage';
import EndpointDetailPage from './pages/dashboard/EndpointDetailPage';
import TeamPage from './pages/dashboard/TeamPage';
import KeysPage from './pages/dashboard/KeysPage';
import AnalyticsPage from './pages/dashboard/AnalyticsPage';
import BillingPage from './pages/dashboard/BillingPage';
import DocsPage from './pages/dashboard/DocsPage';

// Public verification page (task 7.14)
import VerifyRequestPage from './pages/verify/VerifyRequestPage';

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Auth routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/verify-email" element={<VerifyEmailPage />} />

          {/* Protected dashboard routes — auth guard in DashboardLayout */}
          <Route path="/dashboard" element={<DashboardLayout />}>
            <Route index element={<OverviewPage />} />
            <Route path="endpoints" element={<EndpointsPage />} />
            <Route path="endpoints/:id" element={<EndpointDetailPage />} />
            <Route path="team" element={<TeamPage />} />
            <Route path="keys" element={<KeysPage />} />
            <Route path="analytics" element={<AnalyticsPage />} />
            <Route path="billing" element={<BillingPage />} />
            <Route path="docs" element={<DocsPage />} />
          </Route>

          {/* Public verification — unauthenticated (task 7.14) */}
          <Route path="/verify/:requestId" element={<VerifyRequestPage />} />

          {/* Default redirect */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
