import { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from '../context/AuthContext';
import { OrgProvider } from '../context/OrgContext';

// Create a custom render function that includes all providers
const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <OrgProvider>{children}</OrgProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
};

const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: AllTheProviders, ...options });

export * from '@testing-library/react';
export { customRender as render };

// Mock data helpers
export const mockUser = {
  _id: 'user123',
  email: 'test@example.com',
  emailVerified: true,
  createdAt: new Date().toISOString(),
};

export const mockOrg = {
  _id: 'org123',
  name: 'Test Organization',
  slug: 'test-org',
  plan: 'free' as const,
  createdAt: new Date().toISOString(),
};

export const mockEndpoint = {
  _id: 'endpoint123',
  orgId: 'org123',
  name: 'Test API',
  targetUrl: 'https://api.example.com',
  proxySlug: 'test-api',
  apiKey: 'test-key-123',
  isActive: true,
  ipAllowlist: [],
  requestCount: 42,
  createdAt: new Date().toISOString(),
};

export const mockProxyLog = {
  _id: 'log123',
  requestId: 'req-123',
  orgId: 'org123',
  endpointId: 'endpoint123',
  method: 'GET',
  path: '/users',
  statusCode: 200,
  latencyMs: 150,
  ecdsaVerified: true,
  dilithiumVerified: true,
  threatFlag: false,
  timestamp: new Date().toISOString(),
};
