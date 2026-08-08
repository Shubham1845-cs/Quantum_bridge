# QuantumBridge Dashboard Frontend

A modern, responsive React application for managing quantum-safe API proxies. Built with React, TypeScript, Vite, and Tailwind CSS.

## Features

- 🔐 **Authentication**: Secure login, registration, and email verification
- 🏢 **Organization Management**: Create and manage multiple organizations
- 🔌 **Endpoint Management**: Register and configure API endpoints with quantum-safe proxying
- 📊 **Real-time Analytics**: Monitor request volume, verification rates, and threats
- 🔑 **Key Management**: View and rotate cryptographic keypairs (ECDSA P-256 + ML-DSA-65)
- 👥 **Team Collaboration**: Invite members with role-based access control
- 💳 **Billing Integration**: Stripe-powered subscription management
- 🔔 **Webhook Configuration**: Set up automated threat notifications
- ✅ **Public Verification**: Independent signature verification for third parties
- 📚 **Integration Docs**: Code snippets for Node.js, Python, and cURL

## Tech Stack

- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite 8
- **Styling**: Tailwind CSS v4 with custom cyber theme
- **State Management**: TanStack Query (React Query) for server state
- **Routing**: React Router v7
- **HTTP Client**: Axios with automatic token refresh
- **Animations**: Framer Motion
- **Charts**: Recharts
- **Notifications**: React Hot Toast

## Prerequisites

- Node.js 18+ and npm
- QuantumBridge API Server running on port 3000 (see `../server/README.md`)

## Environment Variables

Create a `.env` file in the project root (use `.env.example` as template):

```env
# API Base URL (defaults to /api which proxies to localhost:3000 in development)
VITE_API_URL=/api

# Stripe Public Key (for billing integration)
VITE_STRIPE_PUBLIC_KEY=pk_test_your_stripe_public_key_here
```

### Environment Variable Details

- **VITE_API_URL**: Base URL for API requests. In development, `/api` is proxied to `http://localhost:3000` via Vite. In production, set this to your API server URL (e.g., `https://api.quantumbridge.io`).
- **VITE_STRIPE_PUBLIC_KEY**: Your Stripe publishable key for billing features. Get this from your Stripe dashboard.

## Development Setup

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Start the development server**:
   ```bash
   npm run dev
   ```

   The app will be available at `http://localhost:5173`

3. **Ensure the API server is running**:
   ```bash
   cd ../server
   npm run dev
   ```

## Build for Production

```bash
npm run build
```

This creates an optimized production build in the `dist/` directory.

## Preview Production Build

```bash
npm run preview
```

## Project Structure

```
src/
├── api/                    # API client layer
│   ├── client.ts          # Base HTTP client with interceptors
│   ├── auth.ts            # Authentication endpoints
│   ├── orgs.ts            # Organization endpoints
│   ├── endpoints.ts       # Endpoint management
│   ├── analytics.ts       # Analytics endpoints
│   ├── keys.ts            # Key management
│   ├── billing.ts         # Billing endpoints
│   ├── webhooks.ts        # Webhook management
│   ├── team.ts            # Team management
│   └── verify.ts          # Public verification
├── components/            # Reusable UI components
│   ├── ErrorBoundary.tsx  # Global error boundary
│   ├── ProtectedRoute.tsx # Auth guard for routes
│   ├── OrgLayout.tsx      # Layout for org pages
│   └── ...
├── context/
│   ├── AuthContext.tsx    # Authentication state
│   └── OrgContext.tsx     # Current organization state
├── hooks/
│   └── useToast.ts        # Toast notification hook
├── lib/
│   ├── queryClient.ts     # React Query configuration
│   ├── env.ts             # Environment variable validation
│   └── utils.ts           # Utility functions
├── pages/                 # Page components
│   ├── auth/              # Auth pages (login, register, verify)
│   ├── dashboard/         # Dashboard pages
│   └── ...
├── types/                 # TypeScript type definitions
├── App.tsx                # Main app component with routing
├── main.tsx               # App entry point
└── index.css              # Global styles and Tailwind config
```

## Key Features

### Authentication

- JWT access tokens stored in memory (never localStorage)
- Refresh tokens managed via httpOnly cookies
- Automatic token refresh on 401 responses
- Protected routes with redirect to login

### API Client

- Axios instance with request/response interceptors
- Automatic Authorization header injection
- Token refresh on 401 errors
- Error handling with user-friendly messages

### State Management

- React Query for server state (caching, refetching, mutations)
- React Context for auth and organization state
- Session storage for organization selection persistence

### Styling

- Tailwind CSS v4 with custom cyber theme
- Custom colors: `cyber-cyan` (#00FFFF), `neon-purple` (#8A2BE2)
- Custom shadows: `shadow-neon-cyan`, `shadow-neon-purple`
- Responsive design (mobile, tablet, desktop)
- Dark theme with gradient accents

### Performance

- Route-based code splitting with React.lazy()
- React Query caching with 30s stale time
- Lazy loading for images and components
- Optimized bundle size

### Security

- JWT tokens in memory only
- httpOnly cookies for refresh tokens
- Input sanitization to prevent XSS
- HTTPS-only in production
- Content Security Policy headers

## API Integration

The frontend communicates with the QuantumBridge API Server on port 3000. In development, Vite proxies `/api/*` requests to `http://localhost:3000`.

Example API call:
```typescript
import apiClient from './api/client';

// GET /orgs
const { data } = await apiClient.get('/orgs');
```

## Deployment

### Vercel (Recommended)

1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```

2. **Deploy**:
   ```bash
   vercel
   ```

3. **Set environment variables** in Vercel dashboard:
   - `VITE_API_URL`: Your production API URL
   - `VITE_STRIPE_PUBLIC_KEY`: Your Stripe public key

### Manual Deployment

1. Build the app:
   ```bash
   npm run build
   ```

2. Serve the `dist/` directory with any static file server (Nginx, Apache, etc.)

3. Configure your server to:
   - Serve `index.html` for all routes (SPA routing)
   - Proxy `/api/*` to your API server
   - Use HTTPS

## Testing

The project uses Vitest and React Testing Library for testing (to be implemented in Phase 10).

```bash
npm run test
```

## Accessibility

- Semantic HTML elements
- ARIA labels for icon-only buttons
- Keyboard navigation support
- Color contrast ratio ≥ 4.5:1
- Focus indicators for interactive elements

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Contributing

1. Create a feature branch
2. Make your changes
3. Run tests and linting
4. Submit a pull request

## License

Proprietary - QuantumBridge

## Support

For issues or questions, contact the development team or open an issue in the repository.
