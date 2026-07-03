# QuantumBridge Design Document

## Overview
This document outlines the design decisions, architecture, and design system implemented in the QuantumBridge Dashboard Frontend project.

## Architecture Overview

### Frontend Applications
The project consists of two main frontend applications:
1. **Web Application** (`apps/web/`) - Public-facing marketing site including landing page, pricing, and authentication pages
2. **Dashboard Application** (`apps/dashboard/`) - Secure, logged-in user application for managing quantum-safe API proxies

### Backend Services
- **Server** (`server/`) - Node.js/Express API handling authentication, email verification, database connections, and business logic
- **Proxy** - Gateway layer routing requests between frontend applications and backend server
- **Shared** (`shared/`) - Shared types, utilities, and constants between frontend and backend

## Design System

### Theme & Styling
- **Theme**: Deep dark mode with vibrant neon accents (cyber blue `#00FFFF`, violet `#8A2BE2`)
- **Styling Framework**: Tailwind CSS v4 with custom CSS for advanced effects
- **Design Language**: Glassmorphism, specialized animations, and immersive "Quantum" feel

### Color System
- **Dashboard Theme** (preserved):
  - `--color-cyber-cyan`: `#00FFFF`
  - `--color-neon-purple`: `#8A2BE2`
  - `--color-deep-space`: Dark background tone
  - `--color-void`: Deep space black
  
- **Landing Page Theme** (added):
  - Uses OKLCH color format with semantic naming (`--background`, `--primary`, etc.)
  - Extended radius system: `--radius-sm` through `--radius-4xl` (7 levels)
  - Extended color palette: 39 color variables mapping to Tailwind utilities

### Typography
- **Dashboard Font**: `--font-space` ('Space Grotesk')
- **Landing Page Fonts**:
  - `--font-heading`: 'Helvetica Now Display Bold', sans-serif
  - `--font-body`: 'Inter', sans-serif
- All fonts available via CSS variables for flexible usage

### Spacing & Radius
- Standard Tailwind spacing scale
- Enhanced radius system for landing page components
- Consistent spacing through Tailwind's utility-first approach

### Shadows & Effects
- **Dashboard Shadows** (preserved):
  - `--shadow-neon-cyan`
  - `--shadow-neon-purple`
  - `--shadow-neon-subtle`
- **Landing Page Effects**:
  - Glassmorphism effects with backdrop-filter fallbacks
  - Seamless video loop backgrounds
  - Scroll-linked parallax atmospheres
  - Animated metric cards with sparklines
  - 3D card hover effects
  - Rotary timeline with scroll-triggered animations

### Animation System
- **Library**: Framer Motion for primary animations
- **Custom Animations**:
  - `pulse-glow`: Pulsing glow effect
  - `float`: Gentle floating animation
  - `scanline`: Scanline effect for backgrounds
  - Scroll-triggered animations (Parallax, reveal effects)
  - Animated counters and sparklines in metric cards
  - Video crossfade transitions

## Component Architecture

### Landing Page Components (`src/components/landing/`)
All landing page components are isolated in the `src/components/landing/` directory:
1. **Footer.tsx** - Landing page footer with branding and links
2. **GlobalAtmosphere.tsx** - Fixed background layer with ambient particles, grid patterns, orbs, and light effects
3. **HelpContactSection.tsx** - Help and contact information section
4. **LandingHero.tsx** - Hero section component with Framer Motion animations
5. **MetricCard.tsx** - Glassmorphism-styled metric cards with animated counters and sparklines
6. **metricData.ts** - Constants for quantum bridge metrics
7. **NewsSection.tsx** - News and updates section
8. **QuantumAtmosphere.tsx** - Scroll-linked parallax atmosphere for cinematic sections
9. **QuantumDefenseConsole.tsx** - Interactive defense console visualization feature showcase
10. **QuantumPricing.tsx** - Pricing section with glassmorphism cards and feature lists
11. **RotaryTimeline.tsx** - "How It Works" timeline with rotary layout and scroll-triggered animations
12. **SeamlessVideoLoop.tsx** - Dual-buffer crossfade video background component
13. **SectionBridge.tsx** - Radial gradient glow component for smooth section transitions
14. **Sparkline.tsx** - SVG-based animated line chart with wave function calculations
15. **UICard3D.tsx** - 3D card component with hover effects

### Dashboard Components
Dashboard components follow the existing structure in `src/components/` with:
- Consistent use of Tailwind utility classes
- Framer Motion animations where appropriate
- Error boundaries and loading states
- Responsive design principles

## State Management

### Authentication
- **AuthContext**: Manages user authentication state
- **Token Storage**: 
  - Access tokens stored in memory only (security)
  - Refresh tokens stored in httpOnly cookies
  - Automatic token refresh on 401 responses

### State Management
- **React Query**: Server state management with intelligent caching
  - 30-second stale time, 5-minute cache time
  - Automatic refetching and background updates
- **React Context**: For global UI state (theme, sidebar state, etc.)
- **Local State**: Component-level state with useState/useReducer

## Routing & Navigation

### Router
- **Library**: React Router v6
- **Implementation**: All routes lazy-loaded with React.lazy() for code splitting
- **Protected Routes**: ProtectedRoute component checks authentication status

### Route Structure
```
/ (root)               → HomePage (landing page)
/login                 → LoginPage
/register              → RegisterPage
/verify-email          → VerifyEmailPage
/dashboard             → DashboardPage
/org/:orgId/*          → OrgLayout (organization-specific routes)
```

### Navigation Features
- React Router `Link` components for client-side navigation
- Anchor links for in-page navigation (`#vault`, `#plans`, etc.)
- Mobile-responsive navigation with hamburger menu
- Authentication-aware navigation buttons (login/logout/dashboard)
- Keyboard navigable menus and dropdowns and navigation elements

## Data Flow & API Integration

### API Client
- **Location**: `src/api/client.ts`
- **Features**:
  - Environment variable validation through `src/lib/env.ts`
  - Automatic JWT token attachment to requests
  - Automatic refresh token handling on 401 responses
  - Error standardization and throwable error objects
  - Request/response logging in development

### Data Fetching
- **Library**: React Query (TanStack Query v5)
- **Patterns**:
  - Query keys structured by resource and ID
  - Optimistic updates where appropriate
  - Pagination and infinite query patterns for lists
  - Mutation patterns for creates/updates/deletes
  - Cache invalidation strategies

### Environment Validation
- **Location**: `src/lib/env.ts`
- **Validated Variables**:
  - `VITE_API_URL`: API endpoint URL (required)
  - `VITE_STRIPE_PUBLIC_KEY`: Stripe publishable key (optional but recommended for payments)
- **Features**:
  - Runtime validation with helpful error messages
  - Development warnings for missing non-critical variables
  - Production failure for missing required variables

## Security Architecture

### Authentication Security
- **Access Tokens**: Stored in memory only (never in localStorage/sessionStorage)
- **Refresh Tokens**: Stored in httpOnly, secure cookies
- **Token Rotation**: Automatic refresh token rotation implemented in API
- **Session Management**: Automatic logout on token expiration/invalidity

### Data Protection
- **XSS Protection**: React's built-in XSS protection via JSX escaping
- **CORS**: Properly configured via API proxy
- **Security Headers**: Configured in vercel.json:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
  - Referrer-Policy: strict-origin-when-cross-origin
  - Permissions-Policy: Restrictive policy for sensitive features

### Environment Security
- **Validation**: All environment variables validated at startup
- **Secrets Management**: No secrets stored in client-side code
- **Environment Separation**: Different configurations for development/staging/production

## Performance Optimization

### Code Splitting
- **Route-Based Splitting**: Each page lazy-loaded via React.lazy()
- **Component-Level Splitting**: Heavy components (charts, maps) lazy-loaded when visible
- **Dynamic Imports**: Used for non-critical dependencies

### Bundle Optimization
- **Total Bundle Size**: ~328KB (107KB gzipped) for main bundle
- **Chunking**: Strategic splitting to avoid large chunks
  - Recharts split into separate chunk (~121KB / 39KB gzipped)
  - Lazy-loaded route components under 30KB each
- **Asset Optimization**: 
  - Optimized video formats and sizes for backgrounds
  - Compressed image assets
  - SVG icons via Lucide React for scalable vector graphics

### Rendering Performance
- **Animation Performance**: GPU-accelerated transforms and opacity changes
- **Render Optimization**: 
  - React.memo() for expensive components
  - useMemo/useCallback for expensive computations
  - Virtual scrolling for large lists (where applicable)
- **Paint Optimization**: 
  - CSS containment where beneficial
  - will-change properties for animated elements
  - Reduced motion preferences respected

### Data Loading Performance
- **Stale-While-Revalidate**: React Query's default caching strategy
- **Selective Subscriptions**: Only subscribing to needed data fields
- **Pagination**: Server-side pagination for large datasets
- **Cancelation**: Automatic cancellation of stale requests

## Responsive Design & Accessibility

### Breakpoints
- **Mobile**: < 640px
- **Tablet**: 640px - 1024px
- **Desktop**: > 1024px
- **Wide Desktop**: > 1280px (for dashboard layouts)

### Responsive Patterns
- **Tailwind-First**: Utility classes for responsive design (sm:, md:, lg:, xl:)
- **Flexible Containers**: Max-width containers with side padding
- **Stack-to-Side**: Vertical stacking on mobile, horizontal on desktop
- **Collapsible Navigations**: Hamburger menus on mobile, expanded on desktop
- **Adaptive Grids**: Column count changes based on screen width

### Accessibility Features
- **Semantic HTML**: Proper use of header, nav, main, section, article, footer
- **ARIA Labels**: Descriptive labels for icon buttons and complex components
- **Keyboard Navigation**: Full keyboard accessibility for interactive elements
- **Focus Management**: Visible focus outlines, logical tab order
- **Screen Reader Support**: Proper heading hierarchy and landmark roles
- **Color Contrast**: Minimum 4.5:1 ratio for text, 3:1 for UI components
- **Text Scaling**: Respects user font size preferences
- **Reduced Motion**: Respects prefers-reduced-motion media query

## Internationalization & Localization
*Note: Current implementation focuses on English locale with UTF-8 support*

### Implementation Approach
- **Static Text**: Externalized in JSON files (planned for future enhancement)
- **Date/Number Formatting**: Uses Intl API for locale-aware formatting
- **Direction Support**: LTR layout with considerations for RTL in future

## Error Handling & Logging

### Client-Side Error Handling
- **ErrorBoundary**: Global error boundary in `src/components/ErrorBoundary.tsx`
  - Component-level error isolation
  - Fallback UI with retry functionality
  - Error logging to console (development) and external service (production)
- **React Error Boundaries**: Component-level boundaries for isolated failures

### API Error Handling
- **Standardized Errors**: Consistent error shape from API client
- **HTTP Status Handling**: Specific handling for 401, 403, 404, 429, 5xx
- **Network Errors**: Distinction between network failures and HTTP errors
- **Form Validation**: Field-level and form-level error display

### Logging Strategy
- **Development**: Console.log/warn/error with contextual information
- **Production**: 
  - Errors sent to monitoring service
  - Performance metrics collected
  - User interaction analytics (privacy-compliant)
- **Log Levels**: Error, Warn, Info, Debug (respecting NODE_ENV)

## Testing Strategy

### Unit Testing
- **Framework**: Vitest with React Testing Library
- **Coverage Target**: 80%+ for business logic and utilities
- **Test Files**: `*.test.tsx` alongside components
- **Mocking**: 
  - MSW (Mock Service Worker) for API mocking
  - Jest-like mocking for utilities and hooks

### Integration Testing
- **User Flows**: Critical user journeys tested
- **API Integration**: Mocked API endpoints testing full request/response cycles
- **Authentication**: Login/logout/session flows tested

### End-to-End Testing
- **Framework**: Playwright (recommended for future implementation)
- **Scenarios**: 
  - User registration → email verification → login → dashboard navigation
  - Organization creation → endpoint creation → monitoring → alerting
  - Billing flow → subscription creation → payment → invoice retrieval

### Accessibility Testing
- **Automated**: axe-core integration for automated a11y testing
- **Manual**: Keyboard navigation and screen reader testing
- **Color Contrast**: Automated checking against WCAG guidelines

## Deployment & DevOps

### Build Process
- **Tool**: Vite with React plugin
- **Environment Variables**: 
  - Prefixed with `VITE_` for client-side exposure
  - Validated at build time
- **Optimization**: 
  - ESBuild for fast bundling
  - CSS deduplication and minification
  - Asset optimization and fingerprinting
  - Code splitting and lazy loading

### Environment Configuration
- **Development**: 
  - Vite dev server with hot module replacement
  - Source maps enabled
  - ESLint and TypeScript checking in dev loop
- **Staging**: 
  - Production-like build with feature flags
  - Testing environment variables
  - Limited user access for QA
- **Production**:
  - Optimized build with minification
  - Source maps disabled (or stored securely)
  - Strict CSP and security headers
  - CDN deployment ready

### Containerization (Future)
- **Dockerfile**: Multi-stage build for Node.js applications
- **Networking**: Exposed port configuration
- **Environment**: Runtime environment variable injection
- **Health Checks**: Container health check endpoints

### Monitoring & Observability
- **Performance Monitoring**: 
  - Core Web Vitals tracking
  - Custom performance metrics
  - Route change timing
- **Error Tracking**: 
  - Client-side error reporting
  - Performance degradation alerts
  - User impact analysis
- **Usage Analytics**: 
  - Feature adoption tracking
  - User journey analysis
  - Performance correlation with business metrics

## Future Enhancements

### Technical Improvements
1. **State Management Evaluation**: Consider Zustand or Jotai for simpler state management
2. **Build Optimization**: 
   - Bundle analyzer integration in CI
   - Tree shaking verification
   - Lazy loading of heavy libraries (Recharts, etc.)
3. **Testing Infrastructure**:
   - End-to-end testing with Playwright/Cypress
   - Visual regression testing
   - Performance benchmarking in CI
4. **Accessibility Enhancements**:
   - Comprehensive WCAG 2.2 AA compliance audit
   - Screen reader testing workflow
   - Keyboard navigation enhancements
5. **Internationalization**:
   - i18n framework integration (react-i18next or similar)
   - Locale detection and persistence
   - Right-to-left (RTL) layout support

### Feature Enhancements
1. **Dashboard Customization**: 
   - Widget-based dashboard layout
   - User-configurable metric displays
   - Saved dashboard views
2. **Collaboration Features**:
   - Real-time collaboration indicators
   - Commenting system on resources
   - Activity feeds and notifications
3. **Advanced Analytics**:
   - Custom report builder
   - Data export functionality (CSV, PDF)
   - Scheduled email reports
4. **Integration Ecosystem**:
   - Webhook endpoint for external integrations
   - API key management with rotation
   - SDK generation for popular languages
5. **Mobile Experience**:
   - Dedicated mobile dashboard views
   - Offline capabilities with sync
   - Push notifications for critical alerts

## Design Principles

### 1. Clarity Over Cleverness
- Prioritize clear, understandable interfaces over clever but confusing designs
- Use familiar patterns and conventions where appropriate
- Progressive disclosure for complex features

### 2. Consistency with Flexibility
- Maintain consistent visual language and interaction patterns
- Allow for purposeful variation to highlight important elements
- Consistent spacing, typography, and color usage

### 3. Performance as Feature
- Treat performance as a core feature, not an afterthought
- Budget performance metrics like other resources
- Optimize critical rendering path first

### 4. Accessibility First
- Design for accessibility from the start, not as an add-on
- Consider diverse user needs including motor, vision, and cognitive differences
- Test with assistive technologies regularly

### 5. Security by Design
- Assume hostile environment and design defenses accordingly
- Secure by default principles
- Regular security audits and dependency updates

### 6. Scalability Mindset
- Design components and systems to scale with usage
- Consider performance implications of feature additions
- Architecture that supports team growth and codebase evolution

## Dependencies & External Services

### Core Dependencies
- **React**: ^18.2.0 - UI library
- **ReactDOM**: ^18.2.0 - React DOM renderer
- **React Router DOM**: ^6.22.0 - Declarative routing
- **React Query**: ^5.0.0 - Server state management
- **Framer Motion**: ^11.0.0 - Animation library
- **Tailwind CSS**: ^4.0.0 - Utility-first CSS framework
- **TypeScript**: ^5.0.0 - Type-safe JavaScript
- **Vite**: ^4.0.0 - Build tool and dev server
- **Lucide React**: ^0.3.0 - Icon library
- **Radix UI Components**: ^1.0.0 - Accessible UI primitives
- **Class Variance Authority**: ^0.7.0 - Component variance utilities
- **Tailwind Merge**: ^2.5.0 - Conditional className merging

### Development Dependencies
- **Vitest**: ^1.0.0 - Unit testing framework
- **React Testing Library**: ^14.0.0 - Testing utilities for React
- **ESLint**: ^8.0.0 - Linting utility
- **Prettier**: ^3.0.0 - Code formatter
- **TypeScript**: ^5.0.0 - TypeScript compiler
- **PostCSS**: ^8.0.0 - CSS processor
- **Autoprefixer**: ^10.0.0 - CSS vendor prefixing

### External Services
- **API Backend**: Node.js/Express service handling business logic
- **Database**: PostgreSQL/MongoDB for persistent storage
- **Authentication**: JWT-based with refresh token rotation
- **Payments**: Stripe integration for subscription billing
- **Email**: Transactional email service (SendGrid/SES equivalent)
- **Monitoring**: Application performance monitoring and error tracking
- **CDN**: Content delivery network for global asset distribution

## Files & Directory Structure

```
quantumbridge/
├── .github/                 # GitHub workflows and templates
├── .git/                    # Git version control
├── .agent/                  # Agent configuration and rules
├── .claude/                 # Claude AI configuration
├── apps/
│   ├── web/                 # Public-facing marketing site
│   └── dashboard/           # Secure user dashboard application
├── server/                  # Node.js/Express backend API
├── shared/                  # Shared types, utilities, constants
├── public/                  # Static assets
├── src/                     # Frontend source code (web/dashboard shared)
│   ├── components/          # Reusable UI components
│   │   ├── layout/          # Layout components (header, footer, sidebar)
│   │   ├── ui/              # Primitive UI components (buttons, inputs, modals)
│   │   ├── charts/          # Data visualization components
│   │   ├── forms/           # Form components and wrappers
│   │   └── landing/         # Landing page specific components (see above)
│   ├── hooks/               # Custom React hooks
│   ├── lib/                 # Utility libraries and helpers
│   ├── pages/               # Page components (route components)
│   ├── routes/              # Route definitions and protections
│   ├── store/               # State management (if using external store)
│   ├── styles/              # Global styles and theme definitions
│   ├── utils/               # Utility functions
│   ├── tests/               # Test utilities and mocks
│   ├── App.tsx              # Main application component
│   ├── main.tsx             # Application entry point
│   ├── index.css            # Global CSS and Tailwind configuration
│   └── env.ts               # Environment variable validation
├── tests/                   # Test configuration and setup
├── scripts/                 # Utility scripts (db operations, deployment helpers)
├── vite.config.ts           # Vite configuration
├── tsconfig.json            # TypeScript configuration
├── package.json             # Project dependencies and scripts
└── README.md                # Project documentation
```