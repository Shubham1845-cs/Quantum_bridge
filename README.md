# QuantumBridge

A post-quantum cryptographic API proxy. QuantumBridge sits in front of any legacy API and adds dual cryptographic signatures — **ECDSA P-256** (classical) and **ML-DSA-65** (post-quantum) — to every proxied response, enabling clients to verify data integrity against future quantum threats.

## Architecture

```
Client App  →  Proxy Server (:8080)  →  Your Legacy API
                     │
                     └─ Signs response with ECDSA P-256 + ML-DSA-65
                     └─ Returns signed headers to client
```

## Monorepo Structure

```
quantumbridge/
├── server/          # Node.js API + proxy server (Express, MongoDB, Redis)
├── quantum-core-site/  # React dashboard (Vite, Tailwind, TanStack Query)
└── shared/          # Shared TypeScript types
```

## Features

- **Dual signature proxy** — every response signed with ECDSA P-256 + ML-DSA-65
- **Key vault** — auto-rotating keypairs every 90 days with grace period
- **Dashboard** — endpoint management, analytics, key rotation, team management
- **Auth** — JWT + refresh token rotation via Redis, email verification
- **Billing** — Stripe integration (Free / Pro / Enterprise)
- **Webhooks** — threat alert delivery to HTTPS endpoints

## Quick Start

```bash
# Install dependencies
npm install
cd server && npm install
cd ../quantum-core-site && npm install

# Start API server (port 3000)
cd server && npm run dev

# Start frontend (port 5173)
cd quantum-core-site && npm run dev
```

## Environment Variables

Copy `server/.env.example` and fill in:

| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Min 32 char secret |
| `REDIS_URL` | Upstash Redis URL |
| `RESEND_API_KEY` | Resend email API key |
| `STRIPE_SECRET_KEY` | Stripe secret key |

## Tech Stack

- **Frontend**: React 19, Vite, Tailwind CSS, TanStack Query, Framer Motion
- **Backend**: Node.js, Express, Mongoose, Redis (Upstash)
- **Auth**: JWT, argon2id, refresh token rotation
- **Signatures**: ECDSA P-256 + ML-DSA-65
- **Email**: Resend
- **Billing**: Stripe

## License

MIT
