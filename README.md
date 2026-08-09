# QuantumBridge

A post-quantum cryptographic API proxy. QuantumBridge sits in front of any legacy API and adds dual cryptographic signatures — **ECDSA P-256** (classical) and **ML-DSA-65** (post-quantum) — to every proxied response, enabling clients to verify data integrity against future quantum threats.

🌐 **Live:** [https://www.quantumbridge.dpdns.org](https://www.quantumbridge.dpdns.org)  
🔧 **API:** [https://quantum-bridge-rjnr.onrender.com](https://quantum-bridge-rjnr.onrender.com)

---

## How It Works

```
Your Client App
      │  Bearer API Key
      ▼
Proxy Server (:8080)          ← adds signatures to every response
      │  forwards to →
Your Legacy API
      │  returns response
      ▼
Proxy Server                  ← signs with ECDSA P-256 + ML-DSA-65
      │
      ▼
Client gets response + headers:
  X-QB-ECDSA-Sig: <base64>
  X-QB-Dilithium-Sig: <base64>
  X-QB-Key-Version: <version>
```

---

## Monorepo Structure

```
quantumbridge/
├── server/             # Node.js API server + proxy server (Express, MongoDB, Redis)
├── quantum-core-site/  # React dashboard (Vite, Tailwind, TanStack Query)
└── shared/             # Shared TypeScript types
```

---

## Features

- **Dual signature proxy** — every response signed with ECDSA P-256 + ML-DSA-65 (post-quantum safe)
- **Key vault** — auto-rotating keypairs every 90 days with 24h grace period
- **Dashboard** — endpoint management, analytics, key rotation, team management, webhooks
- **Auth** — JWT access tokens (15min) + refresh token rotation via Redis (7 days), email verification via Resend
- **Billing** — Stripe integration (Free / Pro / Enterprise plans)
- **Webhooks** — threat alert delivery to configured HTTPS endpoints
- **Analytics** — per-request proxy logs with signature verification results

---

## Quick Start (Local Development)

### Prerequisites
- Node.js 20+
- MongoDB Atlas account
- Redis (Upstash free tier works)

### 1. Clone & Install

```bash
git clone https://github.com/Shubham1845-cs/Quantum_bridge
cd Quantum_bridge

# Install server dependencies
cd server && npm install

# Install frontend dependencies
cd ../quantum-core-site && npm install
```

### 2. Configure Environment

Create `server/.env`:

```env
NODE_ENV=development
PORT=3000
PROXY_PORT=8888

MONGO_URI=mongodb+srv://...
JWT_SECRET=<min 32 chars>
JWT_REFRESH_SECRET=<min 32 chars>
REDIS_URL=rediss://...
ALLOWED_ORIGIN=http://localhost:5173
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
RESEND_API_KEY=re_...
SENTRY_DSN=https://...
PBKDF2_GLOBAL_PEPPER=<min 32 chars>
```

Create `quantum-core-site/.env`:

```env
VITE_API_URL=/api
```

### 3. Run

```bash
# Terminal 1 — API server (port 3000)
cd server && npm run dev

# Terminal 2 — Frontend (port 5173)
cd quantum-core-site && npm run dev

# Terminal 3 — Proxy server (port 8888, optional for testing)
cd server && npm run dev:proxy
```

---

## Testing the Proxy (No Website Needed)

You can test using any free public API as the target:

| API | Target URL |
|---|---|
| JSONPlaceholder | `https://jsonplaceholder.typicode.com` |
| Open Meteo | `https://api.open-meteo.com` |
| Cat Facts | `https://catfact.ninja` |

**Steps:**
1. Register at `http://localhost:5173/register`
2. Go to **Endpoints → New Endpoint**, use `https://jsonplaceholder.typicode.com` as target
3. Copy the API key shown once
4. Start the proxy: `cd server && npm run dev:proxy`
5. Test the proxy:

```powershell
$key = "YOUR_API_KEY"
$slug = "YOUR_ORG_SLUG/YOUR_ENDPOINT_SLUG"

Invoke-WebRequest -Uri "http://localhost:8888/$slug/posts/1" `
  -Headers @{ Authorization = "Bearer $key" } `
  -UseBasicParsing | Select-Object StatusCode, Headers, Content
```

You'll see response headers:
- `X-QB-ECDSA-Sig` — classical ECDSA P-256 signature
- `X-QB-Dilithium-Sig` — post-quantum ML-DSA-65 signature
- `X-QB-Key-Version` — keypair version used

---

## Deployment

### Backend → Render

- **Root Directory:** *(blank)*
- **Build Command:** `chmod +x server/render-build.sh && bash server/render-build.sh`
- **Start Command:** `cd server && node dist/api-server.js`
- **Environment Variables:** Set all variables from `server/.env` in Render dashboard

### Frontend → Vercel

- **Root Directory:** `quantum-core-site`
- **Build Command:** `npm run build`
- **Output Directory:** `dist`
- The `vercel.json` proxies `/api/*` to the Render backend automatically

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `NODE_ENV` | ✅ | `development` or `production` |
| `MONGO_URI` | ✅ | MongoDB Atlas connection string |
| `JWT_SECRET` | ✅ | Min 32 chars |
| `JWT_REFRESH_SECRET` | ✅ | Min 32 chars |
| `REDIS_URL` | ✅ | Upstash Redis URL |
| `ALLOWED_ORIGIN` | ✅ | Frontend URL (e.g. `https://www.quantumbridge.dpdns.org`) |
| `RESEND_API_KEY` | ✅ | Email verification via Resend |
| `STRIPE_SECRET_KEY` | ✅ | Stripe billing |
| `STRIPE_WEBHOOK_SECRET` | ✅ | Stripe webhook validation |
| `SENTRY_DSN` | ✅ | Error tracking |
| `PBKDF2_GLOBAL_PEPPER` | ✅ | Min 32 chars, API key hashing |

---

## Tech Stack

| Layer | Tech |
|---|---|
| Frontend | React 19, Vite 8, Tailwind CSS 4, TanStack Query 5, Framer Motion |
| Backend | Node.js 24, Express 4, Mongoose 8 |
| Auth | JWT (15min), argon2id, Redis refresh token families |
| Signatures | ECDSA P-256 + ML-DSA-65 (post-quantum) |
| Database | MongoDB Atlas |
| Cache | Redis (Upstash) |
| Email | Resend |
| Billing | Stripe |
| Deployment | Render (API) + Vercel (Frontend) |

---

## License

MIT
