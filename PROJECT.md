  # QuantumBridge

  QuantumBridge is a modern, high-performance SaaS platform built with a microservices architecture. It features a premium, dark-themed aesthetic with cutting-edge UI/UX interactions including glassmorphism, dynamic animations, and custom WebGL/shader backgrounds.

  ## Architecture

  The project is structured into multiple interconnected services:

  * **Apps (Frontend)**:
    * `web`: The public-facing marketing site. Includes the landing page, pricing page, and authentication pages (Login, Registration, Email Verification). Built with React, Vite, and features Framer Motion animations and particle backgrounds.
    * `dashboard`: The secure, logged-in user application. Includes the main dashboard layout, user settings, system metrics, and premium hero components (e.g., ShaderBackground, PrismaHero).

  * **Server (Backend)**:
    * A Node.js/Express API that powers the application.
    * Handles authentication, email verification, database connections, and business logic.
    * Uses `.env` for configuration and environment variables.

  * **Proxy (Gateway)**:
    * A proxy layer routing requests between the frontend applications and the backend server.

  ## Design System

  QuantumBridge utilizes a unified, premium design language across all its frontend properties:
  * **Theme**: Deep dark mode with vibrant neon accents (cyber blue, violet).
  * **Styling**: Tailwind CSS combined with custom CSS for glassmorphism and specialized effects.
  * **Animations**: Framer Motion for scroll reveals, text pull-ups, and interactive micro-animations.
  * **Backgrounds**: Custom WebGL shaders and particle network animations for an immersive "Quantum" feel.

  ## Scripts & Automation

  The repository contains several utility scripts (located in `scripts/`) to aid in development and administrative tasks:
  * `verify-user.mjs`: Utility to manually verify user emails in the database.
  * `delete-user.mjs`: Utility to clean up test users from the database.

  ## Technology Stack
  * **Frontend**: React, Vite, Tailwind CSS, Framer Motion
  * **Backend**: Node.js, Express, PostgreSQL/MongoDB (Database)
  * **Design/UI Components**: Lucide Icons, 21st.dev inspired components
