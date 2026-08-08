#!/usr/bin/env bash
set -e

echo "==> Installing server dependencies..."
cd server
npm install --production=false

echo "==> Building TypeScript..."
npm run build

echo "==> Build complete."
