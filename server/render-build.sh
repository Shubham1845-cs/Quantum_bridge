#!/usr/bin/env bash
set -e

echo "==> Installing server dependencies..."
npm install

echo "==> Building TypeScript..."
cd server
npx tsc --project tsconfig.json

echo "==> Build complete."
