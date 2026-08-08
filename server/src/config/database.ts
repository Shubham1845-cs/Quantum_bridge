import mongoose from 'mongoose';
import { env } from './env.js';
import dns from 'node:dns';
import { URL } from 'node:url';

// Use Google DNS for all Node.js DNS lookups (ipv4first for Atlas compatibility)
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

/**
 * Resolves a mongodb+srv:// URI into a standard mongodb:// URI by manually
 * performing the SRV DNS lookup via Google DNS (8.8.8.8). This bypasses the
 * Windows system DNS resolver which often fails on SRV records for Atlas.
 */
async function resolveSrvUri(srvUri: string): Promise<string> {
  // Only process mongodb+srv:// URIs
  if (!srvUri.startsWith('mongodb+srv://')) {
    return srvUri;
  }

  const parsed = new URL(srvUri);
  const hostname = parsed.hostname; // e.g. quantumbridge.t9q2iko.mongodb.net
  const srvName = `_mongodb._tcp.${hostname}`;

  console.info(`[DB] Resolving SRV records for ${srvName} via Google DNS...`);

  // Use a custom resolver pointed at Google DNS to avoid system DNS failures
  const resolver = new dns.Resolver();
  resolver.setServers(['8.8.8.8', '8.8.4.4']);

  const records = await new Promise<dns.SrvRecord[]>((resolve, reject) => {
    resolver.resolveSrv(srvName, (err, addrs) => {
      if (err) reject(err);
      else resolve(addrs);
    });
  });

  if (!records.length) {
    throw new Error(`[DB] No SRV records found for ${srvName}`);
  }

  // Build host list from SRV records
  const hosts = records.map((r) => `${r.name}:${r.port}`).join(',');

  // Reconstruct as standard mongodb:// URI preserving credentials, db path and query params
  const userInfo = parsed.username
    ? `${parsed.username}:${parsed.password}@`
    : '';
  const dbPath = parsed.pathname ?? '/quantumbridge';

  // Preserve original query params and add replicaSet + tls=true (required for Atlas direct)
  const params = new URLSearchParams(parsed.search.replace(/^\?/, ''));
  if (!params.has('tls')) params.set('tls', 'true');
  if (!params.has('authSource')) params.set('authSource', 'admin');
  // authMechanism default (SCRAM-SHA-256) is fine for Atlas

  const directUri = `mongodb://${userInfo}${hosts}${dbPath}?${params.toString()}`;
  console.info(`[DB] Resolved direct URI with ${records.length} host(s)`);
  return directUri;
}

export async function connectWithRetry(): Promise<void> {
  // Resolve SRV once before retry loop — avoids repeated DNS lookups
  let connectionUri: string;
  try {
    connectionUri = await resolveSrvUri(env.MONGO_URI);
  } catch (srvErr) {
    // SRV resolution failed — fall back to original URI and let Mongoose try
    console.warn('[DB] SRV pre-resolution failed, falling back to original URI:', srvErr);
    connectionUri = env.MONGO_URI;
  }

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      await mongoose.connect(connectionUri);
      console.info(`[DB] Connected to MongoDB Atlas (attempt ${attempt})`);
      return;
    } catch (err) {
      const isLastAttempt = attempt === MAX_RETRIES;
      const delay = BASE_DELAY_MS * 2 ** (attempt - 1); // 1s, 2s, 4s

      if (isLastAttempt) {
        console.error(`[DB] Failed to connect after ${MAX_RETRIES} attempts. Exiting.`, err);
        process.exit(1);
      }

      console.warn(`[DB] Connection attempt ${attempt} failed. Retrying in ${delay}ms...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
