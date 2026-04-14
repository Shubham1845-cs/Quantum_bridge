import * as nodeCrypto from 'node:crypto';
import {
  generateKeyPairSync,
  createCipheriv,
  createDecipheriv,
  createSign,
  createVerify,
  randomBytes,
  pbkdf2,
  KeyObject,
} from 'node:crypto';
import { promisify } from 'node:util';
import { env } from '../../config/env.js';
import { KeyVault } from './KeyVault.js';
import logger from '../../utils/logger.js';
import { writeAuditLog } from '../../utils/auditLog.js';

// ---------------------------------------------------------------------------
// Exported interfaces
// ---------------------------------------------------------------------------

export interface DualSignature {
  ecdsaSignature: string;      // base64
  dilithiumSignature: string;  // base64
  keyVersion: number;
}

export interface VerifyResult {
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;         // true if either is false
}

export interface PublicKeySet {
  ecdsaPublicKey: string;      // PEM
  dilithiumPublicKey: string;  // base64
  version: number;
}

const pbkdf2Async = promisify(pbkdf2);

// ---------------------------------------------------------------------------
// Helpers (exported for reuse in tasks 2.7 / 2.8 / property tests)
// ---------------------------------------------------------------------------

/**
 * Derive a 32-byte AES-256 key from orgId + global pepper using PBKDF2-SHA-512.
 * Requirements: 11.1 — 310,000 iterations, SHA-512, unique salt per org.
 */
export async function deriveKey(orgId: string, salt: Buffer): Promise<Buffer> {
  const password = `${orgId}:${env.PBKDF2_GLOBAL_PEPPER}`;
  return pbkdf2Async(password, salt, 310_000, 32, 'sha512');
}

/**
 * Encrypt a plaintext buffer with AES-256-GCM.
 * Returns ciphertext = encrypted_data || 16-byte GCM auth tag, plus the 96-bit IV.
 * Requirements: 4.2 — AES-256-GCM, never persist plaintext.
 */
export function encryptKey(
  plaintext: Buffer,
  derivedKey: Buffer
): { ciphertext: Buffer; iv: Buffer } {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16-byte GCM auth tag
  return { ciphertext: Buffer.concat([encrypted, authTag]), iv };
}

/**
 * Decrypt an AES-256-GCM ciphertext (encrypted_data || auth_tag).
 * Requirements: 4.2 — authenticated decryption.
 */
export function decryptKey(ciphertext: Buffer, derivedKey: Buffer, iv: Buffer): Buffer {
  const authTag = ciphertext.subarray(-16);
  const data = ciphertext.subarray(0, -16);
  const decipher = createDecipheriv('aes-256-gcm', derivedKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ---------------------------------------------------------------------------
// KeyVaultService
// ---------------------------------------------------------------------------

/**
 * generateAndStore
 *
 * Requirements:
 *   4.1 — Auto-generate ECDSA P-256 + ML-DSA-65 keypairs on org creation.
 *   4.2 — Encrypt private keys with AES-256-GCM; never persist plaintext.
 *   4.3 — Store encrypted Key_Blob, IV, and version number.
 *   11.1 — PBKDF2 SHA-512, 310,000 iterations, unique salt per org.
 */
async function generateAndStore(orgId: string): Promise<void> {
  // ECDSA P-256
  const { privateKey: ecdsaPriv, publicKey: ecdsaPub } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // ML-DSA-65 (Node.js v24 native) — @types/node v20 doesn't know this algorithm yet
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { privateKey: dilithiumPriv, publicKey: dilithiumPub } = (generateKeyPairSync as any)(
    'ml-dsa-65'
  ) as { privateKey: KeyObject; publicKey: KeyObject };

  const salt = randomBytes(32);
  const derivedKey = await deriveKey(orgId, salt);

  const ecdsaPrivBuf = Buffer.from(ecdsaPriv);
  const { ciphertext: encECDSA, iv: ecdsaIv } = encryptKey(ecdsaPrivBuf, derivedKey);

  // Export ML-DSA-65 keys to raw buffers for encryption/storage
  const dilithiumPrivBuf = dilithiumPriv.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const dilithiumPubStr = (dilithiumPub.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');

  const { ciphertext: encDilithium, iv: dilithiumIv } = encryptKey(dilithiumPrivBuf, derivedKey);

  // Overwrite plaintext private key buffers before storing (Req 4.2)
  ecdsaPrivBuf.fill(0);
  dilithiumPrivBuf.fill(0);
  derivedKey.fill(0);

  await KeyVault.create({
    orgId,
    version: 1,
    encryptedECDSAPrivKey: encECDSA,
    ecdsaPublicKey: ecdsaPub,
    ecdsaIv,
    encryptedDilithiumPrivKey: encDilithium,
    dilithiumPublicKey: dilithiumPubStr,
    dilithiumIv,
    salt,
    isActive: true,
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
  });
}

// ---------------------------------------------------------------------------
// sign
// Requirements: 4.4, 11.2, 11.3, 11.4
// ---------------------------------------------------------------------------

/**
 * Sign a payload with both ECDSA P-256 and ML-DSA-65.
 * Private keys are decrypted in isolated IIFE scopes and overwritten immediately.
 * No key material is ever logged.
 */
async function sign(
  orgId: string,
  payload: Buffer,
  requestId?: string,
): Promise<DualSignature> {
  const vault = await KeyVault.findOne({ orgId, isActive: true });
  if (!vault) throw new Error(`No active keypair for org: ${orgId}`);

  const derivedKey = await deriveKey(orgId, vault.salt);

  // Isolated IIFE scope — ECDSA private key never leaves this block
  const ecdsaSignature = await (async () => {
    const privKeyBuf = decryptKey(vault.encryptedECDSAPrivKey, derivedKey, vault.ecdsaIv);
    try {
      const signer = createSign('SHA256');
      signer.update(payload);
      return signer.sign(privKeyBuf, 'base64');
    } finally {
      privKeyBuf.fill(0); // overwrite plaintext key buffer
    }
  })();

  // Isolated IIFE scope — ML-DSA-65 private key never leaves this block
  const dilithiumSignature = await (async () => {
    const privKeyBuf = decryptKey(vault.encryptedDilithiumPrivKey, derivedKey, vault.dilithiumIv);
    try {
      // Node.js v24 native ML-DSA-65 signing
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const sig = (nodeCrypto as any).sign('ml-dsa-65', privKeyBuf, payload) as Buffer;
      return sig.toString('base64');
    } finally {
      privKeyBuf.fill(0); // overwrite plaintext key buffer
    }
  })();

  derivedKey.fill(0); // overwrite derived key after both signing operations

  // Log operation metadata — NO key material
  logger.info('signing_operation', {
    orgId,
    requestId,
    keyVersion: vault.version,
    algorithm: 'ECDSA-P256+ML-DSA-65',
  });

  return { ecdsaSignature, dilithiumSignature, keyVersion: vault.version };
}

// ---------------------------------------------------------------------------
// verify
// Requirements: 4.5, 11.3, 11.5
// ---------------------------------------------------------------------------

/**
 * Verify both ECDSA and ML-DSA-65 signatures.
 * Supports grace-period verification via optional `version` param.
 */
async function verify(
  orgId: string,
  payload: Buffer,
  sig: DualSignature,
  version?: number,
): Promise<VerifyResult> {
  const lookupVersion = version ?? sig.keyVersion;
  const vault = await KeyVault.findOne({ orgId, version: lookupVersion });

  if (!vault) {
    throw new Error(`KeyVault version ${lookupVersion} not found for org: ${orgId}`);
  }

  // Validate the vault is usable: either active or within grace period
  const now = new Date();
  const isActive = vault.isActive;
  const inGrace = vault.graceExpiresAt != null && vault.graceExpiresAt > now;

  if (!isActive && !inGrace) {
    throw new Error(`KeyVault version ${lookupVersion} has expired for org: ${orgId}`);
  }

  // Verify ECDSA P-256
  let ecdsaVerified = false;
  try {
    const verifier = createVerify('SHA256');
    verifier.update(payload);
    ecdsaVerified = verifier.verify(vault.ecdsaPublicKey, sig.ecdsaSignature, 'base64');
  } catch {
    ecdsaVerified = false;
  }

  // Verify ML-DSA-65 using Node.js v24 native crypto
  let dilithiumVerified = false;
  try {
    const pubKeyBuf = Buffer.from(vault.dilithiumPublicKey, 'base64');
    const sigBuf = Buffer.from(sig.dilithiumSignature, 'base64');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    dilithiumVerified = (nodeCrypto as any).verify('ml-dsa-65', pubKeyBuf, payload, sigBuf) as boolean;
  } catch {
    dilithiumVerified = false;
  }

  const threatFlag = !ecdsaVerified || !dilithiumVerified;
  return { ecdsaVerified, dilithiumVerified, threatFlag };
}

// ---------------------------------------------------------------------------
// getPublicKeys
// Requirements: 4.5, 11.5
// ---------------------------------------------------------------------------

/**
 * Return only public keys and version — never private key material.
 */
async function getPublicKeys(orgId: string, version?: number): Promise<PublicKeySet> {
  let vault;

  if (version !== undefined) {
    vault = await KeyVault.findOne({ orgId, version });
    if (!vault) {
      throw new Error(`KeyVault version ${version} not found for org: ${orgId}`);
    }
    const now = new Date();
    const isActive = vault.isActive;
    const inGrace = vault.graceExpiresAt != null && vault.graceExpiresAt > now;
    if (!isActive && !inGrace) {
      throw new Error(`KeyVault version ${version} has expired for org: ${orgId}`);
    }
  } else {
    vault = await KeyVault.findOne({ orgId, isActive: true });
    if (!vault) {
      throw new Error(`No active keypair for org: ${orgId}`);
    }
  }

  // Return only public fields — never encrypted blobs or IVs
  return {
    ecdsaPublicKey: vault.ecdsaPublicKey,
    dilithiumPublicKey: vault.dilithiumPublicKey,
    version: vault.version,
  };
}

// ---------------------------------------------------------------------------
// generateAndStoreWithVersion (internal helper for rotation)
// ---------------------------------------------------------------------------

/**
 * Like generateAndStore but accepts an explicit version number.
 * Used by rotate() to create the new keypair with version = old.version + 1.
 */
async function generateAndStoreWithVersion(orgId: string, version: number): Promise<void> {
  const { privateKey: ecdsaPriv, publicKey: ecdsaPub } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { privateKey: dilithiumPriv, publicKey: dilithiumPub } = (generateKeyPairSync as any)(
    'ml-dsa-65'
  ) as { privateKey: KeyObject; publicKey: KeyObject };

  const salt = randomBytes(32);
  const derivedKey = await deriveKey(orgId, salt);

  const ecdsaPrivBuf = Buffer.from(ecdsaPriv);
  const { ciphertext: encECDSA, iv: ecdsaIv } = encryptKey(ecdsaPrivBuf, derivedKey);

  const dilithiumPrivBuf = dilithiumPriv.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const dilithiumPubStr = (dilithiumPub.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
  const { ciphertext: encDilithium, iv: dilithiumIv } = encryptKey(dilithiumPrivBuf, derivedKey);

  ecdsaPrivBuf.fill(0);
  dilithiumPrivBuf.fill(0);
  derivedKey.fill(0);

  await KeyVault.create({
    orgId,
    version,
    encryptedECDSAPrivKey: encECDSA,
    ecdsaPublicKey: ecdsaPub,
    ecdsaIv,
    encryptedDilithiumPrivKey: encDilithium,
    dilithiumPublicKey: dilithiumPubStr,
    dilithiumIv,
    salt,
    isActive: true,
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
  });
}

// ---------------------------------------------------------------------------
// rotate
// Requirements: 4.6, 4.7, 4.8, 11.6
// ---------------------------------------------------------------------------

/**
 * Rotate the active keypair for an org:
 *   1. Mark current keypair isActive=false, set graceExpiresAt = now + 24h
 *   2. Generate new keypair with version = old.version + 1
 *   3. Write AuditLog entry for key.rotated
 */
async function rotate(
  orgId: string,
  actorUserId: string,
  ipAddress = '0.0.0.0',
): Promise<void> {
  const current = await KeyVault.findOne({ orgId, isActive: true });
  if (!current) throw new Error(`No active keypair for org: ${orgId}`);

  const graceExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // now + 24h

  // Mark old keypair inactive, set grace window (Req 4.6, 11.6)
  await KeyVault.updateOne(
    { _id: current._id },
    { isActive: false, graceExpiresAt },
  );

  const newVersion = current.version + 1;
  await generateAndStoreWithVersion(orgId, newVersion);

  logger.info('key_rotated', { orgId, oldVersion: current.version, newVersion });

  // Immutable audit record (Req 11.7)
  const { Types } = await import('mongoose');
  const actorObjectId = actorUserId === 'system'
    ? current.orgId  // system-triggered: use orgId as stand-in actor
    : new Types.ObjectId(actorUserId);

  await writeAuditLog({
    actorUserId: actorObjectId,
    orgId: current.orgId,
    action: 'key.rotated',
    targetResourceType: 'keyVault',
    targetResourceId: current._id.toString(),
    metadata: {
      oldVersion: current.version,
      newVersion,
      triggeredBy: actorUserId === 'system' ? 'scheduler' : 'manual',
    },
    ipAddress,
    timestamp: new Date(),
  });
}

// ---------------------------------------------------------------------------
// runRotationScheduler
// Requirements: 4.7 — auto-rotate every 90 days
// ---------------------------------------------------------------------------

let _schedulerInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start a daily interval that finds vaults expiring within 24 hours and rotates them.
 * Call once at server startup. Safe to call multiple times (idempotent).
 */
function runRotationScheduler(): void {
  if (_schedulerInterval) return; // already running

  const INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

  async function tick(): Promise<void> {
    const cutoff = new Date(Date.now() + 24 * 60 * 60 * 1000); // now + 24h
    const expiring = await KeyVault.find({
      isActive: true,
      expiresAt: { $lte: cutoff },
    });

    logger.info('rotation_scheduler_tick', { expiring: expiring.length });

    for (const vault of expiring) {
      try {
        await rotate(vault.orgId.toString(), 'system');
      } catch (err) {
        logger.error('rotation_scheduler_error', { orgId: vault.orgId, err });
      }
    }
  }

  // Run immediately on startup, then every 24h
  tick().catch((err) => logger.error('rotation_scheduler_initial_tick_error', { err }));
  _schedulerInterval = setInterval(() => {
    tick().catch((err) => logger.error('rotation_scheduler_tick_error', { err }));
  }, INTERVAL_MS);

  logger.info('rotation_scheduler_started', { intervalMs: INTERVAL_MS });
}

export const keyVaultService = {
  generateAndStore,
  sign,
  verify,
  getPublicKeys,
  rotate,
  runRotationScheduler,
};
