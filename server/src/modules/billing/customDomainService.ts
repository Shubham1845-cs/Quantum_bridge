import dns from 'node:dns/promises';
import { Organization } from '../organization/Organization.js';
import logger from '../../utils/logger.js';

// ---------------------------------------------------------------------------
// Custom domain validation (Req 8.10)
//
// Pro and Enterprise orgs may configure one custom domain for their proxy URL.
// Before activating the domain, we verify DNS CNAME ownership:
//   The custom domain must have a CNAME record pointing to the expected target.
//
// Expected CNAME target: proxy.quantumbridge.io
// ---------------------------------------------------------------------------

const CNAME_TARGET = 'proxy.quantumbridge.io';

export class CustomDomainError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'CustomDomainError';
    this.statusCode = statusCode;
  }
}

/**
 * Validates that `domain` has a CNAME record pointing to `proxy.quantumbridge.io`,
 * then activates it on the org.
 *
 * Throws CustomDomainError with:
 *   - 402 if the org is on the Free plan
 *   - 404 if the org is not found
 *   - 400 if the domain format is invalid
 *   - 422 if the CNAME record is missing or points to the wrong target
 */
export async function validateAndActivateCustomDomain(
  orgId: string,
  domain: string
): Promise<void> {
  // Basic domain format validation (no protocol, no path)
  if (!isValidDomainName(domain)) {
    throw new CustomDomainError(
      `Invalid domain format: "${domain}". Provide a bare hostname like "api.example.com".`,
      400
    );
  }

  const org = await Organization.findById(orgId).select('plan customDomain').lean();
  if (!org) {
    throw new CustomDomainError('Organization not found', 404);
  }

  // Req 8.10 — only Pro and Enterprise plans may use custom domains
  if (org.plan === 'free') {
    throw new CustomDomainError(
      'Custom domains require a Pro or Enterprise plan. Upgrade to enable this feature.',
      402
    );
  }

  // Verify DNS CNAME ownership
  await verifyCname(domain);

  // Activate the custom domain on the org
  await Organization.findByIdAndUpdate(orgId, {
    customDomain: domain,
    customDomainVerified: true,
  });

  logger.info('custom_domain_activated', { orgId, domain });
}

/**
 * Resolves the CNAME record for `domain` and checks it points to CNAME_TARGET.
 * Throws CustomDomainError (422) if the record is missing or incorrect.
 */
async function verifyCname(domain: string): Promise<void> {
  let cnameRecords: string[];

  try {
    cnameRecords = await dns.resolveCname(domain);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'ENOENT') {
      throw new CustomDomainError(
        `No CNAME record found for "${domain}". ` +
        `Add a CNAME record pointing to "${CNAME_TARGET}" and try again.`,
        422
      );
    }
    // Unexpected DNS error — surface as 422 with context
    const msg = err instanceof Error ? err.message : String(err);
    throw new CustomDomainError(
      `DNS lookup failed for "${domain}": ${msg}`,
      422
    );
  }

  // Normalise: strip trailing dot, lowercase
  const normalise = (s: string) => s.replace(/\.$/, '').toLowerCase();
  const target = normalise(CNAME_TARGET);
  const matched = cnameRecords.some((r) => normalise(r) === target);

  if (!matched) {
    throw new CustomDomainError(
      `CNAME record for "${domain}" points to "${cnameRecords[0]}" ` +
      `but must point to "${CNAME_TARGET}". Update your DNS and try again.`,
      422
    );
  }
}

/**
 * Minimal domain name validation — rejects URLs, IPs, and obviously malformed strings.
 * Accepts bare hostnames like "api.example.com".
 */
function isValidDomainName(domain: string): boolean {
  if (!domain || domain.includes('://') || domain.includes('/')) return false;
  // Each label: 1–63 chars, alphanumeric + hyphens, no leading/trailing hyphen
  const labelRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => labelRe.test(label));
}
