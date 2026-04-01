import type { OsvVulnerability } from './client';
import { PREFERRED_REF_TYPES } from './config';

export function severityLevel(vuln: OsvVulnerability): 'fatal' | 'warn' {
  const s = vuln.database_specific?.severity?.toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return 'fatal';
  if (s === 'MODERATE' || s === 'LOW') return 'warn';

  // Fallback: numeric CVSS score (≥7.0 = HIGH/CRITICAL threshold).
  const score = vuln.database_specific?.cvss?.score;
  if (typeof score === 'number') return score >= 7.0 ? 'fatal' : 'warn';

  return 'warn';
}

export function advisoryUrl(vuln: OsvVulnerability): string {
  for (const type of PREFERRED_REF_TYPES) {
    const ref = vuln.references?.find((r) => r.type === type);
    if (ref) return ref.url;
  }
  return `https://osv.dev/vulnerability/${vuln.id}`;
}
