import { describe, expect, test } from 'bun:test';
import type { OsvVulnerability } from '../client';
import { advisoryUrl, severityLevel } from '../severity';

// Minimal fixture builder — only set what the test cares about.
function vuln(
  overrides: Partial<OsvVulnerability> & {
    dbSeverity?: string;
    cvssScore?: number;
  } = {}
): OsvVulnerability {
  const { dbSeverity, cvssScore, ...rest } = overrides;
  return {
    id: 'GHSA-test-0000-0000',
    ...rest,
    database_specific: {
      ...(dbSeverity && { severity: dbSeverity }),
      ...(cvssScore !== undefined && { cvss: { score: cvssScore } }),
    },
  };
}

describe('severityLevel', () => {
  test.each([
    ['CRITICAL', 'fatal'],
    ['HIGH', 'fatal'],
    ['MODERATE', 'warn'],
    ['LOW', 'warn'],
  ] as const)('maps %s → %s', (label, expected) => {
    expect(severityLevel(vuln({ dbSeverity: label }))).toBe(expected);
  });

  test('is case-insensitive', () => {
    expect(severityLevel(vuln({ dbSeverity: 'critical' }))).toBe('fatal');
    expect(severityLevel(vuln({ dbSeverity: 'high' }))).toBe('fatal');
  });

  test('unknown label → warn', () => {
    expect(severityLevel(vuln({ dbSeverity: 'UNKNOWN' }))).toBe('warn');
  });

  test('no database_specific → warn', () => {
    expect(severityLevel({ id: 'CVE-2021-0000' })).toBe('warn');
  });

  test.each([
    [9.8, 'fatal'],
    [7.0, 'fatal'],
    [6.9, 'warn'],
    [0.0, 'warn'],
  ] as const)('CVSS score %f → %s when no label', (score, expected) => {
    expect(severityLevel(vuln({ cvssScore: score }))).toBe(expected);
  });

  test('severity label takes precedence over CVSS score', () => {
    // LOW label with a 9.8 CVSS score — label wins.
    expect(severityLevel(vuln({ dbSeverity: 'LOW', cvssScore: 9.8 }))).toBe(
      'warn'
    );
  });
});

describe('advisoryUrl', () => {
  test('prefers ADVISORY reference type', () => {
    const v = vuln({
      references: [
        { type: 'WEB', url: 'https://web.example' },
        { type: 'ADVISORY', url: 'https://advisory.example' },
      ],
    });
    expect(advisoryUrl(v)).toBe('https://advisory.example');
  });

  test('falls back to WEB when no ADVISORY', () => {
    const v = vuln({
      references: [{ type: 'WEB', url: 'https://web.example' }],
    });
    expect(advisoryUrl(v)).toBe('https://web.example');
  });

  test('falls back to ARTICLE when no ADVISORY or WEB', () => {
    const v = vuln({
      references: [{ type: 'ARTICLE', url: 'https://article.example' }],
    });
    expect(advisoryUrl(v)).toBe('https://article.example');
  });

  test('falls back to OSV permalink when no preferred reference', () => {
    expect(advisoryUrl({ id: 'GHSA-xxxx-yyyy-zzzz' })).toBe(
      'https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz'
    );
  });

  test('falls back to OSV permalink when references is empty', () => {
    const v = vuln({ references: [] });
    expect(advisoryUrl(v)).toBe(
      'https://osv.dev/vulnerability/GHSA-test-0000-0000'
    );
  });
});
