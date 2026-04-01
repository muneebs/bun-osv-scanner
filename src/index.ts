import { scanner as osvScanner } from './osv';
import { scanner as snykScanner } from './snyk/index';

const backend = (Bun.env.SCANNER_BACKEND ?? 'osv').toLowerCase();

if (backend !== 'osv' && backend !== 'snyk') {
  process.stderr.write(
    `[@nebzdev/bun-security-scanner] Unknown SCANNER_BACKEND "${backend}", falling back to osv.\n`,
  );
}

export const scanner: Bun.Security.Scanner = backend === 'snyk' ? snykScanner : osvScanner;
