import { backend as osvBackend } from './osv';
import { type Backend, createScanner } from './scanner';
import { backend as snykBackend } from './snyk/index';

const registry: Record<string, Backend> = {
  osv: osvBackend,
  snyk: snykBackend,
};

const backendName = (Bun.env.SCANNER_BACKEND ?? 'osv').toLowerCase();
const selected = registry[backendName];

if (!selected) {
  process.stderr.write(
    `[@nebzdev/bun-security-scanner] Unknown SCANNER_BACKEND "${backendName}", falling back to osv.\n`
  );
}

export const scanner: Bun.Security.Scanner = createScanner(
  selected ?? osvBackend
);
