import { events } from '../events/index.js';
import { nowIso } from '../utils/security.js';
import { parsePackageLock, verifyChecksums } from './checksums.js';
import { scanBehavior, scanThreats } from './behavior.js';
import type { SupplyChainFinding, VerifyImportsOptions, VerifyImportsResult } from './types.js';

/**
 * Offline-first supply-chain verification for npm lockfiles.
 * Run at startup or in CI — not on the HTTP hot path.
 */
export async function verifyImports(
  options: VerifyImportsOptions = {},
): Promise<VerifyImportsResult> {
  const failClosed = options.failClosed !== false;
  const timestamp = nowIso();
  const findings: SupplyChainFinding[] = [];
  let packagesChecked = 0;
  let lockfile: string | undefined;

  try {
    const sourceForParse =
      (options.checksums !== false && options.checksums?.source) ||
      options.lockfile ||
      'package-lock.json';

    const parsed = await parsePackageLock(sourceForParse);
    packagesChecked = parsed.packages.length;
    lockfile = parsed.path;

    if (options.checksums !== false) {
      const checksum = await verifyChecksums(options.checksums ?? { source: sourceForParse });
      findings.push(...checksum.findings);
      packagesChecked = checksum.packagesChecked;
      lockfile = checksum.lockfile;
    }

    if (options.behaviorProfile) {
      findings.push(...scanBehavior(parsed.packages, options.behaviorProfile));
    }

    if (options.threatIntelligence !== false) {
      const threats = await scanThreats(
        parsed.packages,
        options.threatIntelligence ?? { blockKnownMalicious: true },
      );
      findings.push(...threats);
    }

    const blocking = findings.some(
      (f) => f.severity === 'high' || f.severity === 'critical',
    );
    const ok = !blocking;

    if (!ok) {
      events.emit({
        type: 'block',
        violationType: 'SUPPLY_CHAIN',
        code: findings[0]?.code,
        message: findings[0]?.message,
        requestId: `supply_${timestamp}`,
        timestamp,
        meta: { findingCount: findings.length },
      });
    } else if (findings.length > 0) {
      events.emit({
        type: 'alert',
        violationType: 'SUPPLY_CHAIN',
        message: `${findings.length} non-blocking supply-chain finding(s)`,
        requestId: `supply_${timestamp}`,
        timestamp,
        meta: { findingCount: findings.length },
      });
    } else {
      events.emit({
        type: 'allow',
        requestId: `supply_${timestamp}`,
        timestamp,
        meta: { packagesChecked },
      });
    }

    return { ok, findings, packagesChecked, lockfile, timestamp };
  } catch (err) {
    if (options.debug) {
      console.error('[guardrail/supply-chain]', err);
    }
    const finding: SupplyChainFinding = {
      code: 'SUPPLY_CHAIN_ERROR',
      severity: 'critical',
      message: failClosed
        ? 'Supply-chain verification failed closed due to internal error'
        : err instanceof Error
          ? err.message
          : 'Supply-chain verification error',
    };
    if (failClosed) {
      events.emit({
        type: 'block',
        violationType: 'SUPPLY_CHAIN_ERROR',
        message: finding.message,
        requestId: `supply_${timestamp}`,
        timestamp,
      });
      return { ok: false, findings: [finding], packagesChecked, lockfile, timestamp };
    }
    throw err;
  }
}

export { parsePackageLock, verifyChecksums, fingerprint } from './checksums.js';
export {
  scanBehavior,
  scanThreats,
  scanPostinstallScript,
  BUILTIN_DENY_LIST,
} from './behavior.js';
export type * from './types.js';
