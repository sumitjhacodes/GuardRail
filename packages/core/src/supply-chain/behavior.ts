import type { ParsedLockfile } from './checksums.js';
import type { BehaviorProfile, SupplyChainFinding, ThreatIntelligenceOptions } from './types.js';

/** Built-in offline deny list (historical / demo markers). */
export const BUILTIN_DENY_LIST: readonly string[] = [
  'event-stream@3.3.6',
  'flatmap-stream',
  'color-names-js',
];

const SUSPICIOUS_SCRIPT =
  /\b(curl|wget|powershell|Invoke-WebRequest|node\s+-e|eval\s*\(|child_process|npm\s+explore)\b/i;

/**
 * Scan lockfile packages for install-script / behavior policy violations.
 * Network allowlists are advisory — full runtime interception is out of scope.
 */
export function scanBehavior(
  packages: ParsedLockfile['packages'],
  profile: BehaviorProfile = {},
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  const childAllowed = profile.childProcess?.allowed !== false;
  const allow = new Set(profile.allowlistedInstallScripts ?? []);

  if (!childAllowed) {
    for (const pkg of packages) {
      if (pkg.hasInstallScript && !allow.has(pkg.name)) {
        findings.push({
          code: 'INSTALL_SCRIPT',
          severity: 'high',
          message: `Package "${pkg.name}@${pkg.version}" declares an install script (childProcess.allowed=false)`,
          package: pkg.name,
          version: pkg.version,
        });
      }
    }
  }

  if (profile.networkAccess?.blockUnknown) {
    const hosts = profile.networkAccess.allowedHosts ?? ['registry.npmjs.org'];
    findings.push({
      code: 'NETWORK_POLICY',
      severity: 'low',
      message: `Network allowlist active (${hosts.join(', ')}); enforce via install sandbox / firewall — Guardrail records policy only`,
    });
  }

  return findings;
}

/** Flag packages matching deny list or custom lookup. */
export async function scanThreats(
  packages: ParsedLockfile['packages'],
  options: ThreatIntelligenceOptions = {},
): Promise<SupplyChainFinding[]> {
  if (options.blockKnownMalicious === false) return [];

  const findings: SupplyChainFinding[] = [];
  const deny = new Set([
    ...BUILTIN_DENY_LIST.map((s) => s.toLowerCase()),
    ...(options.denyList ?? []).map((s) => s.toLowerCase()),
  ]);

  for (const pkg of packages) {
    const nameKey = pkg.name.toLowerCase();
    const nv = `${nameKey}@${pkg.version}`.toLowerCase();
    if (deny.has(nameKey) || deny.has(nv)) {
      findings.push({
        code: 'KNOWN_MALICIOUS',
        severity: 'critical',
        message: `Package "${pkg.name}@${pkg.version}" matches threat deny list`,
        package: pkg.name,
        version: pkg.version,
      });
      continue;
    }
    if (options.lookup) {
      const bad = await options.lookup({ name: pkg.name, version: pkg.version });
      if (bad) {
        findings.push({
          code: 'THREAT_FEED_HIT',
          severity: 'critical',
          message: `Package "${pkg.name}@${pkg.version}" flagged by threatIntelligence.lookup`,
          package: pkg.name,
          version: pkg.version,
        });
      }
    }
  }

  return findings;
}

/** Heuristic scan of a postinstall / scripts blob (fixtures / CI helpers). */
export function scanPostinstallScript(script: string, pkgName = 'unknown'): SupplyChainFinding[] {
  if (!SUSPICIOUS_SCRIPT.test(script)) return [];
  return [
    {
      code: 'SUSPICIOUS_POSTINSTALL',
      severity: 'high',
      message: `Suspicious install script patterns in "${pkgName}"`,
      package: pkgName,
    },
  ];
}
