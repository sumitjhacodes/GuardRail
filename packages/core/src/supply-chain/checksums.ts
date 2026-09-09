import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ChecksumAlgorithm, ChecksumOptions, SupplyChainFinding } from './types.js';

interface LockPackage {
  name?: string;
  version?: string;
  integrity?: string;
  resolved?: string;
  link?: boolean;
  hasInstallScript?: boolean;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
}

interface PackageLock {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
  dependencies?: Record<
    string,
    {
      version?: string;
      integrity?: string;
      resolved?: string;
      requires?: Record<string, string>;
      dependencies?: unknown;
    }
  >;
}

export interface ParsedLockfile {
  path: string;
  packages: Array<{
    name: string;
    version: string;
    integrity?: string;
    resolved?: string;
    /** npm workspace / file: link — no registry integrity */
    link: boolean;
    hasInstallScript: boolean;
    pathKey: string;
  }>;
}

function isLinkPackage(pkg: Pick<LockPackage, 'link' | 'resolved'>, resolved?: string): boolean {
  if (pkg.link) return true;
  const r = resolved ?? pkg.resolved;
  if (!r) return false;
  return r.startsWith('file:') || r.startsWith('link:') || r.startsWith('workspace:');
}

function packageNameFromPath(key: string, pkg: LockPackage): string {
  if (pkg.name) return pkg.name;
  if (!key || key === '') return '';
  // "node_modules/lodash" or "node_modules/@scope/pkg"
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  if (idx === -1) return key;
  return key.slice(idx + marker.length);
}

/**
 * Parse npm package-lock.json (v1–v3) into a flat package list.
 */
export async function parsePackageLock(sourcePath: string): Promise<ParsedLockfile> {
  const path = resolve(sourcePath);
  const raw = await readFile(path, 'utf8');
  const lock = JSON.parse(raw) as PackageLock;
  const packages: ParsedLockfile['packages'] = [];

  if (lock.packages) {
    for (const [key, pkg] of Object.entries(lock.packages)) {
      if (key === '') continue; // root project
      // Workspace package roots (e.g. "packages/core") are not registry installs
      if (!key.includes('node_modules/')) continue;
      const name = packageNameFromPath(key, pkg);
      if (!name) continue;
      packages.push({
        name,
        version: pkg.version ?? '0.0.0',
        integrity: pkg.integrity,
        resolved: pkg.resolved,
        link: isLinkPackage(pkg),
        hasInstallScript: Boolean(pkg.hasInstallScript),
        pathKey: key,
      });
    }
  } else if (lock.dependencies) {
    const walk = (deps: NonNullable<PackageLock['dependencies']>, prefix = '') => {
      for (const [name, info] of Object.entries(deps)) {
        packages.push({
          name,
          version: info.version ?? '0.0.0',
          integrity: info.integrity,
          resolved: info.resolved,
          link: isLinkPackage({ resolved: info.resolved }),
          hasInstallScript: false,
          pathKey: prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`,
        });
        if (info.dependencies && typeof info.dependencies === 'object') {
          walk(info.dependencies as NonNullable<PackageLock['dependencies']>, `node_modules/${name}`);
        }
      }
    };
    walk(lock.dependencies);
  }

  return { path, packages };
}

function expectedAlgoPrefix(algorithm: ChecksumAlgorithm): string {
  return `${algorithm}-`;
}

/**
 * Verify every package declares an integrity field matching the chosen algorithm family.
 * Does not re-download tarballs (offline-first) — validates lockfile hygiene.
 */
export async function verifyChecksums(
  options: ChecksumOptions = {},
): Promise<{ findings: SupplyChainFinding[]; packagesChecked: number; lockfile: string }> {
  const source = options.source ?? 'package-lock.json';
  const algorithm = options.algorithm ?? 'sha512';
  const requireIntegrity = options.requireIntegrity !== false;
  const parsed = await parsePackageLock(source);
  const findings: SupplyChainFinding[] = [];
  const prefix = expectedAlgoPrefix(algorithm);

  for (const pkg of parsed.packages) {
    // Workspace / file: links are local — npm omits integrity by design
    if (pkg.link) continue;

    if (!pkg.integrity) {
      if (requireIntegrity) {
        findings.push({
          code: 'MISSING_INTEGRITY',
          severity: 'high',
          message: `Package "${pkg.name}@${pkg.version}" has no integrity checksum in the lockfile`,
          package: pkg.name,
          version: pkg.version,
        });
      }
      continue;
    }
    if (!pkg.integrity.startsWith(prefix) && algorithm === 'sha512') {
      // Accept sha512 (npm default) or configured algorithm; warn on weaker hashes when sha512 required
      if (pkg.integrity.startsWith('sha1-') || pkg.integrity.startsWith('sha256-')) {
        findings.push({
          code: 'WEAK_INTEGRITY',
          severity: 'medium',
          message: `Package "${pkg.name}@${pkg.version}" uses weaker integrity than ${algorithm}`,
          package: pkg.name,
          version: pkg.version,
        });
      } else if (!pkg.integrity.includes('-')) {
        findings.push({
          code: 'INVALID_INTEGRITY',
          severity: 'high',
          message: `Package "${pkg.name}@${pkg.version}" has a malformed integrity field`,
          package: pkg.name,
          version: pkg.version,
        });
      }
    }
  }

  return { findings, packagesChecked: parsed.packages.length, lockfile: parsed.path };
}

/** Hash a string for advisory fingerprinting (not for lockfile re-verify). */
export function fingerprint(input: string, algorithm: ChecksumAlgorithm = 'sha512'): string {
  return `${algorithm}-${createHash(algorithm).update(input).digest('base64')}`;
}

export type { PackageLock };
