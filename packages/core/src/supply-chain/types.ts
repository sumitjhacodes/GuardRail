export type ChecksumAlgorithm = 'sha512' | 'sha256' | 'sha1';

export interface ChecksumOptions {
  /** Path to package-lock.json (default: ./package-lock.json) */
  source?: string;
  algorithm?: ChecksumAlgorithm;
  /** Fail when a package lacks integrity (default: true) */
  requireIntegrity?: boolean;
}

export interface NetworkAccessProfile {
  allowedHosts?: string[];
  blockUnknown?: boolean;
}

export interface ChildProcessProfile {
  /** When false, packages with install scripts are flagged (default: true = allow) */
  allowed?: boolean;
}

export interface BehaviorProfile {
  networkAccess?: NetworkAccessProfile;
  childProcess?: ChildProcessProfile;
  /** Package names that may declare install scripts */
  allowlistedInstallScripts?: string[];
}

export interface ThreatIntelligenceOptions {
  /** Block packages on the built-in / provided deny list (default: true when set) */
  blockKnownMalicious?: boolean;
  /** Extra package names or name@version keys to deny */
  denyList?: string[];
  /** Optional async check — return true if package is malicious */
  lookup?: (pkg: { name: string; version: string }) => boolean | Promise<boolean>;
}

export interface VerifyImportsOptions {
  /** Path to package-lock.json (default: package-lock.json) */
  lockfile?: string;
  checksums?: ChecksumOptions | false;
  behaviorProfile?: BehaviorProfile;
  threatIntelligence?: ThreatIntelligenceOptions | false;
  /** Fail closed on parse/IO errors (default: true) */
  failClosed?: boolean;
  debug?: boolean;
}

export type SupplyChainFindingSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SupplyChainFinding {
  code: string;
  severity: SupplyChainFindingSeverity;
  message: string;
  package?: string;
  version?: string;
}

export interface VerifyImportsResult {
  ok: boolean;
  findings: SupplyChainFinding[];
  packagesChecked: number;
  lockfile?: string;
  timestamp: string;
}
