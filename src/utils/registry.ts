/**
 * Registry API helpers for npm and PyPI
 */

export interface NpmPackageInfo {
  name: string;
  version: string;
  description?: string;
  createdAt: Date;
  modifiedAt: Date;
  downloadsLastWeek: number;
  maintainers: string[];
  hasInstallScripts: boolean;
  repository?: string;
  deprecated?: string;
}

export interface PypiPackageInfo {
  name: string;
  version: string;
  description?: string;
  createdAt?: Date;
  downloadsLastMonth?: number;
  maintainers: string[];
  repository?: string;
  yanked: boolean;
}

export interface RegistryCheckResult {
  exists: boolean;
  info?: NpmPackageInfo | PypiPackageInfo;
  error?: string;
}

// Rate limiting state
const rateLimitState = {
  npm: { lastCall: 0, minInterval: 100 },    // 10 req/sec max
  pypi: { lastCall: 0, minInterval: 100 },   // 10 req/sec max
  npmDownloads: { lastCall: 0, minInterval: 100 }
};

async function rateLimit(registry: keyof typeof rateLimitState): Promise<void> {
  const state = rateLimitState[registry];
  const now = Date.now();
  const timeSinceLastCall = now - state.lastCall;
  
  if (timeSinceLastCall < state.minInterval) {
    await new Promise(resolve => setTimeout(resolve, state.minInterval - timeSinceLastCall));
  }
  
  state.lastCall = Date.now();
}

/**
 * Check if a package exists on npm registry and get metadata
 */
export async function checkNpmPackage(packageName: string): Promise<RegistryCheckResult> {
  await rateLimit('npm');
  
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10000)
    });

    if (response.status === 404) {
      return { exists: false };
    }

    if (!response.ok) {
      return { 
        exists: false, 
        error: `HTTP ${response.status}: ${response.statusText}` 
      };
    }

    const data = await response.json() as unknown;
    const d = data as Record<string, unknown>;
    const distTags = d['dist-tags'] as Record<string, string> | undefined;
    const latestVersion = distTags?.latest;
    const versions = d.versions as Record<string, Record<string, unknown>> | undefined;
    const versionData = latestVersion && versions ? versions[latestVersion] : null;
    const timeData = (d.time || {}) as Record<string, string>;

    // Check for install scripts in the latest version
    const scripts = (versionData?.scripts || {}) as Record<string, unknown>;
    const hasInstallScripts = !!(
      scripts.preinstall ||
      scripts.install ||
      scripts.postinstall ||
      scripts.preuninstall ||
      scripts.uninstall ||
      scripts.postuninstall
    );

    // Get downloads (separate API call)
    let downloadsLastWeek = 0;
    try {
      downloadsLastWeek = await getNpmDownloads(packageName);
    } catch {
      // Ignore download fetch errors
    }

    const maintainersList = (d.maintainers || []) as Array<Record<string, unknown>>;
    const repo = d.repository as string | Record<string, unknown> | undefined;

    const info: NpmPackageInfo = {
      name: d.name as string,
      version: latestVersion || 'unknown',
      description: d.description as string | undefined,
      createdAt: new Date(timeData.created || 0),
      modifiedAt: new Date(timeData.modified || (latestVersion ? timeData[latestVersion] : '') || 0),
      downloadsLastWeek,
      maintainers: maintainersList.map((m) => (m.name || m.email || 'unknown') as string),
      hasInstallScripts,
      repository: typeof repo === 'string'
        ? repo
        : (repo as Record<string, unknown> | undefined)?.url as string | undefined,
      deprecated: versionData?.deprecated as string | undefined
    };

    return { exists: true, info };
  } catch (error) {
    return { 
      exists: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    };
  }
}

/**
 * Get weekly download count for an npm package
 */
async function getNpmDownloads(packageName: string): Promise<number> {
  await rateLimit('npmDownloads');
  
  const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
  const response = await fetch(url, {
    signal: AbortSignal.timeout(5000)
  });
  
  if (!response.ok) return 0;
  
  const data = await response.json() as Record<string, unknown>;
  return (data.downloads as number) || 0;
}

/**
 * Check if a package exists on PyPI and get metadata
 */
export async function checkPypiPackage(packageName: string): Promise<RegistryCheckResult> {
  await rateLimit('pypi');
  
  try {
    const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10000)
    });

    if (response.status === 404) {
      return { exists: false };
    }

    if (!response.ok) {
      return { 
        exists: false, 
        error: `HTTP ${response.status}: ${response.statusText}` 
      };
    }

    const data = await response.json() as Record<string, unknown>;
    const info_data = (data.info || {}) as Record<string, unknown>;
    const releases = (data.releases || {}) as Record<string, Array<Record<string, unknown>>>;

    // Find creation date from first release
    let createdAt: Date | undefined;
    const releaseVersions = Object.keys(releases);
    if (releaseVersions.length > 0) {
      const firstRelease = releases[releaseVersions[0]];
      if (firstRelease?.[0]?.upload_time) {
        createdAt = new Date(firstRelease[0].upload_time as string);
      }
    }

    // Check if latest version is yanked
    const latestVersion = info_data.version as string | undefined;
    const latestReleaseFiles = (latestVersion ? releases[latestVersion] : undefined) || [];
    const yanked = latestReleaseFiles.some((f) => f.yanked);

    const project_urls = (info_data.project_urls || {}) as Record<string, string>;

    const info: PypiPackageInfo = {
      name: info_data.name as string,
      version: latestVersion || 'unknown',
      description: info_data.summary as string | undefined,
      createdAt,
      maintainers: [info_data.author, info_data.maintainer].filter(Boolean) as string[],
      repository: project_urls.Source ||
                  project_urls.Repository ||
                  (info_data.home_page as string | undefined),
      yanked
    };

    return { exists: true, info };
  } catch (error) {
    return { 
      exists: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    };
  }
}

/**
 * Check package age (returns days since creation)
 */
export function getPackageAge(info: NpmPackageInfo | PypiPackageInfo): number | null {
  const createdAt = 'createdAt' in info ? info.createdAt : undefined;
  if (!createdAt) return null;
  
  const now = new Date();
  const diffMs = now.getTime() - createdAt.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Determine if a package is suspiciously new (< 30 days old with low downloads)
 */
export function isSuspiciouslyNew(info: NpmPackageInfo | PypiPackageInfo): boolean {
  const ageDays = getPackageAge(info);
  if (ageDays === null) return false;
  
  // Package is less than 30 days old
  if (ageDays >= 30) return false;
  
  // Check download threshold based on registry type
  if ('downloadsLastWeek' in info) {
    // npm: less than 100 downloads per week for a new package
    return info.downloadsLastWeek < 100;
  }
  
  // For PyPI without download data, just flag new packages
  return ageDays < 7;
}

/**
 * Batch check multiple packages with concurrency control
 */
export async function batchCheckNpm(
  packages: string[], 
  concurrency: number = 3
): Promise<Map<string, RegistryCheckResult>> {
  const results = new Map<string, RegistryCheckResult>();
  
  for (let i = 0; i < packages.length; i += concurrency) {
    const batch = packages.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(pkg => checkNpmPackage(pkg).then(result => ({ pkg, result })))
    );
    
    for (const { pkg, result } of batchResults) {
      results.set(pkg, result);
    }
  }
  
  return results;
}

/**
 * Batch check multiple PyPI packages with concurrency control
 */
export async function batchCheckPypi(
  packages: string[], 
  concurrency: number = 3
): Promise<Map<string, RegistryCheckResult>> {
  const results = new Map<string, RegistryCheckResult>();
  
  for (let i = 0; i < packages.length; i += concurrency) {
    const batch = packages.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(pkg => checkPypiPackage(pkg).then(result => ({ pkg, result })))
    );
    
    for (const { pkg, result } of batchResults) {
      results.set(pkg, result);
    }
  }
  
  return results;
}
