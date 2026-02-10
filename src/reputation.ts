/**
 * ClawGuard Community Reputation
 * 
 * Trust signals from the community:
 * - "Audited by 47 agents, 0 issues" badges
 * - Author reputation scores
 * - Skill popularity and trust metrics
 */

import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const REPUTATION_API = process.env.CLAWGUARD_API || 'https://clawguard-api.onrender.com/api/v1';
const LOCAL_CACHE = join(homedir(), '.config', 'clawguard', 'reputation');

export interface SkillReputation {
  skillHash: string;
  skillName: string;
  
  // Scan stats
  totalScans: number;
  uniqueScanners: number;
  lastScanned: string;
  
  // Results
  passCount: number;
  failCount: number;
  passRate: number;
  
  // Trust signals
  auditCount: number;
  trustedAuditors: string[];
  
  // Risk assessment
  averageRiskScore: number;
  highestRiskScore: number;
  
  // Badge
  badge: 'verified' | 'trusted' | 'community' | 'unverified' | 'flagged';
  badgeReason: string;
}

export interface AuthorReputation {
  authorId: string;
  
  // Stats
  totalSkills: number;
  totalScans: number;
  
  // Trust
  verifiedIdentity: boolean;
  trustedBy: number;
  flaggedBy: number;
  
  // Score
  reputationScore: number;  // 0-100
  
  // Badge
  badge: 'trusted' | 'verified' | 'new' | 'flagged';
}

/**
 * Get reputation for a skill
 */
export async function getSkillReputation(skillHash: string): Promise<SkillReputation | null> {
  try {
    // Try API first
    const response = await fetch(`${REPUTATION_API}/reputation/skill/${skillHash}`, {
      signal: AbortSignal.timeout(5000)
    });
    
    if (response.ok) {
      const data = await response.json() as SkillReputation;
      
      // Cache locally
      await cacheReputation('skill', skillHash, data);
      
      return data;
    }
  } catch {
    // Try local cache
    return getCachedReputation('skill', skillHash);
  }
  
  return null;
}

/**
 * Get reputation for an author
 */
export async function getAuthorReputation(authorId: string): Promise<AuthorReputation | null> {
  try {
    const response = await fetch(`${REPUTATION_API}/reputation/author/${authorId}`, {
      signal: AbortSignal.timeout(5000)
    });
    
    if (response.ok) {
      const data = await response.json() as AuthorReputation;
      await cacheReputation('author', authorId, data);
      return data;
    }
  } catch {
    return getCachedReputation('author', authorId);
  }
  
  return null;
}

/**
 * Report a successful scan (contributes to reputation)
 */
export async function reportScan(params: {
  skillHash: string;
  skillName: string;
  scannerId: string;
  passed: boolean;
  riskScore: number;
  findings: number;
}): Promise<void> {
  try {
    await fetch(`${REPUTATION_API}/reputation/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(5000)
    });
  } catch {
    // Best effort - queue for later
    await queueReport(params);
  }
}

/**
 * Format reputation as badge string
 */
export function formatBadge(rep: SkillReputation): string {
  const icons: Record<string, string> = {
    verified: '✅',
    trusted: '🛡️',
    community: '👥',
    unverified: '❓',
    flagged: '⚠️'
  };
  
  const icon = icons[rep.badge] || '❓';
  
  return `${icon} ${rep.badge.toUpperCase()}: ${rep.totalScans} scans, ${rep.passRate}% pass rate`;
}

/**
 * Format author reputation
 */
export function formatAuthorBadge(rep: AuthorReputation): string {
  const icons: Record<string, string> = {
    trusted: '⭐',
    verified: '✓',
    new: '🆕',
    flagged: '⚠️'
  };
  
  return `${icons[rep.badge]} ${rep.authorId} (score: ${rep.reputationScore}/100)`;
}

/**
 * Calculate badge from stats
 */
export function calculateBadge(stats: {
  totalScans: number;
  passRate: number;
  auditCount: number;
  flagCount: number;
}): SkillReputation['badge'] {
  if (stats.flagCount > 0) return 'flagged';
  if (stats.auditCount >= 3 && stats.passRate >= 95) return 'verified';
  if (stats.totalScans >= 50 && stats.passRate >= 90) return 'trusted';
  if (stats.totalScans >= 10) return 'community';
  return 'unverified';
}

// Local caching helpers

async function cacheReputation(type: string, id: string, data: unknown): Promise<void> {
  try {
    const dir = join(LOCAL_CACHE, type);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, `${id}.json`), JSON.stringify(data));
  } catch { /* no-op */ }
}

async function getCachedReputation<T>(type: string, id: string): Promise<T | null> {
  try {
    const data = await readFile(join(LOCAL_CACHE, type, `${id}.json`), 'utf-8');
    return JSON.parse(data);
  } catch {
    return null;
  }
}

async function queueReport(params: unknown): Promise<void> {
  try {
    const queueFile = join(LOCAL_CACHE, 'pending_reports.json');
    let queue: unknown[] = [];
    try {
      const data = await readFile(queueFile, 'utf-8');
      queue = JSON.parse(data);
    } catch { /* no-op */ }
    queue.push({ ...params as object, queuedAt: new Date().toISOString() });
    await mkdir(LOCAL_CACHE, { recursive: true });
    await writeFile(queueFile, JSON.stringify(queue, null, 2));
  } catch { /* no-op */ }
}

/**
 * Flush pending reports
 */
export async function flushPendingReports(): Promise<number> {
  const queueFile = join(LOCAL_CACHE, 'pending_reports.json');
  let queue: unknown[] = [];
  
  try {
    const data = await readFile(queueFile, 'utf-8');
    queue = JSON.parse(data);
  } catch {
    return 0;
  }

  let sent = 0;
  const failed: unknown[] = [];

  for (const report of queue) {
    try {
      await fetch(`${REPUTATION_API}/reputation/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(report),
        signal: AbortSignal.timeout(5000)
      });
      sent++;
    } catch {
      failed.push(report);
    }
  }

  await writeFile(queueFile, JSON.stringify(failed, null, 2));
  return sent;
}
