/**
 * ClawGuard shared type definitions
 */

// ============== Core Types ==============

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type OutputFormat = 'json' | 'md' | 'html';
export type FindingCategory = 'code' | 'supply' | 'prompt' | 'meta' | 'semantic' | 'chain' | 'semantic-chain' | 'honeypot';

export interface SkillMeta {
  name: string;
  path: string;
  version?: string;
  description?: string;
  author?: string;
  body?: string;
  tools?: string[];
  frontmatter?: Record<string, unknown>;
}

export interface Finding {
  id: string;                // e.g., "T-CODE-002"
  category: FindingCategory; // e.g., "code", "supply", "prompt"
  severity: Severity;
  title: string;
  description: string;
  location?: string;         // file:line
  evidence?: string;         // code snippet
  remediation?: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanOptions {
  path: string;              // Local path or URL
  deep?: boolean;            // Include dep source analysis
  sandbox?: boolean;         // Run behavioral sandbox
  semantic?: boolean;        // Run LLM-powered semantic analysis
  output?: OutputFormat;
  verbose?: boolean;
  apiKey?: string;           // Anthropic API key for semantic analysis
  sourceLabel?: string;      // Original URL for remote scans (shown in reports)
}

export interface ScanResult {
  skill: SkillMeta;
  findings: Finding[];
  riskScore: number;         // 0-100
  riskLevel: RiskLevel;
  scanTime: number;          // ms
  analyzersRun: string[];
  summary: SeveritySummary;
}

export interface PatternDef {
  id: string;
  pattern: string;
  severity: Severity;
  description: string;
  remediation?: string;
  fileTypes?: string[];      // Limit to specific extensions
}

export interface DetectionPattern {
  id: string;
  name: string;
  pattern: string;
  severity: Severity;
  description: string;
  remediation?: string;
}

export interface SkillDocument {
  meta: SkillMeta;
  body: string;
}

// ============== Analyzer Interfaces ==============

export interface Analyzer {
  name: string;
  analyze(skillPath: string, options?: ScanOptions): Promise<Finding[]>;
}

export interface StaticAnalyzer {
  analyze(skillPath: string): Promise<Finding[]>;
}

export interface DependencyAnalyzer {
  analyze(skillPath: string): Promise<Finding[]>;
}

export interface PromptAnalyzer {
  analyze(skillPath: string, skillDoc?: SkillDocument): Promise<Finding[]>;
}

export interface SandboxAnalyzer {
  analyze(skillPath: string): Promise<Finding[]>;
}

// ============== Risk Scoring ==============

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
};

export const RISK_THRESHOLDS = {
  SAFE: 10,
  LOW: 25,
  MEDIUM: 50,
  HIGH: 75,
} as const;

/**
 * Calculate the risk score from findings
 */
export function calculateRiskScore(findings: Finding[]): number {
  const score = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  return Math.min(100, score);
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): RiskLevel {
  if (score <= RISK_THRESHOLDS.SAFE) return 'SAFE';
  if (score <= RISK_THRESHOLDS.LOW) return 'LOW';
  if (score <= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score <= RISK_THRESHOLDS.HIGH) return 'HIGH';
  return 'CRITICAL';
}

/**
 * Summarize findings by severity
 */
export function summarizeFindings(findings: Finding[]): SeveritySummary {
  const summary: SeveritySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  
  for (const f of findings) {
    summary[f.severity]++;
  }
  
  return summary;
}
