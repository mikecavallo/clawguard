/**
 * ClawGuard shared type definitions
 */
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
    id: string;
    category: FindingCategory;
    severity: Severity;
    title: string;
    description: string;
    location?: string;
    evidence?: string;
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
    path: string;
    deep?: boolean;
    sandbox?: boolean;
    semantic?: boolean;
    output?: OutputFormat;
    verbose?: boolean;
    apiKey?: string;
    sourceLabel?: string;
}
export interface ScanResult {
    skill: SkillMeta;
    findings: Finding[];
    riskScore: number;
    riskLevel: RiskLevel;
    scanTime: number;
    analyzersRun: string[];
    summary: SeveritySummary;
}
export interface PatternDef {
    id: string;
    pattern: string;
    severity: Severity;
    description: string;
    remediation?: string;
    fileTypes?: string[];
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
export declare const SEVERITY_WEIGHTS: Record<Severity, number>;
export declare const RISK_THRESHOLDS: {
    readonly SAFE: 10;
    readonly LOW: 25;
    readonly MEDIUM: 50;
    readonly HIGH: 75;
};
/**
 * Calculate the risk score from findings
 */
export declare function calculateRiskScore(findings: Finding[]): number;
/**
 * Get risk level from score
 */
export declare function getRiskLevel(score: number): RiskLevel;
/**
 * Summarize findings by severity
 */
export declare function summarizeFindings(findings: Finding[]): SeveritySummary;
