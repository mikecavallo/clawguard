/**
 * ClawGuard Orchestrator
 * Coordinates skill loading, analyzer execution, and result aggregation
 */
import { type ScanOptions, type ScanResult, type SkillMeta } from './types.js';
/**
 * Parse SKILL.md file and extract metadata
 */
export declare function parseSkillMd(skillPath: string): Promise<SkillMeta>;
/**
 * Main scan orchestrator
 * Loads skill, runs analyzers, aggregates results
 */
export declare class Orchestrator {
    private analyzers;
    constructor();
    /**
     * Get list of available analyzer names
     */
    getAnalyzerNames(): string[];
    /**
     * Run a full security scan on a skill
     */
    scan(options: ScanOptions): Promise<ScanResult>;
    /**
     * Validate that the skill path exists, is a directory, and is safe to scan
     */
    private validateSkillPath;
}
/**
 * Create a new orchestrator instance
 */
export declare function createOrchestrator(): Orchestrator;
