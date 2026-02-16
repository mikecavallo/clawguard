/**
 * ClawGuard - Security Scanner for AI Agent Skills
 */
export * from './types.js';
export { PromptAnalyzer, createPromptAnalyzer } from './analyzers/prompt.js';
export { createStaticAnalyzer } from './analyzers/static.js';
export { DepsAnalyzer, DependencyAnalyzer, createDependencyAnalyzer } from './analyzers/deps.js';
export { Orchestrator, createOrchestrator, parseSkillMd } from './orchestrator.js';
export { detectInvisibleUnicode, containsInvisibleUnicode, detectHiddenWhitespace, hasHiddenWhitespaceBlocks, detectHomoglyphs, hasHomoglyphObfuscation, detectRtlOverride, hasRtlOverride, parseSkillDocument, } from './analyzers/prompt.js';
/**
 * Convenience function: scan a skill and return results
 */
export declare function scan(skillPath: string, options?: {
    semantic?: boolean;
    sandbox?: boolean;
    verbose?: boolean;
}): Promise<import("./types.js").ScanResult>;
