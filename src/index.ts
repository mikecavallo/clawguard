/**
 * ClawGuard - Security Scanner for AI Agent Skills
 */

export * from './types.js';
export { PromptAnalyzer, createPromptAnalyzer } from './analyzers/prompt.js';
export { createStaticAnalyzer } from './analyzers/static.js';
export { DepsAnalyzer, DependencyAnalyzer, createDependencyAnalyzer } from './analyzers/deps.js';
export { Orchestrator, createOrchestrator, parseSkillMd } from './orchestrator.js';

// Re-export helper functions for direct use
export {
  detectInvisibleUnicode,
  containsInvisibleUnicode,
  detectHiddenWhitespace,
  hasHiddenWhitespaceBlocks,
  detectHomoglyphs,
  hasHomoglyphObfuscation,
  detectRtlOverride,
  hasRtlOverride,
  parseSkillDocument,
} from './analyzers/prompt.js';

/**
 * Convenience function: scan a skill and return results
 */
export async function scan(skillPath: string, options: { semantic?: boolean; sandbox?: boolean; verbose?: boolean } = {}) {
  const { createOrchestrator: create } = await import('./orchestrator.js');
  const orchestrator = create();
  return orchestrator.scan({ path: skillPath, ...options });
}
