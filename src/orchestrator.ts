/**
 * ClawGuard Orchestrator
 * Coordinates skill loading, analyzer execution, and result aggregation
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import {
  type Finding,
  type ScanOptions,
  type ScanResult,
  type SkillMeta,
  calculateRiskScore,
  getRiskLevel,
  summarizeFindings,
} from './types.js';
import {
  createStaticAnalyzer,
  createDependencyAnalyzer,
  createPromptAnalyzer,
  createSandboxAnalyzer,
  createSemanticAnalyzer,
} from './analyzers/index.js';
import { loadConfig } from './config.js';

// ============================================================================
// SKILL.md Parsing
// ============================================================================

/** Regex for YAML frontmatter (--- at start, --- to end) */
const FRONTMATTER_REGEX = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

/**
 * Parse YAML frontmatter (simple key: value parsing)
 * For production, use the 'yaml' package
 */
function parseSimpleYaml(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex > 0) {
      const key = trimmed.slice(0, colonIndex).trim();
      let value: string | string[] = trimmed.slice(colonIndex + 1).trim();
      
      // Handle quoted strings
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      
      // Handle arrays (simple case: [a, b, c])
      if (value.startsWith('[') && value.endsWith(']')) {
        value = value.slice(1, -1).split(',').map(s => s.trim().replace(/['"]/g, ''));
      }
      
      result[key] = value;
    }
  }
  
  return result;
}

/**
 * Parse SKILL.md file and extract metadata
 */
export async function parseSkillMd(skillPath: string): Promise<SkillMeta> {
  const skillMdPath = path.join(skillPath, 'SKILL.md');
  const dirName = path.basename(skillPath);
  
  // Default metadata using directory name
  const defaultMeta: SkillMeta = {
    name: dirName,
    path: skillPath,
  };
  
  try {
    const content = await fs.readFile(skillMdPath, 'utf-8');
    const match = content.match(FRONTMATTER_REGEX);
    
    if (match) {
      const [, frontmatterStr, body] = match;
      const frontmatter = parseSimpleYaml(frontmatterStr);
      
      return {
        name: (frontmatter.name as string) || dirName,
        version: frontmatter.version as string | undefined,
        author: frontmatter.author as string | undefined,
        description: frontmatter.description as string | undefined,
        path: skillPath,
        tools: frontmatter.tools as string[] | undefined,
        frontmatter,
        body: body.trim(),
      };
    } else {
      // No frontmatter, entire file is body
      return {
        ...defaultMeta,
        body: content.trim(),
      };
    }
  } catch (error) {
    // SKILL.md doesn't exist or isn't readable
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return defaultMeta;
    }
    throw error;
  }
}

// ============================================================================
// Orchestrator
// ============================================================================

interface AnalyzerEntry {
  name: string;
  instance: { analyze(skillPath: string): Promise<Finding[]> };
  skipUnlessSandbox?: boolean;
  skipUnlessSemantic?: boolean;
}

/**
 * Main scan orchestrator
 * Loads skill, runs analyzers, aggregates results
 */
export class Orchestrator {
  private analyzers: AnalyzerEntry[] = [];
  
  constructor() {
    // Register all analyzers
    this.analyzers = [
      { name: 'static', instance: createStaticAnalyzer() },
      { name: 'deps', instance: createDependencyAnalyzer() },
      { name: 'prompt', instance: createPromptAnalyzer() },
      { name: 'sandbox', instance: createSandboxAnalyzer(), skipUnlessSandbox: true },
    ];
  }
  
  /**
   * Get list of available analyzer names
   */
  getAnalyzerNames(): string[] {
    return this.analyzers.map(a => a.name);
  }
  
  /**
   * Run a full security scan on a skill
   */
  async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    
    // Resolve and validate path
    const skillPath = path.resolve(options.path);
    await this.validateSkillPath(skillPath);
    
    if (options.verbose) {
      console.log(`Scanning skill at: ${options.sourceLabel || skillPath}`);
    }
    
    // Parse SKILL.md
    const meta = await parseSkillMd(skillPath);

    // For remote scans, show the original URL instead of temp path
    if (options.sourceLabel) {
      meta.path = options.sourceLabel;
      // If no SKILL.md, the name defaults to the temp dir basename ("repo") — fix that
      if (meta.name === path.basename(skillPath)) {
        // Extract a meaningful name from the URL
        const urlMatch = options.sourceLabel.match(/\/([^/]+?)(?:\.git)?(?:\/?|\?.*)?$/);
        if (urlMatch) {
          meta.name = urlMatch[1];
        }
      }
    }

    if (options.verbose) {
      console.log(`Skill: ${meta.name}${meta.version ? ` v${meta.version}` : ''}`);
    }
    
    // Run all analyzers
    const allFindings: Finding[] = [];
    const analyzersRun: string[] = [];
    
    // Build list of analyzers to run
    const analyzersToRun = [...this.analyzers];
    
    // Add semantic analyzer if requested
    if (options.semantic) {
      try {
        // Load config for provider/model settings
        const config = await loadConfig();
        
        const semanticAnalyzer = await createSemanticAnalyzer({
          apiKey: options.apiKey || config.apiKey,
          provider: config.provider,
          model: config.model,
          baseUrl: config.baseUrl
        });
        analyzersToRun.push({ 
          name: 'semantic', 
          instance: semanticAnalyzer,
          skipUnlessSemantic: true 
        });
        
        if (options.verbose) {
          console.log(`🧠 Semantic analysis: ${config.provider}/${config.model}`);
        }
      } catch (error) {
        console.warn('Semantic analyzer not available:', (error as Error).message);
      }
    }
    
    for (const analyzer of analyzersToRun) {
      // Skip sandbox unless explicitly requested
      if (analyzer.skipUnlessSandbox && !options.sandbox) {
        continue;
      }
      
      if (options.verbose) {
        console.log(`Running ${analyzer.name} analyzer...`);
      }
      
      try {
        const findings = await analyzer.instance.analyze(skillPath);
        allFindings.push(...findings);
        analyzersRun.push(analyzer.name);
      } catch (error) {
        // Log error but continue with other analyzers
        console.error(`Error in ${analyzer.name} analyzer:`, error);
      }
    }
    
    // Calculate results
    const riskScore = calculateRiskScore(allFindings);
    const riskLevel = getRiskLevel(riskScore);
    const summary = summarizeFindings(allFindings);
    const scanTime = Date.now() - startTime;
    
    return {
      skill: meta,
      findings: allFindings,
      riskScore,
      riskLevel,
      scanTime,
      analyzersRun,
      summary,
    };
  }
  
  /**
   * Validate that the skill path exists, is a directory, and is safe to scan
   */
  private async validateSkillPath(skillPath: string): Promise<void> {
    // Block scanning sensitive system directories
    const resolved = path.resolve(skillPath);
    const BLOCKED_PATHS = ['/', '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/boot', '/proc', '/sys', '/dev'];
    const home = process.env.HOME || '/home';

    if (BLOCKED_PATHS.includes(resolved)) {
      throw new Error(`Refusing to scan system directory: ${resolved}`);
    }

    // Block scanning home directory root (common accident)
    if (resolved === home) {
      throw new Error(`Refusing to scan home directory root. Provide the skill subdirectory path instead.`);
    }

    // Detect path traversal attempts in the original input
    if (skillPath.includes('..') && resolved !== path.resolve(path.normalize(skillPath))) {
      throw new Error(`Suspicious path traversal detected: ${skillPath}`);
    }

    try {
      // Use lstat to detect symlinks before following them
      const lstat = await fs.lstat(resolved);

      if (lstat.isSymbolicLink()) {
        const realPath = await fs.realpath(resolved);
        // Ensure the symlink target isn't a blocked directory
        if (BLOCKED_PATHS.some(bp => realPath === bp || realPath.startsWith(bp + '/'))) {
          throw new Error(`Symlink points to restricted directory: ${realPath}`);
        }
      }

      const stat = await fs.stat(resolved);
      if (!stat.isDirectory()) {
        throw new Error(`Path is not a directory: ${skillPath}`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new Error(`Skill path does not exist: ${skillPath}`);
      }
      throw error;
    }
  }
}

/**
 * Create a new orchestrator instance
 */
export function createOrchestrator(): Orchestrator {
  return new Orchestrator();
}
