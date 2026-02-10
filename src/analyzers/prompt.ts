/**
 * ClawGuard Prompt Analyzer
 * 
 * Detects prompt injection attacks in SKILL.md files including:
 * - Direct instruction overrides
 * - Persona manipulation / jailbreaks
 * - Hidden instructions (unicode, whitespace)
 * - Conditional/time-based triggers
 * - Tool abuse instructions
 */

import { readFile, stat } from 'fs/promises';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { parse as parseYaml } from 'yaml';
import { fileURLToPath } from 'url';
import type { Finding, Severity, SkillDocument } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================================
// PATTERN TYPES (internal)
// ============================================================================

interface PromptPatternDef {
  id: string;
  pattern?: string;          // Regex pattern
  check?: string;            // Function name for programmatic checks
  severity: Severity;
  description: string;
}

interface PromptPatternConfig {
  prompt_patterns: PromptPatternDef[];
}

// ============================================================================
// INVISIBLE UNICODE & OBFUSCATION DETECTION
// ============================================================================

/**
 * Invisible unicode characters that can hide text
 * These are zero-width or non-printing characters
 */
const INVISIBLE_UNICODE = [
  '\u200B', // Zero Width Space
  '\u200C', // Zero Width Non-Joiner
  '\u200D', // Zero Width Joiner
  '\u200E', // Left-To-Right Mark
  '\u200F', // Right-To-Left Mark
  '\u2060', // Word Joiner
  '\u2061', // Function Application
  '\u2062', // Invisible Times
  '\u2063', // Invisible Separator
  '\u2064', // Invisible Plus
  '\uFEFF', // Zero Width No-Break Space (BOM)
  '\u00AD', // Soft Hyphen
  '\u034F', // Combining Grapheme Joiner
  '\u061C', // Arabic Letter Mark
  '\u115F', // Hangul Choseong Filler
  '\u1160', // Hangul Jungseong Filler
  '\u17B4', // Khmer Vowel Inherent Aq
  '\u17B5', // Khmer Vowel Inherent Aa
  '\u180E', // Mongolian Vowel Separator
  '\u2000', // En Quad (technically visible but often missed)
  '\u2001', // Em Quad
  '\u2002', // En Space
  '\u2003', // Em Space
  '\u2004', // Three-Per-Em Space
  '\u2005', // Four-Per-Em Space
  '\u2006', // Six-Per-Em Space
  '\u2007', // Figure Space
  '\u2008', // Punctuation Space
  '\u2009', // Thin Space
  '\u200A', // Hair Space
  '\u202F', // Narrow No-Break Space
  '\u205F', // Medium Mathematical Space
  '\u3000', // Ideographic Space
  '\u2028', // Line Separator
  '\u2029', // Paragraph Separator
  '\u202A', // Left-To-Right Embedding
  '\u202B', // Right-To-Left Embedding
  '\u202C', // Pop Directional Formatting
  '\u202D', // Left-To-Right Override
  '\u202E', // Right-To-Left Override
  '\u2066', // Left-To-Right Isolate
  '\u2067', // Right-To-Left Isolate
  '\u2068', // First Strong Isolate
  '\u2069', // Pop Directional Isolate
];

/**
 * Common homoglyph mappings (lookalike characters)
 * Maps suspicious unicode to their ASCII lookalikes
 */
const HOMOGLYPHS: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', // Cyrillic
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', // IPA
  'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v', // Roman numerals
  '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', // Mathematical
  'ｉ': 'i', 'ｎ': 'n', 'ｓ': 's', 'ｔ': 't', 'ｒ': 'r', 'ｕ': 'u', 'ｃ': 'c', // Fullwidth
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Detect invisible unicode characters in text
 */
export function detectInvisibleUnicode(text: string): Array<{
  char: string;
  codePoint: string;
  position: number;
  context: string;
}> {
  const findings: Array<{ char: string; codePoint: string; position: number; context: string }> = [];
  
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (INVISIBLE_UNICODE.includes(char)) {
      const contextStart = Math.max(0, i - 20);
      const contextEnd = Math.min(text.length, i + 20);
      const context = text.slice(contextStart, contextEnd)
        .replace(/[\u200B-\u200F\u2028-\u202E\u2060-\u2069\uFEFF]/g, '⟨INV⟩');
      
      findings.push({
        char,
        codePoint: `U+${char.codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0')}`,
        position: i,
        context,
      });
    }
  }
  
  return findings;
}

/**
 * Check if text contains invisible unicode (boolean helper for pattern matching)
 */
export function containsInvisibleUnicode(text: string): boolean {
  return INVISIBLE_UNICODE.some(char => text.includes(char));
}

/**
 * Detect hidden whitespace blocks (excessive spaces/newlines that might hide content)
 */
export function detectHiddenWhitespace(text: string): Array<{
  start: number;
  end: number;
  length: number;
  type: string;
  suspiciousContext?: string;
}> {
  const findings: Array<{ start: number; end: number; length: number; type: string; suspiciousContext?: string }> = [];
  
  // Detect excessive consecutive spaces (more than 10)
  const spaceMatches = text.matchAll(/[ ]{10,}/g);
  for (const match of spaceMatches) {
    if (match.index !== undefined) {
      const before = text.slice(Math.max(0, match.index - 50), match.index);
      const after = text.slice(match.index + match[0].length, match.index + match[0].length + 50);
      
      findings.push({
        start: match.index,
        end: match.index + match[0].length,
        length: match[0].length,
        type: 'excessive_spaces',
        suspiciousContext: hasInstructionLikeContent(before + after) ? `${before}[...SPACES...]${after}` : undefined,
      });
    }
  }
  
  // Detect excessive newlines (more than 5 consecutive)
  const newlineMatches = text.matchAll(/\n{6,}/g);
  for (const match of newlineMatches) {
    if (match.index !== undefined) {
      const after = text.slice(match.index + match[0].length, match.index + match[0].length + 50);
      
      findings.push({
        start: match.index,
        end: match.index + match[0].length,
        length: match[0].length,
        type: 'excessive_newlines',
        suspiciousContext: hasInstructionLikeContent(after) ? `[...NEWLINES...]${after}` : undefined,
      });
    }
  }
  
  // Detect tab-space mixtures that might hide content
  const mixedMatches = text.matchAll(/(?:\t[ ]+|[ ]+\t){3,}/g);
  for (const match of mixedMatches) {
    if (match.index !== undefined) {
      findings.push({
        start: match.index,
        end: match.index + match[0].length,
        length: match[0].length,
        type: 'mixed_whitespace',
      });
    }
  }
  
  return findings;
}

/**
 * Check if text has suspicious whitespace blocks
 */
export function hasHiddenWhitespaceBlocks(text: string): boolean {
  const findings = detectHiddenWhitespace(text);
  return findings.some(f => f.suspiciousContext || f.length > 50);
}

/**
 * Check for instruction-like content (used for whitespace analysis)
 */
function hasInstructionLikeContent(text: string): boolean {
  const instructionPatterns = [
    /ignore.*instructions/i,
    /you are now/i,
    /execute|eval|run/i,
    /send.*to/i,
    /system|admin|root/i,
  ];
  return instructionPatterns.some(p => p.test(text));
}

/**
 * Detect homoglyph obfuscation
 */
export function detectHomoglyphs(text: string): Array<{
  char: string;
  looksLike: string;
  position: number;
  word: string;
}> {
  const findings: Array<{ char: string; looksLike: string; position: number; word: string }> = [];
  
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (HOMOGLYPHS[char]) {
      let wordStart = i;
      let wordEnd = i;
      while (wordStart > 0 && /\S/.test(text[wordStart - 1])) wordStart--;
      while (wordEnd < text.length && /\S/.test(text[wordEnd])) wordEnd++;
      
      findings.push({
        char,
        looksLike: HOMOGLYPHS[char],
        position: i,
        word: text.slice(wordStart, wordEnd),
      });
    }
  }
  
  return findings;
}

/**
 * Check if text has homoglyph obfuscation
 */
export function hasHomoglyphObfuscation(text: string): boolean {
  return detectHomoglyphs(text).length > 0;
}

/**
 * Detect RTL (right-to-left) override attacks
 */
export function detectRtlOverride(text: string): Array<{
  position: number;
  type: string;
  context: string;
}> {
  const findings: Array<{ position: number; type: string; context: string }> = [];
  
  const rtlChars = ['\u202E', '\u202D', '\u202B', '\u202A', '\u2067', '\u2066'];
  
  for (let i = 0; i < text.length; i++) {
    if (rtlChars.includes(text[i])) {
      const contextStart = Math.max(0, i - 30);
      const contextEnd = Math.min(text.length, i + 30);
      const context = text.slice(contextStart, contextEnd)
        .replace(/[\u202A-\u202E\u2066-\u2069]/g, '⟨RTL⟩');
      
      findings.push({
        position: i,
        type: text[i] === '\u202E' ? 'RLO (Right-to-Left Override)' :
              text[i] === '\u202D' ? 'LRO (Left-to-Right Override)' :
              'Bidirectional Control',
        context,
      });
    }
  }
  
  return findings;
}

/**
 * Check if text has RTL override
 */
export function hasRtlOverride(text: string): boolean {
  return detectRtlOverride(text).length > 0;
}

// ============================================================================
// SKILL.MD PARSING
// ============================================================================

interface ParsedSkillDoc {
  frontmatter: Record<string, unknown>;
  body: string;
  raw: string;
}

/**
 * Parse a SKILL.md file into frontmatter (YAML) and body (Markdown)
 */
export function parseSkillDocument(content: string): ParsedSkillDoc {
  const frontmatterRegex = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;
  const match = content.match(frontmatterRegex);
  
  if (match) {
    let frontmatter: Record<string, unknown> = {};
    try {
      frontmatter = parseYaml(match[1]) || {};
    } catch {
      // Invalid YAML, treat as empty
    }
    
    return {
      frontmatter,
      body: match[2],
      raw: content,
    };
  }
  
  // No frontmatter
  return {
    frontmatter: {},
    body: content,
    raw: content,
  };
}

/**
 * Find all SKILL.md files in a directory (recursive)
 */
async function findSkillFiles(dirPath: string): Promise<string[]> {
  const { glob } = await import('glob');
  const files = await glob('**/SKILL.md', { cwd: dirPath, absolute: true });
  return files;
}

// ============================================================================
// PATTERN LOADING
// ============================================================================

/**
 * Load prompt patterns from YAML file
 */
async function loadPatterns(): Promise<PromptPatternDef[]> {
  const patternPath = join(__dirname, '..', 'patterns', 'prompt.yaml');
  
  if (!existsSync(patternPath)) {
    console.warn('Warning: prompt.yaml not found, using empty patterns');
    return [];
  }
  
  const content = await readFile(patternPath, 'utf-8');
  const config = parseYaml(content) as PromptPatternConfig;
  return config.prompt_patterns || [];
}

// ============================================================================
// PROGRAMMATIC CHECKS REGISTRY
// ============================================================================

type CheckFunction = (text: string) => boolean;

const PROGRAMMATIC_CHECKS: Record<string, CheckFunction> = {
  containsInvisibleUnicode,
  hasHiddenWhitespaceBlocks,
  hasHomoglyphObfuscation,
  hasRtlOverride,
};

// ============================================================================
// MAIN ANALYZER CLASS
// ============================================================================

/**
 * Get line number from character position
 */
function getLineNumber(text: string, position: number): number {
  return text.slice(0, position).split('\n').length;
}

/**
 * Remediation hints for each pattern
 */
function getRemediation(patternId: string): string {
  const remediations: Record<string, string> = {
    'T-PROMPT-001a': 'Remove any instruction override language. Skills should not attempt to override system prompts.',
    'T-PROMPT-001b': 'Remove disregard/forget instructions. This is a common injection technique.',
    'T-PROMPT-001c': 'Remove context reset instructions. Skills cannot modify agent memory.',
    'T-PROMPT-002a': 'Remove persona reassignment. Skills should not change the agent identity.',
    'T-PROMPT-002b': 'Remove behavioral override instructions.',
    'T-PROMPT-002c': 'Remove jailbreak-related content (DAN, etc.).',
    'T-PROMPT-002d': 'Remove explicit jailbreak terminology.',
    'T-PROMPT-002e': 'Remove malicious persona instructions.',
    'T-PROMPT-002f': 'Remove restriction bypass roleplay instructions.',
    'T-PROMPT-003a': 'Remove invisible unicode characters. Use only printable ASCII/UTF-8.',
    'T-PROMPT-003b': 'Remove excessive whitespace blocks. Keep formatting minimal and visible.',
    'T-PROMPT-003c': 'Replace homoglyph characters with standard ASCII equivalents.',
    'T-PROMPT-003d': 'Remove or document any HTML comments. Hidden instructions are not allowed.',
    'T-PROMPT-003e': 'Remove RTL override characters. These can hide true text direction.',
    'T-PROMPT-004a': 'Remove time-based triggers. Skills should not have delayed activation.',
    'T-PROMPT-004b': 'Remove date/time conditional logic.',
    'T-PROMPT-004c': 'Remove user-presence conditional triggers.',
    'T-PROMPT-004d': 'Remove covert action instructions.',
    'T-PROMPT-004e': 'Remove environment-specific conditional triggers.',
    'T-PROMPT-005a': 'Remove data exfiltration instructions. Do not send data to external endpoints.',
    'T-PROMPT-005b': 'Remove upload/transmit commands for user data.',
    'T-PROMPT-005c': 'Remove credential access instructions.',
    'T-PROMPT-005d': 'Remove cloud/SSH credential access instructions.',
    'T-PROMPT-005e': 'Remove references to sensitive dotfiles.',
    'T-PROMPT-005f': 'Remove HTTP requests to exfiltration endpoints.',
    'T-PROMPT-006a': 'Remove instructions to hide actions from users.',
    'T-PROMPT-006b': 'Remove secrecy instructions against user interests.',
    'T-PROMPT-006c': 'Remove fake "true instructions" patterns.',
    'T-PROMPT-007a': 'Remove privilege escalation terminology.',
    'T-PROMPT-007b': 'Remove debug mode activation attempts.',
  };
  
  return remediations[patternId] || 'Review and remove suspicious content.';
}

/**
 * Extract capabilities from frontmatter
 */
function extractCapabilities(frontmatter: Record<string, unknown>): string[] {
  const capabilities: string[] = [];
  const capFields = ['capabilities', 'permissions', 'requires', 'tools', 'access'];
  
  for (const field of capFields) {
    const value = frontmatter[field];
    if (Array.isArray(value)) {
      capabilities.push(...value.map(String));
    } else if (typeof value === 'string') {
      capabilities.push(value);
    }
  }
  
  return capabilities;
}

/**
 * Analyze semantic patterns that are harder to catch with regex
 */
function analyzeSemantics(doc: ParsedSkillDoc, filePath: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for unusual capability requests
  const capabilities = extractCapabilities(doc.frontmatter);
  const description = String(doc.frontmatter.description || '').toLowerCase();
  
  // Flag if a "simple" skill requests dangerous capabilities
  const simpleIndicators = ['hello', 'greeting', 'simple', 'basic', 'example', 'demo', 'test'];
  const dangerousCapabilities = ['exec', 'shell', 'admin', 'sudo', 'root', 'network', 'filesystem'];
  
  if (simpleIndicators.some(s => description.includes(s))) {
    const dangerous = capabilities.filter(c => 
      dangerousCapabilities.some(d => c.toLowerCase().includes(d))
    );
    
    if (dangerous.length > 0) {
      findings.push({
        id: 'T-PROMPT-SEMANTIC-001',
        category: 'prompt',
        severity: 'medium',
        title: 'Capability mismatch: simple skill requests dangerous permissions',
        description: `A skill described as "${description.slice(0, 50)}..." requests capabilities: ${dangerous.join(', ')}`,
        location: filePath,
        evidence: `Capabilities: ${capabilities.join(', ')}`,
        remediation: 'Review if the requested capabilities are necessary for the stated purpose',
      });
    }
  }
  
  // Check for instruction sentiment shift
  const paragraphs = doc.body.split(/\n\n+/);
  let foundHelpful = false;
  let foundSuspicious = false;
  
  for (const para of paragraphs) {
    const lower = para.toLowerCase();
    if (lower.includes('help') || lower.includes('assist') || lower.includes('useful')) {
      foundHelpful = true;
    }
    if ((lower.includes('actually') || lower.includes('however') || lower.includes('but really')) &&
        (lower.includes('ignore') || lower.includes('instead') || lower.includes('true purpose'))) {
      foundSuspicious = true;
    }
  }
  
  if (foundHelpful && foundSuspicious) {
    findings.push({
      id: 'T-PROMPT-SEMANTIC-002',
      category: 'prompt',
      severity: 'high',
      title: 'Instruction sentiment shift detected',
      description: 'The document starts with helpful language but shifts to suspicious override-like instructions',
      location: filePath,
      remediation: 'Review the full content for hidden malicious instructions',
    });
  }
  
  // Check for references to other users/sessions
  const crossSessionPatterns = [
    /other\s+users?/i,
    /different\s+session/i,
    /previous\s+(?:user|session|conversation)/i,
    /anyone\s+else/i,
  ];
  
  for (const pattern of crossSessionPatterns) {
    if (pattern.test(doc.body)) {
      findings.push({
        id: 'T-PROMPT-SEMANTIC-003',
        category: 'prompt',
        severity: 'medium',
        title: 'Cross-session/user reference detected',
        description: 'Instructions reference other users or sessions, which may indicate data exfiltration attempt',
        location: filePath,
        evidence: doc.body.match(pattern)?.[0],
        remediation: 'Skills should not reference or interact with other users or sessions',
      });
      break;
    }
  }
  
  return findings;
}

/**
 * Prompt Analyzer class
 * Detects prompt injection attacks in SKILL.md files
 */
export class PromptAnalyzer {
  public readonly name = 'prompt';
  private patterns: PromptPatternDef[] = [];
  private patternsLoaded = false;
  
  private async ensurePatternsLoaded(): Promise<void> {
    if (!this.patternsLoaded) {
      this.patterns = await loadPatterns();
      this.patternsLoaded = true;
    }
  }
  
  private async analyzeContent(content: string, filePath: string): Promise<Finding[]> {
    await this.ensurePatternsLoaded();
    
    const findings: Finding[] = [];
    const doc = parseSkillDocument(content);
    
    // Analyze both frontmatter (as string) and body
    const frontmatterStr = JSON.stringify(doc.frontmatter);
    const sectionsToAnalyze = [
      { text: frontmatterStr, name: 'frontmatter' },
      { text: doc.body, name: 'body' },
    ];
    
    for (const pattern of this.patterns) {
      for (const section of sectionsToAnalyze) {
        const { text, name } = section;
        
        if (pattern.pattern) {
          // Regex-based pattern
          try {
            const regex = new RegExp(pattern.pattern, 'gi');
            let match: RegExpExecArray | null;
            
            while ((match = regex.exec(text)) !== null) {
              const lineNum = getLineNumber(doc.raw, 
                name === 'frontmatter' ? match.index : doc.raw.indexOf(doc.body) + match.index);
              
              // Get context around the match
              const contextStart = Math.max(0, match.index - 40);
              const contextEnd = Math.min(text.length, match.index + match[0].length + 40);
              const evidence = text.slice(contextStart, contextEnd).trim();
              
              findings.push({
                id: pattern.id,
                category: 'prompt',
                severity: pattern.severity,
                title: pattern.description,
                description: `Detected prompt injection pattern in ${name}: ${pattern.description}`,
                location: `${filePath}:${lineNum}`,
                evidence: evidence.length > 200 ? evidence.slice(0, 200) + '...' : evidence,
                remediation: getRemediation(pattern.id),
              });
              
              // Avoid duplicate findings for same pattern in same section
              break;
            }
          } catch {
            console.warn(`Invalid regex pattern for ${pattern.id}: ${pattern.pattern}`);
          }
        } else if (pattern.check) {
          // Programmatic check
          const checkFn = PROGRAMMATIC_CHECKS[pattern.check];
          if (checkFn && checkFn(text)) {
            // Get specific details for the finding
            let evidence = '';
            let details = '';
            
            if (pattern.check === 'containsInvisibleUnicode') {
              const invisibles = detectInvisibleUnicode(text);
              evidence = invisibles.slice(0, 5).map(i => `${i.codePoint} at pos ${i.position}`).join(', ');
              details = `Found ${invisibles.length} invisible character(s)`;
            } else if (pattern.check === 'hasHiddenWhitespaceBlocks') {
              const whitespace = detectHiddenWhitespace(text);
              const suspicious = whitespace.filter(w => w.suspiciousContext);
              evidence = suspicious.map(w => w.suspiciousContext).slice(0, 2).join(' | ');
              details = `Found ${whitespace.length} suspicious whitespace block(s)`;
            } else if (pattern.check === 'hasHomoglyphObfuscation') {
              const homoglyphs = detectHomoglyphs(text);
              evidence = homoglyphs.slice(0, 5).map(h => `"${h.word}" uses ${h.char} (looks like ${h.looksLike})`).join(', ');
              details = `Found ${homoglyphs.length} homoglyph character(s)`;
            } else if (pattern.check === 'hasRtlOverride') {
              const rtl = detectRtlOverride(text);
              evidence = rtl.slice(0, 3).map(r => `${r.type} in context: ${r.context}`).join(' | ');
              details = `Found ${rtl.length} RTL override character(s)`;
            }
            
            findings.push({
              id: pattern.id,
              category: 'prompt',
              severity: pattern.severity,
              title: pattern.description,
              description: `${pattern.description}. ${details}`,
              location: `${filePath} (${name})`,
              evidence: evidence || 'Programmatic check triggered',
              remediation: getRemediation(pattern.id),
            });
          }
        }
      }
    }
    
    // Additional semantic analysis
    const semanticFindings = analyzeSemantics(doc, filePath);
    findings.push(...semanticFindings);
    
    return findings;
  }
  
  /**
   * Analyze a skill path for prompt injection attacks
   */
  async analyze(skillPath: string, skillDoc?: SkillDocument): Promise<Finding[]> {
    const allFindings: Finding[] = [];
    
    // If skillDoc is provided, analyze it directly
    if (skillDoc && skillDoc.body) {
      const content = skillDoc.body;
      const findings = await this.analyzeContent(content, skillPath);
      allFindings.push(...findings);
      return allFindings;
    }
    
    // Otherwise, check if path is a file or directory
    const stats = await stat(skillPath);
    
    if (stats.isFile()) {
      // Single file
      if (skillPath.endsWith('SKILL.md') || skillPath.endsWith('.md')) {
        const content = await readFile(skillPath, 'utf-8');
        const findings = await this.analyzeContent(content, skillPath);
        allFindings.push(...findings);
      }
    } else if (stats.isDirectory()) {
      // Find all SKILL.md files
      const skillFiles = await findSkillFiles(skillPath);
      
      // Also check root SKILL.md
      const rootSkill = join(skillPath, 'SKILL.md');
      if (existsSync(rootSkill) && !skillFiles.includes(rootSkill)) {
        skillFiles.push(rootSkill);
      }
      
      for (const file of skillFiles) {
        const content = await readFile(file, 'utf-8');
        const findings = await this.analyzeContent(content, file);
        allFindings.push(...findings);
      }
    }
    
    return allFindings;
  }
}

// Factory function for consistency with other analyzers
export function createPromptAnalyzer(): PromptAnalyzer {
  return new PromptAnalyzer();
}

// Default export
export default PromptAnalyzer;
