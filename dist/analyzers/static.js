/**
 * ClawGuard Static Code Analyzer
 *
 * Scans skill files for:
 * - Pattern-based malware detection
 * - Obfuscation detection (base64, hex, unicode)
 * - Fetch-and-execute patterns
 * - Persistence mechanisms
 * - AST analysis for JS/TS
 */
import { readFile, readdir, stat } from 'fs/promises';
import { join, extname, relative } from 'path';
import { parse as parseYaml } from 'yaml';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { parseJS, analyzeAST, astFindingsToFindings } from '../utils/ast.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// File extensions to scan
const SCANNABLE_EXTENSIONS = new Set([
    '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx',
    '.py', '.pyw',
    '.sh', '.bash', '.zsh', '.fish', '.ksh',
    '.rb',
    '.pl', '.pm',
    '.php',
    '.go',
    '.rs',
    '.md', '.markdown', '.txt', '.yaml', '.yml', '.json',
    '.toml', '.ini', '.cfg', '.conf',
]);
// Extensions for AST analysis
const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx']);
// TS extensions for future AST analysis (currently pattern matching only)
// const TS_EXTENSIONS = new Set(['.ts', '.mts', '.cts', '.tsx']);
// Max file size to scan (skip huge files)
const MAX_FILE_SIZE = 1024 * 1024; // 1MB
/**
 * Load and compile patterns from YAML file
 */
async function loadPatterns() {
    const patternsPath = join(__dirname, '..', 'patterns', 'code.yaml');
    try {
        const content = await readFile(patternsPath, 'utf-8');
        const parsed = parseYaml(content);
        return parsed.patterns.map((p) => ({
            id: p.id,
            name: p.name || p.id,
            regex: new RegExp(p.pattern, 'gi'),
            severity: p.severity,
            description: p.description,
            remediation: p.remediation || 'Review this code pattern for security issues.',
            fileTypes: p.fileTypes,
        }));
    }
    catch (err) {
        console.error(`Warning: Could not load patterns from ${patternsPath}:`, err);
        return [];
    }
}
/**
 * Recursively get all files in a directory
 */
async function getAllFiles(dir, baseDir = dir) {
    const files = [];
    try {
        const entries = await readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = join(dir, entry.name);
            // Skip hidden dirs, node_modules, etc.
            if (entry.name.startsWith('.') ||
                entry.name === 'node_modules' ||
                entry.name === '__pycache__' ||
                entry.name === 'venv' ||
                entry.name === '.git') {
                continue;
            }
            if (entry.isDirectory()) {
                const subFiles = await getAllFiles(fullPath, baseDir);
                files.push(...subFiles);
            }
            else if (entry.isFile()) {
                const ext = extname(entry.name).toLowerCase();
                if (SCANNABLE_EXTENSIONS.has(ext) || entry.name === 'SKILL.md') {
                    files.push(fullPath);
                }
            }
        }
    }
    catch {
        // Directory might not exist or be unreadable
    }
    return files;
}
/**
 * Find all pattern matches in content
 */
function findPatternMatches(content, patterns, filename, fileExt) {
    const findings = [];
    const lines = content.split('\n');
    for (const pattern of patterns) {
        // Skip if pattern is limited to specific file types and this isn't one
        if (pattern.fileTypes && !pattern.fileTypes.includes(fileExt)) {
            continue;
        }
        // Reset regex state
        pattern.regex.lastIndex = 0;
        let match;
        while ((match = pattern.regex.exec(content)) !== null) {
            // Find line number
            const upToMatch = content.slice(0, match.index);
            const lineNum = upToMatch.split('\n').length;
            // Get the line content for evidence
            const lineContent = lines[lineNum - 1] || '';
            const evidence = lineContent.trim().slice(0, 200);
            findings.push({
                id: pattern.id,
                category: 'code',
                severity: pattern.severity,
                title: pattern.name.replace(/-/g, ' '),
                description: pattern.description,
                location: `${filename}:${lineNum}`,
                evidence: evidence,
                remediation: pattern.remediation,
            });
            // Prevent infinite loops on zero-width matches
            if (match[0].length === 0) {
                pattern.regex.lastIndex++;
            }
        }
    }
    return findings;
}
/**
 * Detect obfuscation patterns that aren't covered by regex
 */
function detectObfuscation(content, filename) {
    const findings = [];
    const lines = content.split('\n');
    // Check for high ratio of non-printable or unusual characters
    // eslint-disable-next-line no-control-regex
    const nonPrintableCount = (content.match(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g) || []).length;
    if (nonPrintableCount > 10) {
        findings.push({
            id: 'T-CODE-003',
            category: 'code',
            severity: 'high',
            title: 'Non-printable characters detected',
            description: `File contains ${nonPrintableCount} non-printable characters - possible obfuscation`,
            location: filename,
            remediation: 'Remove non-printable characters. Use plain, readable code.',
        });
    }
    // Check for invisible unicode characters (zero-width joiners, etc.)
    const invisibleUnicode = content.match(/[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]/g);
    if (invisibleUnicode && invisibleUnicode.length > 5) {
        findings.push({
            id: 'T-CODE-003',
            category: 'code',
            severity: 'high',
            title: 'Invisible unicode characters detected',
            description: `File contains ${invisibleUnicode.length} invisible unicode characters - possible hidden content`,
            location: filename,
            remediation: 'Remove invisible unicode. These can hide malicious instructions.',
        });
    }
    // Check for extremely long lines (common in obfuscated code)
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].length > 1000) {
            // Check if it's mostly code vs data
            const line = lines[i];
            const alphanumRatio = (line.match(/[a-zA-Z0-9]/g) || []).length / line.length;
            if (alphanumRatio > 0.8) {
                findings.push({
                    id: 'T-CODE-002',
                    category: 'code',
                    severity: 'medium',
                    title: 'Extremely long line detected',
                    description: `Line ${i + 1} is ${lines[i].length} characters - possible obfuscated code`,
                    location: `${filename}:${i + 1}`,
                    evidence: lines[i].slice(0, 100) + '...',
                    remediation: 'Break up long lines. Obfuscated code is often single-line.',
                });
            }
        }
    }
    // Check for packed JavaScript patterns
    const packedPatterns = [
        { pattern: /eval\(function\(p,a,c,k,e,/, name: 'eval packer' },
        { pattern: /\['\\x/, name: 'hex array access' },
    ];
    for (const { pattern, name } of packedPatterns) {
        if (pattern.test(content)) {
            findings.push({
                id: 'T-CODE-002',
                category: 'code',
                severity: 'critical',
                title: 'Packed/obfuscated JavaScript detected',
                description: `Code uses ${name} pattern - JavaScript packing/obfuscation`,
                location: filename,
                remediation: 'Unpack and review the code. Legitimate code should be readable.',
            });
            break;
        }
    }
    // Check for _0x obfuscation with threshold logic
    // (minified code may have a few, but malware has many)
    const obfuscatedVars = content.match(/_0x[a-f0-9]{4,}/gi) || [];
    const OBFUSCATION_THRESHOLD = 10; // Threshold from npm-security-scanner
    if (obfuscatedVars.length >= OBFUSCATION_THRESHOLD) {
        // Calculate density to distinguish minified from malicious
        const uniqueVars = new Set(obfuscatedVars.map(v => v.toLowerCase()));
        const density = obfuscatedVars.length / (content.length / 1000); // per KB
        findings.push({
            id: 'T-CODE-002',
            category: 'code',
            severity: density > 5 ? 'critical' : 'high',
            title: 'Heavy obfuscation detected (_0x pattern)',
            description: `Found ${obfuscatedVars.length} obfuscated variable names (${uniqueVars.size} unique). Density: ${density.toFixed(1)}/KB`,
            location: filename,
            evidence: obfuscatedVars.slice(0, 5).join(', ') + (obfuscatedVars.length > 5 ? '...' : ''),
            remediation: 'Deobfuscate and review code. This pattern is common in npm malware.',
        });
    }
    return findings;
}
/**
 * Analyze a single file
 */
async function analyzeFile(filePath, baseDir, patterns) {
    const findings = [];
    try {
        // Check file size
        const stats = await stat(filePath);
        if (stats.size > MAX_FILE_SIZE) {
            return [{
                    id: 'T-META-001',
                    category: 'meta',
                    severity: 'info',
                    title: 'Large file skipped',
                    description: `File is ${Math.round(stats.size / 1024)}KB - skipped for performance`,
                    location: relative(baseDir, filePath),
                }];
        }
        // Read file content
        const content = await readFile(filePath, 'utf-8');
        const ext = extname(filePath).toLowerCase();
        const relPath = relative(baseDir, filePath);
        // Pattern matching
        const patternFindings = findPatternMatches(content, patterns, relPath, ext);
        findings.push(...patternFindings);
        // Obfuscation detection
        const obfuscationFindings = detectObfuscation(content, relPath);
        findings.push(...obfuscationFindings);
        // AST analysis for JavaScript
        if (JS_EXTENSIONS.has(ext)) {
            const ast = parseJS(content, relPath);
            if (ast) {
                const astFindings = analyzeAST(ast, content, relPath);
                const converted = astFindingsToFindings(astFindings, relPath);
                findings.push(...converted);
            }
        }
        // For TypeScript, we do pattern matching but skip AST (acorn doesn't handle TS)
        // A future enhancement could use @typescript-eslint/parser
    }
    catch {
        // File read error - might be binary or permission issue
    }
    return findings;
}
/**
 * Deduplicate findings (same id + location)
 */
function deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
        const key = `${f.id}:${f.location}:${f.evidence}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
/**
 * Create a static analyzer instance
 */
export function createStaticAnalyzer() {
    let patterns = null;
    return {
        async analyze(skillPath) {
            // Load patterns on first use
            if (!patterns) {
                patterns = await loadPatterns();
            }
            // Get all files to scan
            const files = await getAllFiles(skillPath);
            if (files.length === 0) {
                return [{
                        id: 'T-META-002',
                        category: 'meta',
                        severity: 'info',
                        title: 'No scannable files found',
                        description: 'The skill directory contains no files that can be analyzed',
                        location: skillPath,
                    }];
            }
            // Analyze all files
            const allFindings = [];
            for (const file of files) {
                const fileFindings = await analyzeFile(file, skillPath, patterns);
                allFindings.push(...fileFindings);
            }
            // Deduplicate and sort by severity
            const deduplicated = deduplicateFindings(allFindings);
            const severityOrder = {
                critical: 0,
                high: 1,
                medium: 2,
                low: 3,
                info: 4,
            };
            deduplicated.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
            return deduplicated;
        }
    };
}
// Default export for convenience
export default createStaticAnalyzer;
