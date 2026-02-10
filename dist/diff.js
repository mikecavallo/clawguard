/**
 * ClawGuard Differential Analysis
 *
 * Track skill versions and detect suspicious changes:
 * - "v1.2.3 added network access that wasn't in 1.2.2"
 * - Capability creep detection
 * - Content diff between versions
 */
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { glob } from 'glob';
import { createHash } from 'crypto';
const HISTORY_DIR = join(homedir(), '.config', 'clawguard', 'history');
// Capability detection patterns
const CAPABILITY_PATTERNS = {
    'network_access': [/fetch\s*\(/i, /axios/i, /curl/i, /wget/i, /http/i, /request\(/i],
    'file_read': [/readFile/i, /fs\.read/i, /open\s*\(/i, /cat\s+/i],
    'file_write': [/writeFile/i, /fs\.write/i, />\s*[^\s]/i, />>/i],
    'exec': [/exec\s*\(/i, /spawn/i, /child_process/i, /\$\(/i],
    'credential_access': [/\.ssh/i, /\.aws/i, /credentials/i, /\.env/i, /API_KEY/i],
    'persistence': [/cron/i, /\.bashrc/i, /\.zshrc/i, /startup/i],
    'messaging': [/telegram/i, /discord/i, /slack/i, /email/i, /smtp/i],
    'browser': [/puppeteer/i, /playwright/i, /browser/i, /selenium/i],
    'encoding': [/base64/i, /atob/i, /btoa/i, /Buffer\.from/i]
};
/**
 * Detect capabilities in content
 */
function detectCapabilities(content) {
    const caps = [];
    for (const [cap, patterns] of Object.entries(CAPABILITY_PATTERNS)) {
        if (patterns.some(p => p.test(content))) {
            caps.push(cap);
        }
    }
    return caps;
}
/**
 * Create snapshot of skill
 */
export async function createSnapshot(skillPath) {
    const files = await glob('**/*.{md,js,ts,py,sh,json,yaml,yml}', {
        cwd: skillPath,
        ignore: ['node_modules/**', '.git/**'],
        nodir: true
    });
    const allContent = [];
    const fileHashes = {};
    const allCaps = new Set();
    const sensitivePatterns = [];
    for (const file of files.sort()) {
        const content = await readFile(join(skillPath, file), 'utf-8');
        allContent.push(content);
        // Hash each file
        fileHashes[file] = createHash('sha256').update(content).digest('hex').slice(0, 16);
        // Detect capabilities
        detectCapabilities(content).forEach(c => allCaps.add(c));
        // Check for sensitive patterns
        if (/\.ssh|\.aws|credentials|password|secret|token/i.test(content)) {
            sensitivePatterns.push(file);
        }
    }
    // Try to get version from package.json
    let version;
    try {
        const pkg = await readFile(join(skillPath, 'package.json'), 'utf-8');
        version = JSON.parse(pkg).version;
    }
    catch { /* no-op */ }
    const fullHash = createHash('sha256')
        .update(allContent.join('\n'))
        .digest('hex');
    return {
        hash: fullHash,
        version,
        capturedAt: new Date().toISOString(),
        capabilities: Array.from(allCaps).sort(),
        fileHashes,
        sensitivePatterns
    };
}
/**
 * Load skill history
 */
async function loadHistory(skillName) {
    try {
        const data = await readFile(join(HISTORY_DIR, `${skillName}.json`), 'utf-8');
        return JSON.parse(data);
    }
    catch {
        return null;
    }
}
/**
 * Save skill history
 */
async function saveHistory(history) {
    await mkdir(HISTORY_DIR, { recursive: true });
    await writeFile(join(HISTORY_DIR, `${history.skillName}.json`), JSON.stringify(history, null, 2));
}
/**
 * Compare two snapshots and generate findings
 */
function compareSnapshots(oldSnap, newSnap, skillName) {
    const findings = [];
    // Check for new capabilities (capability creep)
    const oldCaps = new Set(oldSnap.capabilities);
    const newCaps = newSnap.capabilities.filter(c => !oldCaps.has(c));
    if (newCaps.length > 0) {
        const severity = newCaps.some(c => ['credential_access', 'exec', 'network_access'].includes(c)) ? 'high' : 'medium';
        findings.push({
            id: 'T-DIFF-CAPABILITY_CREEP',
            category: 'meta',
            severity,
            title: 'New Capabilities Added',
            description: `This skill version added new capabilities that weren't in the previous version:\n\n` +
                `New: ${newCaps.join(', ')}\n` +
                `Previous: ${oldSnap.capabilities.join(', ') || 'none'}`,
            location: skillName,
            evidence: `Version ${oldSnap.version || 'unknown'} → ${newSnap.version || 'unknown'}`,
            remediation: 'Review why these capabilities were added. Ensure they are necessary.'
        });
    }
    // Check for removed capabilities (might indicate cleanup after attack)
    const removedCaps = oldSnap.capabilities.filter(c => !newSnap.capabilities.includes(c));
    if (removedCaps.length > 0 && newCaps.length > 0) {
        findings.push({
            id: 'T-DIFF-SUSPICIOUS_SWAP',
            category: 'meta',
            severity: 'medium',
            title: 'Capabilities Swapped',
            description: `This update both added and removed capabilities, which could indicate obfuscation:\n\n` +
                `Added: ${newCaps.join(', ')}\n` +
                `Removed: ${removedCaps.join(', ')}`,
            location: skillName,
            evidence: `Capability swap in version ${newSnap.version || 'unknown'}`
        });
    }
    // Check for new sensitive file access
    const oldSensitive = new Set(oldSnap.sensitivePatterns);
    const newSensitive = newSnap.sensitivePatterns.filter(f => !oldSensitive.has(f));
    if (newSensitive.length > 0) {
        findings.push({
            id: 'T-DIFF-NEW_SENSITIVE_ACCESS',
            category: 'meta',
            severity: 'high',
            title: 'New Sensitive File References',
            description: `New files with sensitive patterns added:\n\n${newSensitive.join('\n')}`,
            location: skillName,
            evidence: `Files referencing credentials/secrets in version ${newSnap.version || 'unknown'}`
        });
    }
    // Check for file changes
    const changedFiles = [];
    const newFiles = [];
    const deletedFiles = [];
    for (const [file, hash] of Object.entries(newSnap.fileHashes)) {
        if (!oldSnap.fileHashes[file]) {
            newFiles.push(file);
        }
        else if (oldSnap.fileHashes[file] !== hash) {
            changedFiles.push(file);
        }
    }
    for (const file of Object.keys(oldSnap.fileHashes)) {
        if (!newSnap.fileHashes[file]) {
            deletedFiles.push(file);
        }
    }
    if (newFiles.length > 0 || changedFiles.length > 0) {
        findings.push({
            id: 'T-DIFF-FILE_CHANGES',
            category: 'meta',
            severity: 'info',
            title: 'File Changes Detected',
            description: [
                newFiles.length > 0 ? `New files: ${newFiles.join(', ')}` : '',
                changedFiles.length > 0 ? `Modified: ${changedFiles.join(', ')}` : '',
                deletedFiles.length > 0 ? `Deleted: ${deletedFiles.join(', ')}` : ''
            ].filter(Boolean).join('\n'),
            location: skillName,
            evidence: `${newFiles.length} new, ${changedFiles.length} modified, ${deletedFiles.length} deleted`
        });
    }
    return findings;
}
/**
 * Analyze skill for changes from previous version
 */
export async function analyzeDiff(skillPath) {
    const skillName = skillPath.split('/').pop() || 'unknown';
    // Create current snapshot
    const currentSnap = await createSnapshot(skillPath);
    // Load history
    const history = await loadHistory(skillName);
    if (!history || history.snapshots.length === 0) {
        // First time seeing this skill
        const newHistory = {
            skillName,
            skillPath,
            snapshots: [currentSnap]
        };
        await saveHistory(newHistory);
        return {
            findings: [],
            isNew: true,
            currentVersion: currentSnap.version
        };
    }
    const lastSnap = history.snapshots[history.snapshots.length - 1];
    // Check if unchanged
    if (lastSnap.hash === currentSnap.hash) {
        return {
            findings: [],
            isNew: false,
            previousVersion: lastSnap.version,
            currentVersion: currentSnap.version
        };
    }
    // Compare and generate findings
    const findings = compareSnapshots(lastSnap, currentSnap, skillName);
    // Save new snapshot
    history.snapshots.push(currentSnap);
    // Keep last 10 snapshots
    if (history.snapshots.length > 10) {
        history.snapshots = history.snapshots.slice(-10);
    }
    await saveHistory(history);
    return {
        findings,
        isNew: false,
        previousVersion: lastSnap.version,
        currentVersion: currentSnap.version
    };
}
/**
 * Get skill history
 */
export async function getHistory(skillName) {
    return loadHistory(skillName);
}
/**
 * Clear skill history
 */
export async function clearHistory(skillName) {
    const { unlink } = await import('fs/promises');
    try {
        await unlink(join(HISTORY_DIR, `${skillName}.json`));
    }
    catch { /* no-op */ }
}
