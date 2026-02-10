/**
 * Pattern update command: update-patterns
 * Fetches latest YAML pattern files from GitHub
 */
import { writeFile, readFile, mkdir } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PATTERNS_DIR = join(__dirname, '..', 'patterns');
const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/mikecavallo/clawguard/main/src/patterns';
const PATTERN_FILES = ['code.yaml', 'deps.yaml', 'prompt.yaml'];
/**
 * Extract version comment from YAML header (# version: X.Y.Z)
 */
function extractVersion(content) {
    const match = content.match(/^#\s*version:\s*(.+)/m);
    return match?.[1]?.trim();
}
/**
 * Count patterns in a YAML file
 */
function countPatterns(content) {
    return (content.match(/^\s*- id:/gm) || []).length;
}
async function updatePatterns(options) {
    console.log('ClawGuard Pattern Updater');
    console.log('═'.repeat(40));
    console.log('');
    await mkdir(PATTERNS_DIR, { recursive: true });
    let updated = 0;
    let skipped = 0;
    let errors = 0;
    for (const file of PATTERN_FILES) {
        const localPath = join(PATTERNS_DIR, file);
        const remoteUrl = `${GITHUB_RAW_BASE}/${file}`;
        try {
            // Read local file
            let localContent = '';
            let localVersion;
            let localCount = 0;
            try {
                localContent = await readFile(localPath, 'utf-8');
                localVersion = extractVersion(localContent);
                localCount = countPatterns(localContent);
            }
            catch {
                // No local file — will download fresh
            }
            if (options.verbose) {
                console.log(`Checking ${file}...`);
                console.log(`  Local: ${localVersion || 'unknown'} (${localCount} patterns)`);
            }
            // Fetch remote
            const response = await fetch(remoteUrl);
            if (!response.ok) {
                console.log(`  ⚠️  Failed to fetch ${file}: ${response.status}`);
                errors++;
                continue;
            }
            const remoteContent = await response.text();
            const remoteVersion = extractVersion(remoteContent);
            const remoteCount = countPatterns(remoteContent);
            if (options.verbose) {
                console.log(`  Remote: ${remoteVersion || 'unknown'} (${remoteCount} patterns)`);
            }
            // Compare — update if content differs or force flag
            if (options.force || remoteContent !== localContent) {
                await writeFile(localPath, remoteContent, 'utf-8');
                const countDiff = remoteCount - localCount;
                const diffStr = countDiff > 0 ? ` (+${countDiff} new)` : countDiff < 0 ? ` (${countDiff})` : '';
                console.log(`  ✓ Updated ${file}: ${remoteCount} patterns${diffStr}`);
                updated++;
            }
            else {
                console.log(`  ✓ ${file} is already up to date (${localCount} patterns)`);
                skipped++;
            }
        }
        catch (error) {
            console.log(`  ❌ Error updating ${file}: ${error.message}`);
            errors++;
        }
    }
    console.log('');
    console.log(`Done: ${updated} updated, ${skipped} unchanged, ${errors} errors`);
    if (updated > 0) {
        console.log('');
        console.log('Pattern files updated. Changes take effect on next scan.');
    }
}
export function register(program) {
    program
        .command('update-patterns')
        .description('Fetch latest detection patterns from GitHub')
        .option('--force', 'Force update even if patterns appear unchanged')
        .option('-v, --verbose', 'Show detailed comparison')
        .action(async (options) => {
        try {
            await updatePatterns(options);
        }
        catch (error) {
            console.error('Update error:', error.message);
            process.exit(1);
        }
    });
}
