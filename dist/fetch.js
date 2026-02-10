/**
 * URL fetching for remote skill scanning
 *
 * Supports:
 * - GitHub repos: https://github.com/user/repo
 * - GitHub subdirs: https://github.com/user/repo/tree/main/skills/my-skill
 * - Direct tar.gz: https://example.com/skill.tar.gz
 * - Direct zip: https://example.com/skill.zip
 */
import { mkdtemp, rm, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join, basename } from 'path';
import { execSync } from 'child_process';
/**
 * Check if a string is a URL
 */
export function isUrl(input) {
    return /^https?:\/\//i.test(input);
}
/**
 * Parse GitHub URL to extract owner, repo, branch, and path
 */
function parseGitHubUrl(url) {
    // https://github.com/owner/repo
    // https://github.com/owner/repo/tree/branch/path/to/skill
    const match = url.match(/github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+)(?:\/(.+))?)?/);
    if (!match)
        return null;
    return {
        owner: match[1],
        repo: match[2].replace(/\.git$/, ''),
        branch: match[3] || 'main',
        subPath: match[4]
    };
}
/**
 * Fetch a skill from a URL to a temporary directory
 */
export async function fetchSkillFromUrl(url) {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawguard-'));
    try {
        // GitHub URL
        const github = parseGitHubUrl(url);
        if (github) {
            return await fetchFromGitHub(github, tempDir, url);
        }
        // Direct archive URL
        if (url.endsWith('.tar.gz') || url.endsWith('.tgz')) {
            return await fetchTarGz(url, tempDir);
        }
        if (url.endsWith('.zip')) {
            return await fetchZip(url, tempDir);
        }
        // Try as git repo
        if (url.endsWith('.git') || url.includes('github.com') || url.includes('gitlab.com')) {
            return await fetchGitRepo(url, tempDir);
        }
        throw new Error(`Unsupported URL format: ${url}`);
    }
    catch (error) {
        // Cleanup on error
        await rm(tempDir, { recursive: true, force: true }).catch(() => { });
        throw error;
    }
}
/**
 * Fetch from GitHub (supports subdirectories via sparse checkout)
 */
async function fetchFromGitHub(github, tempDir, originalUrl) {
    const repoUrl = `https://github.com/${github.owner}/${github.repo}.git`;
    if (github.subPath) {
        // Use sparse checkout for subdirectory
        console.log(`📥 Fetching ${github.owner}/${github.repo}/${github.subPath}...`);
        execSync(`git clone --depth 1 --filter=blob:none --sparse "${repoUrl}" repo`, {
            cwd: tempDir,
            stdio: 'pipe'
        });
        execSync(`git sparse-checkout set "${github.subPath}"`, {
            cwd: join(tempDir, 'repo'),
            stdio: 'pipe'
        });
        const localPath = join(tempDir, 'repo', github.subPath);
        return {
            localPath,
            tempDir,
            source: originalUrl,
            cleanup: async () => cleanupTempDir(tempDir)
        };
    }
    else {
        // Clone entire repo
        console.log(`📥 Fetching ${github.owner}/${github.repo}...`);
        execSync(`git clone --depth 1 "${repoUrl}" repo`, {
            cwd: tempDir,
            stdio: 'pipe'
        });
        return {
            localPath: join(tempDir, 'repo'),
            tempDir,
            source: originalUrl,
            cleanup: async () => cleanupTempDir(tempDir)
        };
    }
}
/**
 * Fetch and extract tar.gz
 */
async function fetchTarGz(url, tempDir) {
    console.log(`📥 Downloading ${basename(url)}...`);
    const archivePath = join(tempDir, 'skill.tar.gz');
    // Download
    execSync(`curl -fsSL -o "${archivePath}" "${url}"`, { stdio: 'pipe' });
    // Extract
    const extractDir = join(tempDir, 'skill');
    await mkdir(extractDir, { recursive: true });
    execSync(`tar -xzf "${archivePath}" -C "${extractDir}" --strip-components=1`, { stdio: 'pipe' });
    return {
        localPath: extractDir,
        tempDir,
        source: url,
        cleanup: async () => cleanupTempDir(tempDir)
    };
}
/**
 * Fetch and extract zip
 */
async function fetchZip(url, tempDir) {
    console.log(`📥 Downloading ${basename(url)}...`);
    const archivePath = join(tempDir, 'skill.zip');
    // Download
    execSync(`curl -fsSL -o "${archivePath}" "${url}"`, { stdio: 'pipe' });
    // Extract
    const extractDir = join(tempDir, 'skill');
    await mkdir(extractDir, { recursive: true });
    execSync(`unzip -q "${archivePath}" -d "${extractDir}"`, { stdio: 'pipe' });
    // Handle single root directory in zip
    const { readdirSync } = await import('fs');
    const contents = readdirSync(extractDir);
    if (contents.length === 1) {
        const inner = join(extractDir, contents[0]);
        const stat = await import('fs/promises').then(m => m.stat(inner));
        if ((await stat).isDirectory()) {
            return {
                localPath: inner,
                tempDir,
                source: url,
                cleanup: async () => cleanupTempDir(tempDir)
            };
        }
    }
    return {
        localPath: extractDir,
        tempDir,
        source: url,
        cleanup: async () => cleanupTempDir(tempDir)
    };
}
/**
 * Clone a git repository
 */
async function fetchGitRepo(url, tempDir) {
    console.log(`📥 Cloning ${url}...`);
    execSync(`git clone --depth 1 "${url}" repo`, {
        cwd: tempDir,
        stdio: 'pipe'
    });
    return {
        localPath: join(tempDir, 'repo'),
        tempDir,
        source: url,
        cleanup: async () => cleanupTempDir(tempDir)
    };
}
/**
 * Cleanup temporary directory
 */
export async function cleanupTempDir(tempDir) {
    await rm(tempDir, { recursive: true, force: true });
}
