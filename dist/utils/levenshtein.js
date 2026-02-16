/**
 * Levenshtein distance calculation for typosquatting detection
 *
 * Techniques adapted from dnstwist (https://github.com/elceef/dnstwist):
 * - Character omission (lodash → lodas)
 * - Character swap (lodash → lodahs)
 * - Homoglyphs (lodash → l0dash)
 * - Adjacent key typos (lodash → kodash)
 * - Vowel dropping (lodash → ldsh)
 * - Character repetition (lodash → loddash)
 */
// Homoglyph mappings - characters that look similar
const HOMOGLYPHS = {
    'a': ['4', '@', 'á', 'à', 'â', 'ä', 'ã'],
    'b': ['8', '6'],
    'c': ['(', '{', '[', 'ç'],
    'd': ['cl'],
    'e': ['3', 'é', 'è', 'ê', 'ë'],
    'g': ['9', 'q'],
    'h': ['#'],
    'i': ['1', '!', 'l', '|', 'í', 'ì', 'î', 'ï'],
    'l': ['1', '!', 'i', '|'],
    'o': ['0', 'ó', 'ò', 'ô', 'ö', 'õ'],
    's': ['5', '$', 'z'],
    't': ['7', '+'],
    'u': ['ú', 'ù', 'û', 'ü'],
    'z': ['2', 's'],
    '0': ['o'],
    '1': ['l', 'i'],
};
// QWERTY keyboard adjacent keys for typo detection
const ADJACENT_KEYS = {
    'q': ['w', 'a', '1', '2'],
    'w': ['q', 'e', 'a', 's', '2', '3'],
    'e': ['w', 'r', 's', 'd', '3', '4'],
    'r': ['e', 't', 'd', 'f', '4', '5'],
    't': ['r', 'y', 'f', 'g', '5', '6'],
    'y': ['t', 'u', 'g', 'h', '6', '7'],
    'u': ['y', 'i', 'h', 'j', '7', '8'],
    'i': ['u', 'o', 'j', 'k', '8', '9'],
    'o': ['i', 'p', 'k', 'l', '9', '0'],
    'p': ['o', 'l', '0', '-'],
    'a': ['q', 'w', 's', 'z'],
    's': ['a', 'w', 'e', 'd', 'z', 'x'],
    'd': ['s', 'e', 'r', 'f', 'x', 'c'],
    'f': ['d', 'r', 't', 'g', 'c', 'v'],
    'g': ['f', 't', 'y', 'h', 'v', 'b'],
    'h': ['g', 'y', 'u', 'j', 'b', 'n'],
    'j': ['h', 'u', 'i', 'k', 'n', 'm'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'z': ['a', 's', 'x'],
    'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'],
    'v': ['c', 'f', 'g', 'b'],
    'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'],
    'm': ['n', 'j', 'k'],
    '-': ['_', '0', 'p'],
    '_': ['-'],
};
const VOWELS = new Set(['a', 'e', 'i', 'o', 'u']);
/**
 * Calculate the Levenshtein (edit) distance between two strings
 * @param a First string
 * @param b Second string
 * @returns Number of single-character edits required to change a into b
 */
export function levenshteinDistance(a, b) {
    const aLen = a.length;
    const bLen = b.length;
    // Handle edge cases
    if (aLen === 0)
        return bLen;
    if (bLen === 0)
        return aLen;
    // Create matrix of distances
    const matrix = [];
    // Initialize first column
    for (let i = 0; i <= aLen; i++) {
        matrix[i] = [i];
    }
    // Initialize first row
    for (let j = 0; j <= bLen; j++) {
        matrix[0][j] = j;
    }
    // Fill in the rest of the matrix
    for (let i = 1; i <= aLen; i++) {
        for (let j = 1; j <= bLen; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(matrix[i - 1][j] + 1, // deletion
            matrix[i][j - 1] + 1, // insertion
            matrix[i - 1][j - 1] + cost // substitution
            );
        }
    }
    return matrix[aLen][bLen];
}
/**
 * Check if a package name is within a given distance of any popular package
 * @param name Package name to check
 * @param popularPackages List of popular package names
 * @param maxDistance Maximum allowed edit distance (default: 2)
 * @returns Object with match info if typosquat detected, null otherwise
 */
export function checkTyposquat(name, popularPackages, maxDistance = 2) {
    const nameLower = name.toLowerCase();
    for (const popular of popularPackages) {
        const popularLower = popular.toLowerCase();
        // Skip if it's an exact match (not a typosquat)
        if (nameLower === popularLower) {
            continue;
        }
        const distance = levenshteinDistance(nameLower, popularLower);
        if (distance <= maxDistance) {
            return { original: popular, distance };
        }
    }
    return null;
}
/**
 * Check if one string is a homoglyph variant of another
 * (e.g., l0dash is a homoglyph of lodash)
 */
function isHomoglyphVariant(name, target) {
    if (name.length !== target.length)
        return false;
    let differences = 0;
    for (let i = 0; i < name.length; i++) {
        if (name[i] === target[i])
            continue;
        // Check if this could be a homoglyph substitution
        const targetChar = target[i].toLowerCase();
        const nameChar = name[i].toLowerCase();
        const homoglyphs = HOMOGLYPHS[targetChar] || [];
        const reverseHomoglyphs = HOMOGLYPHS[nameChar] || [];
        if (homoglyphs.includes(nameChar) || reverseHomoglyphs.includes(targetChar)) {
            differences++;
        }
        else {
            return false; // Non-homoglyph difference
        }
    }
    return differences > 0 && differences <= 2;
}
/**
 * Check if one string could be an adjacent-key typo of another
 * (e.g., kodash is a typo of lodash - k is adjacent to l)
 */
function isAdjacentKeyTypo(name, target) {
    if (name.length !== target.length)
        return false;
    let typos = 0;
    for (let i = 0; i < name.length; i++) {
        if (name[i] === target[i])
            continue;
        const targetChar = target[i].toLowerCase();
        const nameChar = name[i].toLowerCase();
        const adjacent = ADJACENT_KEYS[targetChar] || [];
        if (adjacent.includes(nameChar)) {
            typos++;
        }
        else {
            return false;
        }
    }
    return typos === 1; // Only one adjacent-key typo
}
/**
 * Check if name is target with vowels dropped
 * (e.g., ldsh could be lodash with vowels removed)
 */
function isVowelDropped(name, target) {
    // Remove vowels from target and compare
    const targetNoVowels = target.toLowerCase().split('').filter(c => !VOWELS.has(c)).join('');
    return name.toLowerCase() === targetNoVowels && name !== target;
}
/**
 * Check if name is target with a character omitted
 * (e.g., lodas is lodash with 'h' omitted)
 */
function isCharacterOmission(name, target) {
    if (name.length !== target.length - 1)
        return false;
    // Try removing each character from target and see if it matches name
    for (let i = 0; i < target.length; i++) {
        const withoutChar = target.slice(0, i) + target.slice(i + 1);
        if (withoutChar.toLowerCase() === name.toLowerCase()) {
            return true;
        }
    }
    return false;
}
/**
 * Check if name is target with an extra character inserted
 * (e.g., lodassh is lodash with extra 's')
 */
function isCharacterInsertion(name, target) {
    if (name.length !== target.length + 1)
        return false;
    // Try removing each character from name and see if it matches target
    for (let i = 0; i < name.length; i++) {
        const withoutChar = name.slice(0, i) + name.slice(i + 1);
        if (withoutChar.toLowerCase() === target.toLowerCase()) {
            return true;
        }
    }
    return false;
}
/**
 * Check if name is target with two adjacent characters swapped
 * (e.g., lodahs is lodash with 's' and 'h' swapped)
 */
function isCharacterSwap(name, target) {
    if (name.length !== target.length)
        return false;
    const nameLower = name.toLowerCase();
    const targetLower = target.toLowerCase();
    // Find differences
    const diffs = [];
    for (let i = 0; i < nameLower.length; i++) {
        if (nameLower[i] !== targetLower[i]) {
            diffs.push(i);
        }
    }
    // Should have exactly 2 differences that are adjacent and swapped
    if (diffs.length === 2 && diffs[1] - diffs[0] === 1) {
        return nameLower[diffs[0]] === targetLower[diffs[1]] &&
            nameLower[diffs[1]] === targetLower[diffs[0]];
    }
    return false;
}
/**
 * Check for common typosquatting patterns beyond Levenshtein
 * Adapted from dnstwist techniques
 * @param name Package name to check
 * @param popularPackages List of popular package names
 * @returns Object with match info if pattern detected, null otherwise
 */
export function checkTyposquatPatterns(name, popularPackages) {
    const nameLower = name.toLowerCase();
    for (const popular of popularPackages) {
        const popularLower = popular.toLowerCase();
        // Skip exact match
        if (nameLower === popularLower) {
            continue;
        }
        // Check for common patterns
        // 1. Hyphen/underscore swaps: lodash vs lodash_ vs lodash- vs _lodash
        const normalizedName = nameLower.replace(/[-_]/g, '');
        const normalizedPopular = popularLower.replace(/[-_]/g, '');
        if (normalizedName === normalizedPopular) {
            return { original: popular, pattern: 'hyphen-underscore-swap' };
        }
        // 2. Prefix/suffix attacks: python-requests, requests-python, requests2
        const prefixes = ['python-', 'py-', 'node-', 'js-', 'npm-', 'pip-', 'go-'];
        const suffixes = ['-python', '-py', '-node', '-js', '-npm', '2', '3', '-dev', '-latest', '-beta', '-alpha', '-next', 's'];
        for (const prefix of prefixes) {
            if (nameLower === prefix + popularLower) {
                return { original: popular, pattern: 'suspicious-prefix' };
            }
        }
        for (const suffix of suffixes) {
            if (nameLower === popularLower + suffix) {
                return { original: popular, pattern: 'suspicious-suffix' };
            }
        }
        // 3. Scope confusion: @evil/lodash looks like lodash
        if (nameLower.includes('/')) {
            const scopedName = nameLower.split('/')[1];
            if (scopedName === popularLower) {
                return { original: popular, pattern: 'scope-confusion' };
            }
        }
        // 4. Letter repetition: expresss, lodaash
        const dedupedName = nameLower.replace(/(.)\1+/g, '$1');
        const dedupedPopular = popularLower.replace(/(.)\1+/g, '$1');
        if (dedupedName === dedupedPopular && nameLower !== popularLower) {
            return { original: popular, pattern: 'letter-repetition' };
        }
        // 5. Homoglyph substitution: l0dash, reque5ts (dnstwist technique)
        if (isHomoglyphVariant(nameLower, popularLower)) {
            return { original: popular, pattern: 'homoglyph' };
        }
        // 6. Adjacent key typo: kodash (k next to l on keyboard)
        if (isAdjacentKeyTypo(nameLower, popularLower)) {
            return { original: popular, pattern: 'adjacent-key-typo' };
        }
        // 7. Vowel dropping: ldsh for lodash
        if (isVowelDropped(nameLower, popularLower)) {
            return { original: popular, pattern: 'vowel-drop' };
        }
        // 8. Character omission: lodas for lodash (dnstwist technique)
        if (isCharacterOmission(nameLower, popularLower)) {
            return { original: popular, pattern: 'character-omission' };
        }
        // 9. Character insertion: lodassh for lodash
        if (isCharacterInsertion(nameLower, popularLower)) {
            return { original: popular, pattern: 'character-insertion' };
        }
        // 10. Character swap: lodahs for lodash (adjacent swap)
        if (isCharacterSwap(nameLower, popularLower)) {
            return { original: popular, pattern: 'character-swap' };
        }
    }
    return null;
}
// Well-known packages that are NOT typosquats despite being close to popular names
const KNOWN_GOOD_PACKAGES = new Set([
    'acorn', 'acorn-walk', 'vitest', 'vite', 'esbuild', 'tsup', 'tslib',
    'pnpm', 'yarn', 'bun', 'deno', 'tsx', 'ts-node', 'tsc',
    'zod', 'zustand', 'jotai', 'immer', 'mitt', 'mri', 'cac',
    'cors', 'cross-spawn', 'cross-env', 'dotenv', 'dotenvx',
    'glob', 'globby', 'fast-glob', 'picomatch', 'minimatch',
    'chalk', 'picocolors', 'kleur', 'ansi-colors',
    'uuid', 'nanoid', 'cuid', 'ulid',
    'yargs', 'yargs-parser', 'mri', 'cac', 'citty',
    'debug', 'pino', 'winston', 'bunyan',
    'jest', 'mocha', 'ava', 'tap', 'uvu',
    'eslint', 'prettier', 'biome', 'oxlint',
    'rollup', 'parcel', 'turbo', 'turborepo',
    'express', 'koa', 'hono', 'fastify', 'hapi',
    'react', 'preact', 'solid-js', 'svelte', 'vue', 'nuxt', 'next',
    'redis', 'ioredis', 'pg', 'mysql', 'mysql2',
    'mongoose', 'prisma', 'drizzle-orm', 'knex', 'sequelize', 'typeorm',
    'axios', 'got', 'ky', 'undici', 'node-fetch',
    'commander', 'inquirer', 'prompts', 'ora', 'listr2',
    'lodash', 'ramda', 'remeda', 'radash',
    'dayjs', 'date-fns', 'luxon', 'moment',
    'sharp', 'jimp', 'canvas',
    'socket.io', 'ws', 'uws',
    'bcrypt', 'argon2', 'scrypt',
    'yaml', 'toml', 'ini', 'json5',
    'semver', 'compare-versions',
]);
/**
 * Comprehensive typosquat check combining distance and pattern detection
 */
export function detectTyposquat(name, popularPackages, maxDistance = 2) {
    // Skip known-good packages
    if (KNOWN_GOOD_PACKAGES.has(name.toLowerCase())) {
        return null;
    }
    // Check Levenshtein distance first
    const distanceMatch = checkTyposquat(name, popularPackages, maxDistance);
    if (distanceMatch) {
        return {
            original: distanceMatch.original,
            type: 'distance',
            detail: `Edit distance: ${distanceMatch.distance}`
        };
    }
    // Check pattern-based typosquats
    const patternMatch = checkTyposquatPatterns(name, popularPackages);
    if (patternMatch) {
        return {
            original: patternMatch.original,
            type: 'pattern',
            detail: `Pattern: ${patternMatch.pattern}`
        };
    }
    return null;
}
