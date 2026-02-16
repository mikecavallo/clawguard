/**
 * Scan commands: scan, full, gate
 */
import { createOrchestrator } from '../orchestrator.js';
import { formatResult } from '../report.js';
import { loadConfig, getApiKey } from '../config.js';
import { scanForCredentialAccess, buildIntentGraph, renderGraphAscii, } from '../analyzers/index.js';
import { fetchSkillFromUrl, isUrl } from '../fetch.js';
import { VERSION } from '../version.js';
/**
 * Run standard scan on a single skill
 */
async function runScan(skillPath, options) {
    const outputFormat = (options.output || 'md');
    const skipSemantic = options.fast || options.staticOnly;
    const config = await loadConfig();
    let runSemantic = !skipSemantic && (config.configured || !!options.apiKey);
    let apiKey = options.apiKey;
    if (apiKey) {
        console.log('⚠️  Passing API keys via --api-key is visible in shell history and process lists.');
        console.log('   Prefer: export CLAWGUARD_API_KEY=your-key');
        console.log('');
    }
    if (runSemantic && !apiKey) {
        apiKey = await getApiKey();
        if (!apiKey) {
            runSemantic = false;
            if (options.verbose) {
                console.log('ℹ️  No API key configured. Running static analysis only.');
                console.log('   Run `clawguard config` to enable semantic analysis.');
                console.log('');
            }
        }
    }
    if (options.verbose) {
        console.log('ClawGuard Security Scanner v' + VERSION);
        console.log('═'.repeat(50));
        if (runSemantic) {
            console.log(`🧠 Semantic analysis: ENABLED (${config.model || 'default'})`);
        }
        else {
            console.log('📋 Static analysis only');
        }
        console.log('');
    }
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({
        path: skillPath,
        deep: options.deep,
        sandbox: options.sandbox,
        semantic: runSemantic,
        apiKey: apiKey,
        output: outputFormat,
        verbose: options.verbose,
        sourceLabel: options.sourceLabel,
    });
    const output = formatResult(result, outputFormat);
    console.log(output);
    if (result.summary.critical > 0)
        process.exit(2);
    if (result.summary.high > 0)
        process.exit(1);
}
/**
 * Run full comprehensive scan
 */
async function runFullScan(skillPath, options) {
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║              ClawGuard FULL SECURITY AUDIT                      ║');
    console.log('║                        v' + VERSION + '                                    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('▶ Phase 1: Static Analysis');
    console.log('─'.repeat(60));
    const orchestrator = createOrchestrator();
    const result = await orchestrator.scan({
        path: skillPath,
        semantic: !!options.apiKey,
        apiKey: options.apiKey,
        verbose: options.verbose
    });
    console.log(formatResult(result, 'md'));
    console.log('');
    console.log('▶ Phase 2: Credential Access Analysis');
    console.log('─'.repeat(60));
    const honeypotFindings = await scanForCredentialAccess(skillPath);
    if (honeypotFindings.length > 0) {
        for (const f of honeypotFindings) {
            const icon = f.severity === 'critical' ? '⛔' : '🔴';
            console.log(`${icon} ${f.title}: ${f.evidence}`);
        }
    }
    else {
        console.log('✅ No suspicious credential access patterns.');
    }
    console.log('');
    console.log('▶ Phase 3: Intent Graph');
    console.log('─'.repeat(60));
    const graph = await buildIntentGraph(skillPath);
    console.log(renderGraphAscii(graph));
    console.log('');
    const totalCritical = result.summary.critical +
        honeypotFindings.filter(f => f.severity === 'critical').length;
    const totalHigh = result.summary.high +
        honeypotFindings.filter(f => f.severity === 'high').length;
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                      FINAL VERDICT                              ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    if (totalCritical > 0) {
        console.log('⛔ CRITICAL RISK - DO NOT INSTALL');
        process.exit(2);
    }
    else if (totalHigh > 0) {
        console.log('🔴 HIGH RISK - Review carefully before installing');
        process.exit(1);
    }
    else if (result.summary.medium > 0) {
        console.log('🟠 MEDIUM RISK - Some concerns, review recommended');
    }
    else {
        console.log('✅ LOW RISK - Appears safe');
    }
}
/**
 * Pre-install security gate
 */
async function runGate(skillPath, options) {
    const config = await loadConfig();
    const orchestrator = createOrchestrator();
    const { checkKnownBad, calculateSkillHash } = await import('../database.js');
    const skillHash = await calculateSkillHash(skillPath);
    const knownBad = await checkKnownBad(skillHash);
    if (knownBad.known) {
        if (options.json) {
            console.log(JSON.stringify({
                allowed: false,
                reason: 'known_malicious',
                threat: knownBad.threat,
                description: knownBad.description
            }));
        }
        else {
            console.error('⛔ BLOCKED: Known malicious skill');
            console.error(`Threat: ${knownBad.threat}`);
        }
        process.exit(2);
    }
    const result = await orchestrator.scan({
        path: skillPath,
        semantic: config.configured,
        sandbox: options.sandbox,
        verbose: false
    });
    const blockCritical = result.summary.critical > 0;
    const blockHigh = !options.allowHigh && result.summary.high > 0;
    const shouldBlock = blockCritical || blockHigh;
    if (options.json) {
        console.log(JSON.stringify({
            allowed: !shouldBlock,
            riskLevel: result.riskLevel,
            riskScore: result.riskScore,
            summary: result.summary,
            findings: shouldBlock ? result.findings : undefined
        }));
    }
    else {
        if (shouldBlock) {
            console.error(`⛔ BLOCKED: ${result.riskLevel} risk (score: ${result.riskScore})`);
            console.error(`Critical: ${result.summary.critical}, High: ${result.summary.high}`);
            const topFindings = result.findings
                .filter(f => f.severity === 'critical' || f.severity === 'high')
                .slice(0, 3);
            for (const f of topFindings) {
                console.error(`  - ${f.title}`);
            }
        }
        else {
            console.log(`✅ ALLOWED: ${result.riskLevel} risk (score: ${result.riskScore})`);
        }
    }
    process.exit(shouldBlock ? 2 : 0);
}
export function register(program) {
    // ========== SCAN COMMAND ==========
    program
        .command('scan <path>')
        .description('Scan a skill for security issues (local path or URL)')
        .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
        .option('-d, --deep', 'Enable deep dependency source analysis')
        .option('-s, --sandbox', 'Run behavioral sandbox tests (requires Docker)')
        .option('-f, --fast', 'Static analysis only (skip semantic)')
        .option('--static-only', 'Static analysis only (skip semantic)')
        .option('--api-key <key>', 'API key for semantic analysis')
        .option('-v, --verbose', 'Enable verbose output')
        .option('--keep', 'Keep downloaded files after scan (for URLs)')
        .action(async (skillPath, options) => {
        let fetchResult = null;
        try {
            let actualPath = skillPath;
            let sourceLabel;
            if (isUrl(skillPath)) {
                fetchResult = await fetchSkillFromUrl(skillPath);
                actualPath = fetchResult.localPath;
                sourceLabel = skillPath;
                console.log(`✓ Fetched from ${skillPath}`);
                console.log('');
            }
            await runScan(actualPath, { ...options, sourceLabel });
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
        finally {
            if (fetchResult && !options.keep) {
                await fetchResult.cleanup();
            }
            else if (fetchResult && options.keep) {
                console.log(`\n📁 Files kept at: ${fetchResult.localPath}`);
            }
        }
    });
    // ========== FULL COMMAND ==========
    program
        .command('full <path>')
        .description('Run ALL analyzers (static + semantic + honeypot + graph)')
        .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
        .option('--api-key <key>', 'Anthropic API key for semantic analysis')
        .option('-v, --verbose', 'Enable verbose output')
        .option('--keep', 'Keep downloaded files after scan (for URLs)')
        .action(async (skillPath, options) => {
        let fetchResult = null;
        try {
            let actualPath = skillPath;
            if (isUrl(skillPath)) {
                fetchResult = await fetchSkillFromUrl(skillPath);
                actualPath = fetchResult.localPath;
                console.log(`✓ Fetched from ${skillPath}`);
                console.log('');
            }
            await runFullScan(actualPath, options);
        }
        catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
        finally {
            if (fetchResult && !options.keep) {
                await fetchResult.cleanup();
            }
            else if (fetchResult && options.keep) {
                console.log(`\n📁 Files kept at: ${fetchResult.localPath}`);
            }
        }
    });
    // ========== GATE COMMAND ==========
    program
        .command('gate <path>')
        .description('Pre-install security gate - blocks install if critical issues found (local path or URL)')
        .option('-s, --sandbox', 'Include behavioral sandbox analysis')
        .option('--allow-high', 'Allow high-risk skills (only block critical)')
        .option('--json', 'Output JSON result')
        .action(async (skillPath, options) => {
        let fetchResult = null;
        try {
            let actualPath = skillPath;
            if (isUrl(skillPath)) {
                fetchResult = await fetchSkillFromUrl(skillPath);
                actualPath = fetchResult.localPath;
                if (!options.json) {
                    console.log(`✓ Fetched from ${skillPath}`);
                }
            }
            await runGate(actualPath, options);
        }
        catch (error) {
            console.error('Gate error:', error.message);
            process.exit(1);
        }
        finally {
            if (fetchResult) {
                await fetchResult.cleanup();
            }
        }
    });
}
