#!/usr/bin/env node
/**
 * ClawGuard Interactive TUI
 *
 * Full-screen terminal interface with config wizard and dashboard.
 */
import { createInterface } from 'readline';
import { stat } from 'fs/promises';
import { createOrchestrator } from './orchestrator.js';
import { formatResult } from './report.js';
import { loadConfig, saveConfig, isConfigured, PROVIDERS, CONFIG_FILE } from './config.js';
import { checkKnownBad, calculateSkillHash, reportMalicious } from './database.js';
// ANSI color codes
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
const GRAY = '\x1b[90m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const BG_RED = '\x1b[41m';
const CORAL = '\x1b[38;2;255;77;77m';
// Box drawing characters
const BOX = {
    tl: '╭', tr: '╮', bl: '╰', br: '╯',
    h: '─', v: '│',
    ltee: '├', rtee: '┤',
    thick_h: '━', thick_v: '┃'
};
const BANNER = `
${CORAL}${BOLD}
   ██████╗██╗      █████╗ ██╗    ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║     ███████║██║ █╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██║     ██╔══██║██║███╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╗███████╗██║  ██║╚███╔███╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
${RESET}`;
const SMALL_BANNER = `${CORAL}${BOLD}  ◆ ClawGuard${RESET}`;
function createPrompt() {
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout
    });
    return {
        ask: (question) => new Promise((resolve) => {
            rl.question(question, (answer) => resolve(answer.trim()));
        }),
        askPassword: (question) => new Promise((resolve) => {
            if (!process.stdin.isTTY) {
                rl.question(question, (answer) => resolve(answer.trim()));
                return;
            }
            process.stdout.write(question);
            let input = '';
            const stdin = process.stdin;
            stdin.setRawMode(true);
            stdin.resume();
            stdin.setEncoding('utf8');
            const onData = (char) => {
                switch (char) {
                    case '\n':
                    case '\r':
                    case '\u0004':
                        stdin.removeListener('data', onData);
                        stdin.setRawMode(false);
                        process.stdout.write('\n');
                        resolve(input);
                        break;
                    case '\u0003':
                        process.exit();
                        break;
                    case '\u007F':
                    case '\b':
                        if (input.length > 0) {
                            input = input.slice(0, -1);
                            process.stdout.write('\b \b');
                        }
                        break;
                    default:
                        input += char;
                        process.stdout.write('•');
                }
            };
            stdin.on('data', onData);
        }),
        close: () => rl.close()
    };
}
function clearScreen() {
    process.stdout.write('\x1b[2J\x1b[H');
}
function box(title, content, width = 60) {
    const lines = [];
    lines.push(`${GRAY}${BOX.tl}${BOX.h.repeat(width - 2)}${BOX.tr}${RESET}`);
    if (title) {
        const titlePad = Math.floor((width - 4 - title.length) / 2);
        lines.push(`${GRAY}${BOX.v}${RESET}${' '.repeat(titlePad)}${BOLD}${title}${RESET}${' '.repeat(width - 4 - titlePad - title.length)}${GRAY}${BOX.v}${RESET}`);
        lines.push(`${GRAY}${BOX.ltee}${BOX.h.repeat(width - 2)}${BOX.rtee}${RESET}`);
    }
    for (const line of content) {
        // eslint-disable-next-line no-control-regex
        const stripped = line.replace(/\x1b\[[0-9;]*m/g, '');
        const padding = width - 4 - stripped.length;
        lines.push(`${GRAY}${BOX.v}${RESET} ${line}${' '.repeat(Math.max(0, padding))} ${GRAY}${BOX.v}${RESET}`);
    }
    lines.push(`${GRAY}${BOX.bl}${BOX.h.repeat(width - 2)}${BOX.br}${RESET}`);
    return lines.join('\n');
}
/**
 * Test API connection
 */
async function testApiConnection(provider, model, apiKey, baseUrl) {
    const startTime = Date.now();
    try {
        if (provider === 'anthropic') {
            const response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01',
                    'content-type': 'application/json'
                },
                body: JSON.stringify({
                    model,
                    max_tokens: 10,
                    messages: [{ role: 'user', content: 'Hi' }]
                })
            });
            if (response.ok) {
                return { success: true, latencyMs: Date.now() - startTime };
            }
            else {
                const error = await response.json();
                return { success: false, error: error.error?.message || `HTTP ${response.status}` };
            }
        }
        else if (provider === 'openai') {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model,
                    max_tokens: 10,
                    messages: [{ role: 'user', content: 'Hi' }]
                })
            });
            if (response.ok) {
                return { success: true, latencyMs: Date.now() - startTime };
            }
            else {
                const error = await response.json();
                return { success: false, error: error.error?.message || `HTTP ${response.status}` };
            }
        }
        else if (provider === 'local') {
            const url = baseUrl || 'http://localhost:11434';
            const response = await fetch(`${url}/api/tags`, { signal: AbortSignal.timeout(5000) });
            if (response.ok) {
                return { success: true, latencyMs: Date.now() - startTime };
            }
            else {
                return { success: false, error: `Ollama not responding at ${url}` };
            }
        }
        return { success: false, error: 'Unknown provider' };
    }
    catch (error) {
        return { success: false, error: error.message };
    }
}
/**
 * Animated spinner
 */
async function withSpinner(message, fn) {
    const frames = ['◐', '◓', '◑', '◒'];
    let i = 0;
    const interval = setInterval(() => {
        process.stdout.write(`\r${CORAL}${frames[i]}${RESET} ${message}`);
        i = (i + 1) % frames.length;
    }, 100);
    try {
        const result = await fn();
        clearInterval(interval);
        process.stdout.write(`\r${GREEN}✓${RESET} ${message}\n`);
        return result;
    }
    catch (error) {
        clearInterval(interval);
        process.stdout.write(`\r${RED}✗${RESET} ${message}\n`);
        throw error;
    }
}
/**
 * Configuration Wizard - Provider Selection
 */
async function wizardSelectProvider(prompt) {
    clearScreen();
    console.log(BANNER);
    console.log(`${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}`);
    console.log('');
    console.log(box('Step 1 of 3: Choose AI Provider', [
        '',
        `${WHITE}ClawGuard uses AI to understand skill intent${RESET}`,
        `${DIM}This catches attacks that patterns miss${RESET}`,
        '',
        `  ${CORAL}[1]${RESET} ${WHITE}Anthropic Claude${RESET}     ${DIM}Best accuracy${RESET}`,
        `  ${CORAL}[2]${RESET} ${WHITE}OpenAI GPT-4${RESET}         ${DIM}Good alternative${RESET}`,
        `  ${CORAL}[3]${RESET} ${WHITE}Ollama (Local)${RESET}       ${DIM}Free, private, offline${RESET}`,
        '',
        `  ${GRAY}[s]${RESET} ${DIM}Skip - use static analysis only${RESET}`,
        ''
    ]));
    console.log('');
    const choice = await prompt.ask(`  ${WHITE}Select provider ${GRAY}[1-3/s]:${RESET} `);
    switch (choice.toLowerCase()) {
        case '1': return 'anthropic';
        case '2': return 'openai';
        case '3': return 'local';
        case 's': return null;
        default: return 'anthropic';
    }
}
/**
 * Configuration Wizard - Model Selection
 */
async function wizardSelectModel(prompt, provider) {
    clearScreen();
    console.log(BANNER);
    console.log(`${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}`);
    console.log('');
    const providerInfo = PROVIDERS[provider];
    const models = providerInfo.models;
    const modelLines = [
        '',
        `${WHITE}Provider: ${CORAL}${providerInfo.name}${RESET}`,
        ''
    ];
    models.forEach((m, i) => {
        const recommended = i === 1 ? ` ${GREEN}← recommended${RESET}` : '';
        modelLines.push(`  ${CORAL}[${i + 1}]${RESET} ${WHITE}${m.name}${RESET}${recommended}`);
    });
    modelLines.push('');
    console.log(box('Step 2 of 3: Choose Model', modelLines));
    console.log('');
    const choice = await prompt.ask(`  ${WHITE}Select model ${GRAY}[1-${models.length}]:${RESET} `);
    const index = parseInt(choice || '2') - 1;
    return models[Math.max(0, Math.min(index, models.length - 1))].id;
}
/**
 * Configuration Wizard - API Key
 */
async function wizardApiKey(prompt, provider, model) {
    clearScreen();
    console.log(BANNER);
    console.log(`${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}`);
    console.log('');
    const providerInfo = PROVIDERS[provider];
    if (provider === 'local') {
        console.log(box('Step 3 of 3: Ollama Configuration', [
            '',
            `${WHITE}Make sure Ollama is running:${RESET}`,
            `${DIM}  ollama serve${RESET}`,
            '',
            `${WHITE}And the model is pulled:${RESET}`,
            `${DIM}  ollama pull ${model}${RESET}`,
            ''
        ]));
        console.log('');
        const customUrl = await prompt.ask(`  ${WHITE}Ollama URL ${GRAY}[localhost:11434]:${RESET} `);
        const baseUrl = customUrl || 'http://localhost:11434';
        // Test connection
        console.log('');
        const result = await withSpinner('Testing Ollama connection...', () => testApiConnection('local', model, undefined, baseUrl));
        if (!result.success) {
            console.log(`  ${RED}Error: ${result.error}${RESET}`);
            console.log(`  ${YELLOW}Make sure Ollama is running and try again.${RESET}`);
            await prompt.ask(`\n  ${DIM}Press Enter to retry...${RESET}`);
            return wizardApiKey(prompt, provider, model);
        }
        console.log(`  ${GREEN}Connected!${RESET} ${DIM}(${result.latencyMs}ms)${RESET}`);
        return { baseUrl };
    }
    // Check for environment variable
    const envKey = process.env[providerInfo.envVar];
    const lines = [
        '',
        `${WHITE}Provider: ${CORAL}${providerInfo.name}${RESET}`,
        `${WHITE}Model: ${CORAL}${model}${RESET}`,
        ''
    ];
    if (envKey) {
        const masked = envKey.slice(0, 8) + '•'.repeat(20) + envKey.slice(-4);
        lines.push(`${GREEN}✓${RESET} Found $${providerInfo.envVar}`);
        lines.push(`  ${DIM}${masked}${RESET}`);
        lines.push('');
    }
    else {
        lines.push(`${DIM}Get your API key from:${RESET}`);
        if (provider === 'anthropic') {
            lines.push(`  ${CYAN}https://console.anthropic.com/settings/keys${RESET}`);
        }
        else {
            lines.push(`  ${CYAN}https://platform.openai.com/api-keys${RESET}`);
        }
        lines.push('');
    }
    console.log(box('Step 3 of 3: API Key', lines));
    console.log('');
    let apiKey;
    if (envKey) {
        const useEnv = await prompt.ask(`  ${WHITE}Use environment variable? ${GRAY}[Y/n]:${RESET} `);
        if (useEnv.toLowerCase() !== 'n') {
            apiKey = envKey;
        }
    }
    if (!apiKey) {
        apiKey = await prompt.askPassword(`  ${WHITE}API Key: ${RESET}`);
        if (!apiKey) {
            console.log(`  ${RED}API key is required${RESET}`);
            await prompt.ask(`\n  ${DIM}Press Enter to retry...${RESET}`);
            return wizardApiKey(prompt, provider, model);
        }
        // Validate key format
        if (providerInfo.keyPrefix && !apiKey.startsWith(providerInfo.keyPrefix)) {
            console.log(`  ${YELLOW}Warning: Key doesn't look like a ${provider} key${RESET}`);
            console.log(`  ${DIM}Expected prefix: ${providerInfo.keyPrefix}...${RESET}`);
        }
    }
    // Test API connection
    console.log('');
    const result = await withSpinner('Testing API connection...', () => testApiConnection(provider, model, apiKey));
    if (!result.success) {
        console.log(`  ${RED}Error: ${result.error}${RESET}`);
        await prompt.ask(`\n  ${DIM}Press Enter to retry...${RESET}`);
        return wizardApiKey(prompt, provider, model);
    }
    console.log(`  ${GREEN}API key verified!${RESET} ${DIM}(${result.latencyMs}ms)${RESET}`);
    // Ask if they want to store the key
    const storeKey = apiKey !== envKey;
    return { apiKey: storeKey ? apiKey : undefined };
}
/**
 * Configuration Wizard - Complete
 */
async function wizardComplete(prompt, config) {
    clearScreen();
    console.log(BANNER);
    console.log(`${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}`);
    console.log('');
    const providerInfo = PROVIDERS[config.provider];
    console.log(box('✓ Configuration Complete', [
        '',
        `${GREEN}ClawGuard is ready to protect you!${RESET}`,
        '',
        `  Provider:  ${WHITE}${providerInfo.name}${RESET}`,
        `  Model:     ${WHITE}${config.model}${RESET}`,
        `  API Key:   ${config.apiKey ? `${GREEN}Stored securely${RESET}` : `${DIM}Using env var${RESET}`}`,
        '',
        `${DIM}Config saved to: ${CONFIG_FILE}${RESET}`,
        ''
    ]));
    console.log('');
    console.log(`  ${DIM}Quick commands:${RESET}`);
    console.log(`    ${CORAL}clawguard scan ./my-skill${RESET}     ${DIM}Scan a skill${RESET}`);
    console.log(`    ${CORAL}clawguard gate ./my-skill${RESET}     ${DIM}Pre-install check${RESET}`);
    console.log(`    ${CORAL}clawguard ui${RESET}                  ${DIM}Open dashboard${RESET}`);
    console.log('');
    await prompt.ask(`  ${DIM}Press Enter to continue to dashboard...${RESET}`);
}
/**
 * Run full configuration wizard
 */
async function runConfigWizard(prompt) {
    const provider = await wizardSelectProvider(prompt);
    if (!provider) {
        // User skipped
        clearScreen();
        console.log(BANNER);
        console.log('');
        console.log(`  ${YELLOW}Configuration skipped.${RESET}`);
        console.log(`  ${DIM}ClawGuard will use static analysis only.${RESET}`);
        console.log(`  ${DIM}Run 'clawguard config' anytime to enable AI analysis.${RESET}`);
        console.log('');
        return false;
    }
    const model = await wizardSelectModel(prompt, provider);
    const { apiKey, baseUrl } = await wizardApiKey(prompt, provider, model);
    const config = {
        provider,
        model,
        apiKey,
        baseUrl,
        configured: true,
        configuredAt: new Date().toISOString()
    };
    await saveConfig(config);
    await wizardComplete(prompt, config);
    return true;
}
async function loadStats() {
    // TODO: Load from scan history
    return {
        scansToday: 0,
        threatsBlocked: 0,
        skillsProtected: 0
    };
}
/**
 * Dashboard view - main screen after config
 */
async function showDashboard(prompt) {
    clearScreen();
    const config = await loadConfig();
    const stats = await loadStats();
    // Compact header
    console.log('');
    console.log(BANNER);
    console.log(`${DIM}  Revolutionary Security Scanner for AI Agent Skills${RESET}`);
    console.log(`  ${DIM}─────────────────────────────────────────────────${RESET}`);
    // Status bar
    if (config.configured) {
        const providerInfo = PROVIDERS[config.provider];
        console.log(`  ${GREEN}●${RESET} ${DIM}AI:${RESET} ${WHITE}${config.model}${RESET} ${DIM}(${providerInfo.name.split(' ')[0]})${RESET}`);
    }
    else {
        console.log(`  ${YELLOW}○${RESET} ${DIM}AI analysis not configured${RESET}`);
    }
    console.log('');
    // Stats cards
    const statWidth = 18;
    const statsRow = [
        `${CORAL}${stats.scansToday}${RESET} scans`,
        `${GREEN}${stats.threatsBlocked}${RESET} threats`,
        `${BLUE}${stats.skillsProtected}${RESET} protected`
    ].map(s => {
        // eslint-disable-next-line no-control-regex
        const stripped = s.replace(/\x1b\[[0-9;]*m/g, '');
        const pad = Math.max(0, statWidth - stripped.length);
        return `  ${GRAY}│${RESET} ${s}${' '.repeat(pad)}`;
    }).join('');
    console.log(`  ${GRAY}┌${'─'.repeat(statWidth)}┬${'─'.repeat(statWidth)}┬${'─'.repeat(statWidth)}┐${RESET}`);
    console.log(statsRow + `${GRAY}│${RESET}`);
    console.log(`  ${GRAY}└${'─'.repeat(statWidth)}┴${'─'.repeat(statWidth)}┴${'─'.repeat(statWidth)}┘${RESET}`);
    console.log('');
    // Menu
    console.log(`  ${CORAL}${BOLD}What would you like to do?${RESET}`);
    console.log('');
    console.log(`    ${WHITE}[1]${RESET} ${GREEN}Scan skill${RESET}              ${DIM}Analyze a local skill${RESET}`);
    console.log(`    ${WHITE}[2]${RESET} ${GREEN}Scan from URL${RESET}           ${DIM}Fetch and scan remote skill${RESET}`);
    console.log(`    ${WHITE}[3]${RESET} ${BLUE}Check known-bad${RESET}          ${DIM}Query threat database${RESET}`);
    console.log(`    ${WHITE}[4]${RESET} ${YELLOW}Configure AI${RESET}            ${DIM}Change provider/model${RESET}`);
    console.log(`    ${WHITE}[5]${RESET} ${MAGENTA}View history${RESET}            ${DIM}Recent scan results${RESET}`);
    console.log('');
    console.log(`    ${GRAY}[q]${RESET} ${DIM}Quit${RESET}`);
    console.log('');
    const choice = await prompt.ask(`  ${WHITE}❯${RESET} `);
    return choice.toLowerCase();
}
/**
 * Scan a single skill with progress output
 */
async function scanSkill(skillPath, options) {
    console.log('');
    console.log(`  ${CORAL}${BOX.thick_h.repeat(56)}${RESET}`);
    console.log(`  ${BOLD}Scanning:${RESET} ${skillPath}`);
    console.log(`  ${CORAL}${BOX.thick_h.repeat(56)}${RESET}`);
    console.log('');
    // Check known-bad database first
    const skillHash = await withSpinner('Checking threat database', async () => {
        const hash = await calculateSkillHash(skillPath);
        const knownBad = await checkKnownBad(hash);
        return { hash, knownBad };
    });
    if (skillHash.knownBad.known) {
        console.log('');
        console.log(`  ${BG_RED}${WHITE}${BOLD} ⛔ KNOWN MALICIOUS SKILL ${RESET}`);
        console.log('');
        console.log(`  ${RED}Threat: ${skillHash.knownBad.threat || 'Unknown'}${RESET}`);
        console.log(`  ${RED}${skillHash.knownBad.description || 'This skill is flagged in our database.'}${RESET}`);
        console.log('');
        console.log(`  ${YELLOW}⚠ Do NOT install this skill.${RESET}`);
        return;
    }
    // Run full scan
    const config = await loadConfig();
    const orchestrator = createOrchestrator();
    const result = await withSpinner('Running security analysis', () => orchestrator.scan({
        path: skillPath,
        semantic: options.semantic && config.configured,
        sandbox: options.sandbox,
        verbose: false
    }));
    // Display results
    console.log('');
    const output = formatResult(result, 'md');
    console.log(output);
    // If critical findings, report
    if (result.summary.critical > 0) {
        console.log(`  ${YELLOW}This skill has critical security issues.${RESET}`);
        await reportMalicious(skillHash.hash, JSON.stringify(result.findings.slice(0, 5)));
        console.log(`  ${DIM}(Reported to threat database)${RESET}`);
    }
}
/**
 * Handle local skill scanning
 */
async function handleLocalScan(prompt) {
    clearScreen();
    console.log('');
    console.log(SMALL_BANNER);
    console.log('');
    console.log(`  ${BOLD}Scan Local Skill${RESET}`);
    console.log(`  ${DIM}Enter path to skill directory (contains SKILL.md)${RESET}`);
    console.log('');
    const input = await prompt.ask(`  ${WHITE}Path:${RESET} `);
    if (!input) {
        console.log(`  ${YELLOW}No path provided.${RESET}`);
        return;
    }
    // Check path exists
    try {
        await stat(input);
    }
    catch {
        console.log(`  ${RED}Path not found: ${input}${RESET}`);
        return;
    }
    // Ask about scan options
    const config = await loadConfig();
    const semantic = config.configured;
    console.log('');
    if (semantic) {
        console.log(`  ${GREEN}✓${RESET} AI analysis enabled ${DIM}(${config.provider}/${config.model})${RESET}`);
    }
    else {
        console.log(`  ${YELLOW}○${RESET} Static analysis only ${DIM}(configure AI for deeper scans)${RESET}`);
    }
    const useSandbox = await prompt.ask(`  ${WHITE}Run behavioral sandbox? (requires Docker) ${GRAY}[y/N]:${RESET} `);
    const sandbox = useSandbox.toLowerCase() === 'y';
    await scanSkill(input, { semantic, sandbox });
}
/**
 * Handle URL scanning
 */
async function handleUrlScan(prompt) {
    clearScreen();
    console.log('');
    console.log(SMALL_BANNER);
    console.log('');
    console.log(`  ${BOLD}Scan Skill from URL${RESET}`);
    console.log(`  ${DIM}Supports GitHub repos, tar.gz, zip archives${RESET}`);
    console.log('');
    const url = await prompt.ask(`  ${WHITE}URL:${RESET} `);
    if (!url) {
        console.log(`  ${YELLOW}No URL provided.${RESET}`);
        return;
    }
    console.log('');
    console.log(`  ${DIM}Tip: Use the CLI for URL scans:${RESET}`);
    console.log(`  ${CORAL}clawguard scan ${url}${RESET}`);
    console.log('');
    // TODO: Implement inline URL fetching
}
/**
 * Handle database check
 */
async function handleDatabaseCheck(prompt) {
    clearScreen();
    console.log('');
    console.log(SMALL_BANNER);
    console.log('');
    console.log(`  ${BOLD}Check Threat Database${RESET}`);
    console.log(`  ${DIM}Enter skill path or SHA-256 hash${RESET}`);
    console.log('');
    const input = await prompt.ask(`  ${WHITE}Path/Hash:${RESET} `);
    if (!input) {
        console.log(`  ${YELLOW}No input provided.${RESET}`);
        return;
    }
    let hash;
    if (input.match(/^[a-f0-9]{64}$/i)) {
        hash = input.toLowerCase();
    }
    else {
        console.log('');
        try {
            hash = await withSpinner('Calculating hash', () => calculateSkillHash(input));
            console.log(`  ${DIM}Hash: ${hash.slice(0, 16)}...${RESET}`);
        }
        catch (error) {
            console.log(`  ${RED}Error reading skill: ${error.message}${RESET}`);
            return;
        }
    }
    console.log('');
    const result = await withSpinner('Querying database', () => checkKnownBad(hash));
    if (result.known) {
        console.log('');
        console.log(`  ${BG_RED}${WHITE}${BOLD} ⛔ KNOWN MALICIOUS ${RESET}`);
        console.log(`  ${RED}Threat: ${result.threat || 'Unknown'}${RESET}`);
        console.log(`  ${DIM}${result.description || 'No additional details.'}${RESET}`);
    }
    else {
        console.log('');
        console.log(`  ${GREEN}✓ Not in threat database${RESET}`);
        console.log(`  ${DIM}Note: This doesn't mean it's safe - run a full scan.${RESET}`);
    }
}
/**
 * Handle view history
 */
async function handleViewHistory(_prompt) {
    clearScreen();
    console.log('');
    console.log(SMALL_BANNER);
    console.log('');
    console.log(`  ${BOLD}Scan History${RESET}`);
    console.log('');
    console.log(`  ${DIM}No scans recorded yet.${RESET}`);
    console.log('');
    console.log(`  ${DIM}Scan a skill to see it here.${RESET}`);
}
/**
 * Main TUI entry point
 */
async function main(options) {
    const prompt = createPrompt();
    try {
        // Check if configured
        const configured = await isConfigured();
        if (!configured || options?.configOnly) {
            // Run config wizard
            const success = await runConfigWizard(prompt);
            if (!success && options?.configOnly) {
                prompt.close();
                return;
            }
        }
        // Main dashboard loop
        let running = true;
        while (running) {
            const choice = await showDashboard(prompt);
            switch (choice) {
                case '1':
                    await handleLocalScan(prompt);
                    await prompt.ask(`\n  ${DIM}Press Enter to continue...${RESET}`);
                    break;
                case '2':
                    await handleUrlScan(prompt);
                    await prompt.ask(`\n  ${DIM}Press Enter to continue...${RESET}`);
                    break;
                case '3':
                    await handleDatabaseCheck(prompt);
                    await prompt.ask(`\n  ${DIM}Press Enter to continue...${RESET}`);
                    break;
                case '4':
                    await runConfigWizard(prompt);
                    break;
                case '5':
                    await handleViewHistory(prompt);
                    await prompt.ask(`\n  ${DIM}Press Enter to continue...${RESET}`);
                    break;
                case 'q':
                case 'quit':
                case 'exit':
                    running = false;
                    break;
                default:
                    // Invalid choice, just refresh
                    break;
            }
        }
        prompt.close();
        clearScreen();
        console.log(`${DIM}  Stay safe. 🛡️${RESET}`);
        console.log('');
    }
    catch (error) {
        prompt.close();
        throw error;
    }
}
// CLI direct execution
const args = process.argv.slice(2);
if (args.includes('--config')) {
    main({ configOnly: true }).catch(console.error);
}
else if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}
export async function runTui(options) {
    return main(options);
}
