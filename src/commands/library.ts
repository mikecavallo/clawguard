/**
 * Library command: multi-skill attack chain analysis
 */

import type { Command } from 'commander';
import {
  analyzeSemanticChains,
  generateCapabilityReport,
} from '../analyzers/index.js';
import { loadConfig } from '../config.js';
import { glob } from 'glob';
import { join } from 'path';

import { VERSION } from '../version.js';

async function runLibraryScan(
  libraryPath: string,
  options: { output?: string; fast?: boolean; staticOnly?: boolean; verbose?: boolean }
): Promise<void> {
  const skipSemantic = options.fast || options.staticOnly;
  const config = await loadConfig();
  const runSemantic = !skipSemantic && config.configured;

  console.log('ClawGuard Library Scanner v' + VERSION);
  console.log('═'.repeat(50));
  console.log('Analyzing skill library for attack chains...');
  if (runSemantic) {
    console.log('🧠 Semantic chain analysis: ENABLED');
  } else if (!skipSemantic && !config.configured) {
    console.log('📋 Pattern analysis only (run `clawguard config` for semantic)');
  }
  console.log('');

  const skillMdFiles = await glob('**/SKILL.md', {
    cwd: libraryPath,
    ignore: ['node_modules/**', '.git/**']
  });

  const skillPaths = skillMdFiles.map(f => join(libraryPath, f.replace('/SKILL.md', '')));

  if (skillPaths.length === 0) {
    console.log('No skills found in', libraryPath);
    return;
  }

  console.log(`Found ${skillPaths.length} skills:`);
  for (const p of skillPaths) {
    console.log(`  • ${p.split('/').pop()}`);
  }
  console.log('');

  const report = await generateCapabilityReport(skillPaths);

  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║                    CAPABILITY MATRIX                            ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log('');

  for (const skill of report.skills) {
    const caps = Array.from(skill.capabilities).join(', ') || 'none';
    console.log(`📦 ${skill.name}`);
    console.log(`   Capabilities: ${caps}`);
    if (skill.sensitiveReads.length > 0) {
      console.log(`   ⚠️  Sensitive reads: ${skill.sensitiveReads.slice(0, 3).join(', ')}`);
    }
    console.log('');
  }

  if (report.chains.length > 0) {
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    ⚠️  ATTACK CHAINS DETECTED                   ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');

    for (const chain of report.chains) {
      const icon = chain.severity === 'critical' ? '⛔' : chain.severity === 'high' ? '🔴' : '🟠';
      console.log(`${icon} ${chain.title}`);
      console.log(`   ${chain.description}`);
      console.log(`   Evidence: ${chain.evidence}`);
      console.log('');
    }
  } else {
    console.log('✅ No pattern-based attack chains detected.');
  }

  let semanticChains: Awaited<ReturnType<typeof analyzeSemanticChains>> = [];
  if (runSemantic) {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                🧠 SEMANTIC CHAIN ANALYSIS                       ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('Analyzing skill combinations with LLM...');

    semanticChains = await analyzeSemanticChains(skillPaths);

    if (semanticChains.length > 0) {
      console.log('');
      for (const chain of semanticChains) {
        const icon = chain.severity === 'critical' ? '⛔' : chain.severity === 'high' ? '🔴' : '🟠';
        console.log(`${icon} ${chain.title}`);
        console.log(`   Skills: ${chain.location}`);
        console.log(`   ${chain.description.split('\n')[0]}`);
        console.log(`   Evidence: ${(chain.evidence || '').slice(0, 100)}...`);
        console.log('');
      }
    } else {
      console.log('✅ No semantic attack chains detected.');
    }
  }

  const totalChains = report.chains.length + semanticChains.length;
  const criticalChains = report.summary.criticalChains +
    semanticChains.filter(c => c.severity === 'critical').length;

  console.log('─'.repeat(60));
  console.log(`Summary: ${report.summary.totalSkills} skills, ${totalChains} attack chains (${criticalChains} critical)`);

  if (criticalChains > 0) process.exit(2);
  if (totalChains > 0) process.exit(1);
}

export function register(program: Command): void {
  program
    .command('library <path>')
    .description('Analyze an entire skill library for attack chains')
    .option('-o, --output <format>', 'Output format: json, md (default: md)', 'md')
    .option('-f, --fast', 'Pattern analysis only (skip semantic)')
    .option('--static-only', 'Pattern analysis only (skip semantic)')
    .option('-v, --verbose', 'Enable verbose output')
    .action(async (libraryPath: string, options) => {
      try {
        await runLibraryScan(libraryPath, options);
      } catch (error) {
        console.error('Error:', (error as Error).message);
        process.exit(1);
      }
    });
}
