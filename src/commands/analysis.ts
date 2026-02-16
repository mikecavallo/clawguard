/**
 * Analysis commands: graph, honeypot
 */

import type { Command } from 'commander';
import {
  scanForCredentialAccess,
  buildIntentGraph,
  renderGraphAscii,
  renderGraphMermaid,
} from '../analyzers/index.js';

import { VERSION } from '../version.js';

export function register(program: Command): void {
  // ========== GRAPH COMMAND ==========
  program
    .command('graph <path>')
    .description('Generate intent graph showing data flow')
    .option('-f, --format <type>', 'Output format: ascii, mermaid (default: ascii)', 'ascii')
    .action(async (skillPath: string, options) => {
      try {
        const graph = await buildIntentGraph(skillPath);
        if (options.format === 'mermaid') {
          console.log(renderGraphMermaid(graph));
        } else {
          console.log(renderGraphAscii(graph));
        }
      } catch (error) {
        console.error('Error:', (error as Error).message);
        process.exit(1);
      }
    });

  // ========== HONEYPOT COMMAND ==========
  program
    .command('honeypot <path>')
    .description('Scan for credential access patterns')
    .option('-v, --verbose', 'Enable verbose output')
    .action(async (skillPath: string) => {
      try {
        console.log('ClawGuard Honeypot Scanner v' + VERSION);
        console.log('═'.repeat(50));
        console.log('Scanning for credential access patterns...');
        console.log('');

        const findings = await scanForCredentialAccess(skillPath);

        if (findings.length === 0) {
          console.log('✅ No credential access patterns detected.');
          return;
        }

        console.log(`⚠️  Found ${findings.length} credential access patterns:`);
        console.log('');

        for (const f of findings) {
          const icon = f.severity === 'critical' ? '⛔' : f.severity === 'high' ? '🔴' : '🟠';
          console.log(`${icon} ${f.title}`);
          console.log(`   Location: ${f.location}`);
          console.log(`   Evidence: ${f.evidence}`);
          console.log('');
        }

        const critical = findings.filter(f => f.severity === 'critical').length;
        if (critical > 0) process.exit(2);
        if (findings.length > 0) process.exit(1);
      } catch (error) {
        console.error('Error:', (error as Error).message);
        process.exit(1);
      }
    });
}
