/**
 * Info commands: version, ui, help, about
 */

import type { Command } from 'commander';
import { showHelp } from '../help.js';

import { VERSION } from '../version.js';

export function register(program: Command): void {
  program
    .command('version')
    .description('Show version information')
    .action(() => {
      console.log(`ClawGuard v${VERSION}`);
      console.log('Revolutionary security scanner for AI agent skills');
    });

  // ========== INTERACTIVE TUI ==========
  program
    .command('ui')
    .alias('tui')
    .description('Launch interactive terminal interface')
    .action(async () => {
      const { runTui } = await import('../tui.js');
      await runTui();
    });

  // ========== DETAILED HELP ==========
  program
    .command('help [topic]')
    .description('Show detailed help (topics: about, scan, library, sandbox, gate, config, ui)')
    .action((topic?: string) => {
      showHelp(topic || 'about');
    });

  // ========== ABOUT ==========
  program
    .command('about')
    .description('Learn how ClawGuard protects you')
    .action(() => {
      showHelp('about');
    });
}
