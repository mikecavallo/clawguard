/**
 * Config commands: config, init
 */
import { showConfig, clearConfig, testConfig } from '../config.js';
export function register(program) {
    // ========== CONFIG COMMAND ==========
    program
        .command('config')
        .description('Configure ClawGuard (API keys, model selection)')
        .option('--show', 'Show current configuration')
        .option('--clear', 'Clear stored configuration')
        .option('--test', 'Test API connection')
        .action(async (options) => {
        if (options.show) {
            await showConfig();
        }
        else if (options.clear) {
            await clearConfig();
        }
        else if (options.test) {
            const success = await testConfig();
            process.exit(success ? 0 : 1);
        }
        else {
            const { runTui } = await import('../tui.js');
            await runTui({ configOnly: true });
        }
    });
    // ========== INIT COMMAND ==========
    program
        .command('init')
        .description('Initialize ClawGuard with setup wizard')
        .action(async () => {
        const { runTui } = await import('../tui.js');
        await runTui({ configOnly: true });
    });
}
