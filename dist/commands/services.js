/**
 * Service commands: monitor, dashboard
 */
import { getMonitor, startMonitor, stopMonitor } from '../monitor.js';
import { startDashboard } from '../dashboard.js';
export function register(program) {
    // ========== CONTINUOUS MONITORING ==========
    program
        .command('monitor')
        .description('Continuous monitoring for installed skills')
        .option('--start', 'Start the monitor daemon')
        .option('--stop', 'Stop the monitor daemon')
        .option('--add <path>', 'Add a skill path to watch')
        .option('--remove <path>', 'Remove a skill path from watch')
        .option('--enable', 'Enable monitoring')
        .option('--disable', 'Disable monitoring')
        .option('--status', 'Show monitor status')
        .option('--alerts', 'Show recent alerts')
        .action(async (options) => {
        try {
            const monitor = getMonitor();
            await monitor.loadConfig();
            if (options.start) {
                await startMonitor();
                console.log('Monitor running. Press Ctrl+C to stop.');
                await new Promise(() => { });
            }
            if (options.stop) {
                await stopMonitor();
                return;
            }
            if (options.add) {
                await monitor.addPath(options.add);
                console.log(`✓ Added ${options.add} to watch list`);
                return;
            }
            if (options.remove) {
                await monitor.removePath(options.remove);
                console.log(`✓ Removed ${options.remove} from watch list`);
                return;
            }
            if (options.enable) {
                await monitor.enable();
                console.log('✓ Monitoring enabled');
                return;
            }
            if (options.disable) {
                await monitor.disable();
                console.log('✓ Monitoring disabled');
                return;
            }
            if (options.alerts) {
                const alerts = await monitor.getAlerts(20);
                if (alerts.length === 0) {
                    console.log('No recent alerts.');
                }
                else {
                    console.log('Recent alerts:\n');
                    for (const a of alerts) {
                        const icon = a.severity === 'critical' ? '🚨' : a.severity === 'warning' ? '⚠️' : 'ℹ️';
                        console.log(`${icon} [${a.skillName}] ${a.message}`);
                        console.log(`   ${a.timestamp}\n`);
                    }
                }
                return;
            }
            // Default: show status
            const config = monitor.getConfig();
            console.log('📡 ClawGuard Monitor Status\n');
            console.log(`   Enabled: ${config.enabled ? 'Yes' : 'No'}`);
            console.log(`   Watch paths: ${config.watchPaths.length}`);
            for (const p of config.watchPaths) {
                console.log(`     - ${p}`);
            }
            console.log(`   Scan interval: ${config.scanIntervalMs / 1000}s`);
            if (config.alertWebhook) {
                console.log(`   Webhook: ${config.alertWebhook}`);
            }
        }
        catch (error) {
            console.error('Monitor error:', error.message);
            process.exit(1);
        }
    });
    // ========== DASHBOARD ==========
    program
        .command('dashboard')
        .description('Start the web dashboard')
        .option('-p, --port <port>', 'Port to run on', '18790')
        .action(async (options) => {
        try {
            await startDashboard(parseInt(options.port));
            console.log('Dashboard running. Press Ctrl+C to stop.');
            await new Promise(() => { });
        }
        catch (error) {
            console.error('Dashboard error:', error.message);
            process.exit(1);
        }
    });
}
