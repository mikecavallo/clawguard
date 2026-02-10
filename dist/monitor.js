/**
 * ClawGuard Continuous Monitoring
 *
 * Runtime watching for installed skills:
 * - Periodic re-scans
 * - File change detection
 * - Behavior baseline comparison
 * - Alert on anomalies
 */
import { watch } from 'fs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join, basename } from 'path';
import { homedir } from 'os';
import { EventEmitter } from 'events';
import { createOrchestrator } from './orchestrator.js';
import { analyzeDiff, createSnapshot } from './diff.js';
import { calculateSkillHash } from './database.js';
const MONITOR_CONFIG = join(homedir(), '.config', 'clawguard', 'monitor.json');
const ALERTS_LOG = join(homedir(), '.config', 'clawguard', 'alerts.json');
const DEFAULT_CONFIG = {
    enabled: false,
    watchPaths: [],
    scanIntervalMs: 3600000 // 1 hour
};
class SkillMonitor extends EventEmitter {
    config = DEFAULT_CONFIG;
    states = new Map();
    watchers = new Map();
    scanInterval;
    running = false;
    async loadConfig() {
        try {
            const data = await readFile(MONITOR_CONFIG, 'utf-8');
            this.config = { ...DEFAULT_CONFIG, ...JSON.parse(data) };
        }
        catch {
            this.config = DEFAULT_CONFIG;
        }
    }
    async saveConfig() {
        await mkdir(join(homedir(), '.config', 'clawguard'), { recursive: true });
        await writeFile(MONITOR_CONFIG, JSON.stringify(this.config, null, 2));
    }
    async start() {
        if (this.running)
            return;
        await this.loadConfig();
        if (!this.config.enabled) {
            console.log('Monitor is disabled. Enable with: clawguard monitor --enable');
            return;
        }
        this.running = true;
        console.log('🔍 ClawGuard Monitor started');
        console.log(`   Watching ${this.config.watchPaths.length} paths`);
        console.log(`   Scan interval: ${this.config.scanIntervalMs / 1000}s`);
        // Initial scan of all paths
        for (const path of this.config.watchPaths) {
            await this.scanPath(path);
            this.setupWatcher(path);
        }
        // Periodic rescan
        this.scanInterval = setInterval(async () => {
            console.log('🔍 Running periodic scan...');
            for (const path of this.config.watchPaths) {
                await this.scanPath(path);
            }
        }, this.config.scanIntervalMs);
    }
    async stop() {
        this.running = false;
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
        }
        for (const watcher of this.watchers.values()) {
            watcher.close();
        }
        this.watchers.clear();
        console.log('🛑 Monitor stopped');
    }
    setupWatcher(skillPath) {
        try {
            const watcher = watch(skillPath, { recursive: true }, async (event, filename) => {
                if (!filename)
                    return;
                // Ignore node_modules and .git
                if (filename.includes('node_modules') || filename.includes('.git'))
                    return;
                console.log(`📁 File change: ${filename} (${event})`);
                // Rescan on change
                await this.scanPath(skillPath);
            });
            this.watchers.set(skillPath, watcher);
        }
        catch (error) {
            console.error(`Failed to watch ${skillPath}:`, error);
        }
    }
    async scanPath(skillPath) {
        const skillName = basename(skillPath);
        try {
            // Get current state
            const hash = await calculateSkillHash(skillPath);
            const previousState = this.states.get(skillPath);
            // Check for hash change
            if (previousState && previousState.hash !== hash) {
                await this.alert({
                    skillPath,
                    skillName,
                    type: 'hash_mismatch',
                    severity: 'warning',
                    message: `Skill content changed since last scan`,
                    details: { oldHash: previousState.hash, newHash: hash }
                });
            }
            // Run differential analysis
            const diffResult = await analyzeDiff(skillPath);
            for (const finding of diffResult.findings) {
                const severity = finding.severity === 'critical' ? 'critical' :
                    finding.severity === 'high' ? 'warning' : 'info';
                await this.alert({
                    skillPath,
                    skillName,
                    type: 'capability_change',
                    severity,
                    message: finding.title,
                    details: finding
                });
            }
            // Quick scan for new findings
            const orchestrator = createOrchestrator();
            const result = await orchestrator.scan({
                path: skillPath,
                semantic: false, // Fast scan
                sandbox: false
            });
            // Check for new findings since last scan
            if (previousState && result.findings.length > previousState.lastFindings) {
                const newCount = result.findings.length - previousState.lastFindings;
                await this.alert({
                    skillPath,
                    skillName,
                    type: 'new_finding',
                    severity: result.summary.critical > 0 ? 'critical' : 'warning',
                    message: `${newCount} new security finding(s) detected`,
                    details: result.findings.slice(0, 5)
                });
            }
            // Get current capabilities
            const snapshot = await createSnapshot(skillPath);
            // Check for capability changes
            if (previousState) {
                const oldCaps = new Set(previousState.capabilities);
                const newCaps = snapshot.capabilities.filter(c => !oldCaps.has(c));
                if (newCaps.length > 0) {
                    await this.alert({
                        skillPath,
                        skillName,
                        type: 'capability_change',
                        severity: 'warning',
                        message: `New capabilities detected: ${newCaps.join(', ')}`,
                        details: { oldCaps: previousState.capabilities, newCaps: snapshot.capabilities }
                    });
                }
            }
            // Update state
            this.states.set(skillPath, {
                path: skillPath,
                hash,
                lastScan: new Date().toISOString(),
                lastFindings: result.findings.length,
                capabilities: snapshot.capabilities
            });
        }
        catch (error) {
            console.error(`Error scanning ${skillPath}:`, error);
        }
    }
    async alert(params) {
        const alert = {
            id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            timestamp: new Date().toISOString(),
            ...params
        };
        // Emit event
        this.emit('alert', alert);
        // Log to console
        const icon = alert.severity === 'critical' ? '🚨' :
            alert.severity === 'warning' ? '⚠️' : 'ℹ️';
        console.log(`${icon} [${alert.skillName}] ${alert.message}`);
        // Save to log
        await this.logAlert(alert);
        // Send webhook if configured
        if (this.config.alertWebhook) {
            await this.sendWebhook(alert);
        }
    }
    async logAlert(alert) {
        try {
            let alerts = [];
            try {
                const data = await readFile(ALERTS_LOG, 'utf-8');
                alerts = JSON.parse(data);
            }
            catch { /* no-op */ }
            alerts.push(alert);
            // Keep last 1000 alerts
            if (alerts.length > 1000) {
                alerts = alerts.slice(-1000);
            }
            await mkdir(join(homedir(), '.config', 'clawguard'), { recursive: true });
            await writeFile(ALERTS_LOG, JSON.stringify(alerts, null, 2));
        }
        catch { /* no-op */ }
    }
    async sendWebhook(alert) {
        if (!this.config.alertWebhook)
            return;
        try {
            await fetch(this.config.alertWebhook, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(alert),
                signal: AbortSignal.timeout(5000)
            });
        }
        catch (error) {
            console.error('Webhook failed:', error);
        }
    }
    async addPath(path) {
        if (!this.config.watchPaths.includes(path)) {
            this.config.watchPaths.push(path);
            await this.saveConfig();
            if (this.running) {
                await this.scanPath(path);
                this.setupWatcher(path);
            }
        }
    }
    async removePath(path) {
        this.config.watchPaths = this.config.watchPaths.filter(p => p !== path);
        await this.saveConfig();
        const watcher = this.watchers.get(path);
        if (watcher) {
            watcher.close();
            this.watchers.delete(path);
        }
        this.states.delete(path);
    }
    async enable() {
        this.config.enabled = true;
        await this.saveConfig();
    }
    async disable() {
        this.config.enabled = false;
        await this.saveConfig();
        await this.stop();
    }
    getConfig() {
        return { ...this.config };
    }
    async getAlerts(limit = 50) {
        try {
            const data = await readFile(ALERTS_LOG, 'utf-8');
            const alerts = JSON.parse(data);
            return alerts.slice(-limit).reverse();
        }
        catch {
            return [];
        }
    }
}
// Singleton instance
let monitorInstance = null;
export function getMonitor() {
    if (!monitorInstance) {
        monitorInstance = new SkillMonitor();
    }
    return monitorInstance;
}
export async function startMonitor() {
    const monitor = getMonitor();
    await monitor.start();
}
export async function stopMonitor() {
    const monitor = getMonitor();
    await monitor.stop();
}
