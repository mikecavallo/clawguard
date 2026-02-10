/**
 * Tool commands: sign, diff, reputation
 */
import { loadConfig } from '../config.js';
import { signSkill, verifySkill, generateKeyPair, auditSkill } from '../signing.js';
import { analyzeDiff, getHistory } from '../diff.js';
import { getSkillReputation, getAuthorReputation, formatBadge } from '../reputation.js';
export function register(program) {
    // ========== SKILL SIGNING ==========
    program
        .command('sign <path>')
        .description('Sign a skill with your private key')
        .option('--generate <id>', 'Generate a new keypair')
        .option('--verify', 'Verify existing signature instead of signing')
        .option('--audit <risk>', 'Add audit signature (SAFE/LOW/MEDIUM/HIGH/CRITICAL)')
        .option('--auditor <id>', 'Auditor ID for audit signature')
        .action(async (skillPath, options) => {
        try {
            if (options.generate) {
                await generateKeyPair(options.generate);
                return;
            }
            if (options.verify) {
                const result = await verifySkill(skillPath);
                if (result.valid) {
                    console.log(`✅ Valid signature`);
                    console.log(`   Author: ${result.author}`);
                    console.log(`   Signed: ${result.signedAt}`);
                    console.log(`   Audits: ${result.audits}`);
                }
                else {
                    console.log(`❌ Invalid: ${result.error}`);
                    process.exit(1);
                }
                return;
            }
            if (options.audit) {
                if (!options.auditor) {
                    console.error('Error: --auditor required for audit');
                    process.exit(1);
                }
                await auditSkill(skillPath, options.auditor, options.audit);
                return;
            }
            await loadConfig();
            const authorId = 'default';
            await signSkill(skillPath, authorId);
        }
        catch (error) {
            console.error('Sign error:', error.message);
            process.exit(1);
        }
    });
    // ========== DIFFERENTIAL ANALYSIS ==========
    program
        .command('diff <path>')
        .description('Analyze changes from previous version')
        .option('--history', 'Show full version history')
        .action(async (skillPath, options) => {
        try {
            if (options.history) {
                const skillName = skillPath.split('/').pop() || 'unknown';
                const history = await getHistory(skillName);
                if (!history) {
                    console.log('No history found for this skill.');
                    return;
                }
                console.log(`📜 History for ${skillName}:`);
                for (const snap of history.snapshots) {
                    console.log(`   ${snap.capturedAt} - v${snap.version || '?'} (${snap.capabilities.join(', ') || 'no caps'})`);
                }
                return;
            }
            const result = await analyzeDiff(skillPath);
            if (result.isNew) {
                console.log('📦 First scan of this skill - baseline captured.');
                return;
            }
            console.log(`📊 Comparing versions: ${result.previousVersion || '?'} → ${result.currentVersion || '?'}`);
            if (result.findings.length === 0) {
                console.log('✅ No significant changes detected.');
            }
            else {
                console.log(`⚠️  ${result.findings.length} change(s) detected:\n`);
                for (const f of result.findings) {
                    const icon = f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : 'ℹ️';
                    console.log(`${icon} ${f.title}`);
                    console.log(`   ${f.description.split('\n')[0]}\n`);
                }
            }
        }
        catch (error) {
            console.error('Diff error:', error.message);
            process.exit(1);
        }
    });
    // ========== REPUTATION ==========
    program
        .command('reputation <target>')
        .description('Check community reputation for skill or author')
        .option('--author', 'Check author reputation instead of skill')
        .action(async (target, options) => {
        try {
            if (options.author) {
                const rep = await getAuthorReputation(target);
                if (rep) {
                    console.log(`👤 Author: ${rep.authorId}`);
                    console.log(`   Score: ${rep.reputationScore}/100`);
                    console.log(`   Skills: ${rep.totalSkills}`);
                    console.log(`   Badge: ${rep.badge}`);
                }
                else {
                    console.log('No reputation data found for this author.');
                }
            }
            else {
                const { calculateSkillHash } = await import('../database.js');
                const hash = target.match(/^[a-f0-9]{64}$/i) ? target : await calculateSkillHash(target);
                const rep = await getSkillReputation(hash);
                if (rep) {
                    console.log(formatBadge(rep));
                    console.log(`   Scans: ${rep.totalScans} (${rep.uniqueScanners} unique scanners)`);
                    console.log(`   Audits: ${rep.auditCount}`);
                    console.log(`   Avg risk: ${rep.averageRiskScore}/100`);
                }
                else {
                    console.log('No reputation data found. This skill may not have been scanned by the community yet.');
                }
            }
        }
        catch (error) {
            console.error('Reputation error:', error.message);
            process.exit(1);
        }
    });
}
