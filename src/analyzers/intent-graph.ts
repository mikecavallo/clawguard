/**
 * ClawGuard Intent Graph Generator
 * 
 * Builds a visual graph of what a skill can:
 * - READ (data sources)
 * - WRITE (persistence targets)  
 * - SEND (exfiltration channels)
 * 
 * This makes the attack surface immediately visible.
 */

import { readFile } from 'fs/promises';
import { join, basename } from 'path';
import { glob } from 'glob';

interface DataNode {
  id: string;
  type: 'source' | 'sink' | 'skill' | 'channel';
  label: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  category: string;
}

interface DataEdge {
  from: string;
  to: string;
  action: 'read' | 'write' | 'send' | 'exec';
  evidence: string;
}

interface IntentGraph {
  nodes: DataNode[];
  edges: DataEdge[];
  summary: {
    sensitiveReads: string[];
    exfilChannels: string[];
    persistenceTargets: string[];
    execCapabilities: boolean;
    riskAssessment: string;
  };
}

// Data sources with risk levels
const DATA_SOURCES: Array<{ pattern: RegExp; label: string; risk: DataNode['risk']; category: string }> = [
  // Critical - credentials
  { pattern: /\.ssh\/id_rsa|\.ssh\/id_ed25519/g, label: 'SSH Private Keys', risk: 'critical', category: 'credentials' },
  { pattern: /\.aws\/credentials/g, label: 'AWS Credentials', risk: 'critical', category: 'credentials' },
  { pattern: /\.kube\/config/g, label: 'Kubernetes Config', risk: 'critical', category: 'credentials' },
  { pattern: /\.gcloud.*credentials/g, label: 'GCP Credentials', risk: 'critical', category: 'credentials' },
  { pattern: /\.azure\/credentials/g, label: 'Azure Credentials', risk: 'critical', category: 'credentials' },
  { pattern: /\.gnupg\/private/g, label: 'GPG Private Keys', risk: 'critical', category: 'credentials' },
  { pattern: /wallet\.dat|\.bitcoin|\.ethereum/g, label: 'Crypto Wallets', risk: 'critical', category: 'credentials' },
  
  // High - tokens/secrets
  { pattern: /\.env(?:\.local|\.prod|\.dev)?/g, label: '.env Files', risk: 'high', category: 'secrets' },
  { pattern: /\.npmrc/g, label: 'NPM Token', risk: 'high', category: 'secrets' },
  { pattern: /\.netrc/g, label: 'Netrc Credentials', risk: 'high', category: 'secrets' },
  { pattern: /\.git-credentials/g, label: 'Git Credentials', risk: 'high', category: 'secrets' },
  { pattern: /\.pypirc/g, label: 'PyPI Credentials', risk: 'high', category: 'secrets' },
  { pattern: /\.docker\/config/g, label: 'Docker Auth', risk: 'high', category: 'secrets' },
  
  // Medium - personal data
  { pattern: /\.bash_history|\.zsh_history/g, label: 'Shell History', risk: 'medium', category: 'personal' },
  { pattern: /\.config\/.*\.json/g, label: 'App Configs', risk: 'medium', category: 'personal' },
  { pattern: /Documents|Desktop|Downloads/g, label: 'User Documents', risk: 'medium', category: 'personal' },
  
  // Agent-specific
  { pattern: /memory\/.*\.md|MEMORY\.md/g, label: 'Agent Memory', risk: 'high', category: 'agent' },
  { pattern: /\.openclaw|\.clawdbot/g, label: 'Agent Platform Config', risk: 'high', category: 'agent' },
  { pattern: /workspace\//g, label: 'Workspace Files', risk: 'medium', category: 'agent' },
];

// Data sinks (where data can go)
const DATA_SINKS: Array<{ pattern: RegExp; label: string; risk: DataNode['risk']; category: string }> = [
  // Network exfil
  { pattern: /https?:\/\/[^\s"'<>]+/g, label: 'External URLs', risk: 'high', category: 'network' },
  { pattern: /webhook\.site|requestbin|pipedream|ngrok/g, label: 'Data Collection Services', risk: 'critical', category: 'network' },
  { pattern: /pastebin|hastebin|ghostbin/g, label: 'Paste Services', risk: 'high', category: 'network' },
  
  // Messaging
  { pattern: /telegram|discord|slack|whatsapp/gi, label: 'Messaging Platforms', risk: 'high', category: 'messaging' },
  { pattern: /smtp|sendmail|email/gi, label: 'Email', risk: 'high', category: 'messaging' },
  
  // Persistence
  { pattern: /\.bashrc|\.zshrc|\.profile/g, label: 'Shell RC Files', risk: 'high', category: 'persistence' },
  { pattern: /crontab|\/etc\/cron/g, label: 'Cron Jobs', risk: 'high', category: 'persistence' },
  { pattern: /\.git\/hooks/g, label: 'Git Hooks', risk: 'medium', category: 'persistence' },
  { pattern: /systemd|launchd/g, label: 'System Services', risk: 'critical', category: 'persistence' },
  
  // Agent persistence
  { pattern: /memory\/.*\.md/g, label: 'Agent Memory (Write)', risk: 'medium', category: 'agent' },
  { pattern: /HEARTBEAT\.md/g, label: 'Heartbeat Config', risk: 'high', category: 'agent' },
];

/**
 * Build an intent graph for a skill
 */
export async function buildIntentGraph(skillPath: string): Promise<IntentGraph> {
  const nodes: DataNode[] = [];
  const edges: DataEdge[] = [];
  const skillName = basename(skillPath);
  
  // Add skill node at center
  nodes.push({
    id: 'skill',
    type: 'skill',
    label: skillName,
    risk: 'low',
    category: 'skill'
  });

  // Read all files
  const files = await glob('**/*.{md,js,ts,py,sh,yaml,yml,json}', {
    cwd: skillPath,
    ignore: ['node_modules/**', '.git/**'],
    nodir: true
  });

  const allContent: string[] = [];
  for (const file of files) {
    try {
      const content = await readFile(join(skillPath, file), 'utf-8');
      allContent.push(content);
    } catch {
      // Skip
    }
  }
  const combinedContent = allContent.join('\n');

  // Find data sources being accessed
  const sensitiveReads: string[] = [];
  for (const source of DATA_SOURCES) {
    const matches = combinedContent.match(source.pattern);
    if (matches) {
      const nodeId = `source_${source.label.toLowerCase().replace(/\s+/g, '_')}`;
      if (!nodes.find(n => n.id === nodeId)) {
        nodes.push({
          id: nodeId,
          type: 'source',
          label: source.label,
          risk: source.risk,
          category: source.category
        });
        edges.push({
          from: nodeId,
          to: 'skill',
          action: 'read',
          evidence: matches.slice(0, 2).join(', ')
        });
        sensitiveReads.push(source.label);
      }
    }
  }

  // Find data sinks
  const exfilChannels: string[] = [];
  const persistenceTargets: string[] = [];
  for (const sink of DATA_SINKS) {
    const matches = combinedContent.match(sink.pattern);
    if (matches) {
      const nodeId = `sink_${sink.label.toLowerCase().replace(/\s+/g, '_')}`;
      if (!nodes.find(n => n.id === nodeId)) {
        nodes.push({
          id: nodeId,
          type: 'sink',
          label: sink.label,
          risk: sink.risk,
          category: sink.category
        });
        
        const action = sink.category === 'persistence' ? 'write' : 'send';
        edges.push({
          from: 'skill',
          to: nodeId,
          action,
          evidence: matches.slice(0, 2).join(', ')
        });
        
        if (sink.category === 'persistence') {
          persistenceTargets.push(sink.label);
        } else {
          exfilChannels.push(sink.label);
        }
      }
    }
  }

  // Check for exec capabilities (exclude regex.exec(), backtick code blocks in markdown)
  const execPatterns = /child_process|subprocess|execSync|(?:cp|child)\.\s*exec\s*\(|(?:^|\s)spawn\s*\(|\$\([^)]+\)/gm;
  const execCapabilities = execPatterns.test(combinedContent);

  // Build risk assessment
  let riskAssessment = '';
  if (sensitiveReads.length > 0 && exfilChannels.length > 0) {
    riskAssessment = 'CRITICAL: Can read sensitive data AND has exfiltration channels';
  } else if (sensitiveReads.some(r => r.includes('Credential') || r.includes('Key'))) {
    riskAssessment = 'HIGH: Accesses credentials';
  } else if (persistenceTargets.length > 0) {
    riskAssessment = 'HIGH: Establishes persistence';
  } else if (execCapabilities) {
    riskAssessment = 'MEDIUM: Has shell execution capability';
  } else if (sensitiveReads.length > 0 || exfilChannels.length > 0) {
    riskAssessment = 'MEDIUM: Has sensitive data access or network capability';
  } else {
    riskAssessment = 'LOW: No obvious dangerous capabilities';
  }

  return {
    nodes,
    edges,
    summary: {
      sensitiveReads,
      exfilChannels,
      persistenceTargets,
      execCapabilities,
      riskAssessment
    }
  };
}

/**
 * Render intent graph as ASCII art
 */
export function renderGraphAscii(graph: IntentGraph): string {
  const lines: string[] = [];
  
  lines.push('╔════════════════════════════════════════════════════════════════╗');
  lines.push('║                    INTENT GRAPH                                ║');
  lines.push('╚════════════════════════════════════════════════════════════════╝');
  lines.push('');

  // Group nodes by type
  const sources = graph.nodes.filter(n => n.type === 'source');
  const sinks = graph.nodes.filter(n => n.type === 'sink');
  const skill = graph.nodes.find(n => n.type === 'skill');

  if (sources.length > 0) {
    lines.push('┌─ DATA SOURCES (what skill can READ) ─────────────────────────────');
    for (const source of sources) {
      const riskIcon = source.risk === 'critical' ? '⛔' : source.risk === 'high' ? '🔴' : '🟡';
      lines.push(`│  ${riskIcon} ${source.label}`);
    }
    lines.push('│');
    lines.push('│          ↓ READ');
    lines.push('│');
  }

  lines.push(`├─────────[ ${skill?.label || 'SKILL'} ]─────────`);
  
  if (sinks.length > 0) {
    lines.push('│');
    lines.push('│          ↓ WRITE/SEND');
    lines.push('│');
    lines.push('└─ DATA SINKS (where skill can SEND) ──────────────────────────────');
    for (const sink of sinks) {
      const riskIcon = sink.risk === 'critical' ? '⛔' : sink.risk === 'high' ? '🔴' : '🟡';
      const edge = graph.edges.find(e => e.to === sink.id);
      const action = edge?.action || 'send';
      lines.push(`   ${riskIcon} ${sink.label} [${action.toUpperCase()}]`);
    }
  }

  lines.push('');
  lines.push('─────────────────────────────────────────────────────────────────────');
  lines.push(`ASSESSMENT: ${graph.summary.riskAssessment}`);
  lines.push('─────────────────────────────────────────────────────────────────────');

  return lines.join('\n');
}

/**
 * Render intent graph as Mermaid diagram (for markdown)
 */
export function renderGraphMermaid(graph: IntentGraph): string {
  const lines: string[] = ['```mermaid', 'graph LR'];
  
  // Add skill node
  const skill = graph.nodes.find(n => n.type === 'skill');
  lines.push(`  SKILL[${skill?.label || 'Skill'}]`);
  
  // Add source nodes and edges
  const sources = graph.nodes.filter(n => n.type === 'source');
  for (const source of sources) {
    const shape = source.risk === 'critical' ? `((${source.label}))` : `[${source.label}]`;
    lines.push(`  ${source.id}${shape}`);
    lines.push(`  ${source.id} -->|read| SKILL`);
  }
  
  // Add sink nodes and edges
  const sinks = graph.nodes.filter(n => n.type === 'sink');
  for (const sink of sinks) {
    const shape = sink.risk === 'critical' ? `((${sink.label}))` : `[${sink.label}]`;
    const edge = graph.edges.find(e => e.to === sink.id);
    lines.push(`  ${sink.id}${shape}`);
    lines.push(`  SKILL -->|${edge?.action || 'send'}| ${sink.id}`);
  }
  
  // Style dangerous nodes
  const criticalNodes = graph.nodes.filter(n => n.risk === 'critical').map(n => n.id);
  const highNodes = graph.nodes.filter(n => n.risk === 'high').map(n => n.id);
  
  if (criticalNodes.length > 0) {
    lines.push(`  style ${criticalNodes.join(',')} fill:#ff0000,color:#fff`);
  }
  if (highNodes.length > 0) {
    lines.push(`  style ${highNodes.join(',')} fill:#ff6600,color:#fff`);
  }
  
  lines.push('```');
  return lines.join('\n');
}

export type { IntentGraph, DataNode, DataEdge };
