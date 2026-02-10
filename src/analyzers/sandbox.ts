/**
 * ClawGuard Behavioral Sandbox
 * 
 * Runs skills in an isolated Docker container and monitors:
 * - File access (especially credential paths)
 * - Network activity (connections, DNS, HTTP)
 * - Process execution (shell commands, child processes)
 * - Environment variable access
 * 
 * Uses honeypot files to detect credential theft attempts.
 */

import { spawn, execSync } from 'child_process';
import { writeFile, mkdir, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { randomUUID } from 'crypto';
import type { Finding, SandboxAnalyzer } from '../types.js';

// Honeypot file paths that will be planted in the sandbox
const HONEYPOT_FILES = [
  { path: '/root/.ssh/id_rsa', content: 'HONEYPOT_SSH_KEY_CLAWGUARD_DETECT' },
  { path: '/root/.ssh/id_ed25519', content: 'HONEYPOT_ED25519_KEY_CLAWGUARD_DETECT' },
  { path: '/root/.aws/credentials', content: '[default]\naws_access_key_id=HONEYPOT_AWS_KEY\naws_secret_access_key=HONEYPOT_AWS_SECRET' },
  { path: '/root/.config/gcloud/credentials.json', content: '{"type":"HONEYPOT_GCP_CREDS"}' },
  { path: '/root/.env', content: 'API_KEY=HONEYPOT_API_KEY_12345\nSECRET=HONEYPOT_SECRET_67890' },
  { path: '/root/.netrc', content: 'machine github.com login HONEYPOT_USER password HONEYPOT_TOKEN' },
  { path: '/root/.npmrc', content: '//registry.npmjs.org/:_authToken=HONEYPOT_NPM_TOKEN' },
];

// Suspicious network destinations
const SUSPICIOUS_DOMAINS = [
  /webhook\.site/i,
  /ngrok\.io/i,
  /requestbin/i,
  /pipedream/i,
  /burpcollaborator/i,
  /evil\.com/i,
  /attacker/i,
  /exfil/i,
  /collector/i,
  /c2\./i,
];

// Suspicious file access patterns
const SENSITIVE_PATHS = [
  /\/root\/\.ssh\//,
  /\/root\/\.aws\//,
  /\/root\/\.gnupg\//,
  /\/root\/\.config\/gcloud/,
  /\/etc\/shadow/,
  /\/etc\/passwd/,
  /\.env$/,
  /credentials/i,
  /\.pem$/,
  /private.*key/i,
];

interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  fileAccess: FileAccessEvent[];
  networkActivity: NetworkEvent[];
  processExecution: ProcessEvent[];
  honeypotHits: HoneypotHit[];
  duration: number;
}

interface FileAccessEvent {
  path: string;
  operation: 'read' | 'write' | 'stat' | 'open';
  timestamp: number;
}

interface NetworkEvent {
  destination: string;
  port: number;
  protocol: string;
  timestamp: number;
  data?: string;
}

interface ProcessEvent {
  command: string;
  args: string[];
  timestamp: number;
}

interface HoneypotHit {
  path: string;
  operation: string;
  timestamp: number;
}

/**
 * Check if Docker is available
 */
async function isDockerAvailable(): Promise<boolean> {
  try {
    execSync('docker --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the sandbox Docker image if needed
 */
async function ensureSandboxImage(): Promise<string> {
  const imageName = 'clawguard-sandbox:latest';
  
  // Check if image exists
  try {
    execSync(`docker image inspect ${imageName}`, { stdio: 'pipe' });
    return imageName;
  } catch {
    // Need to build
  }

  // Create Dockerfile
  const dockerfile = `
FROM node:20-slim

# Install monitoring tools
RUN apt-get update && apt-get install -y \\
    strace \\
    tcpdump \\
    curl \\
    python3 \\
    python3-pip \\
    inotify-tools \\
    && rm -rf /var/lib/apt/lists/*

# Create honeypot directories
RUN mkdir -p /root/.ssh /root/.aws /root/.config/gcloud /root/.gnupg

# Create monitoring script
COPY monitor.sh /monitor.sh
RUN chmod +x /monitor.sh

# Working directory for skill
WORKDIR /skill

# Entry point
ENTRYPOINT ["/monitor.sh"]
`;

  const monitorScript = `#!/bin/bash
set -e

# Output files
STRACE_LOG=/tmp/strace.log
NETWORK_LOG=/tmp/network.log
FILE_LOG=/tmp/files.log
HONEYPOT_LOG=/tmp/honeypot.log

# Create honeypot credential files
mkdir -p /root/.ssh /root/.aws /root/.config/gcloud
echo "HONEYPOT_SSH_PRIVATE_KEY_CLAWGUARD" > /root/.ssh/id_rsa
echo "HONEYPOT_SSH_ED25519_KEY_CLAWGUARD" > /root/.ssh/id_ed25519
echo "[default]
aws_access_key_id=AKIAIOSFODNN7HONEYPOT
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT" > /root/.aws/credentials
echo '{"type":"HONEYPOT_GCP_SERVICE_ACCOUNT"}' > /root/.config/gcloud/credentials.json
echo "API_KEY=HONEYPOT_KEY_12345
SECRET_TOKEN=HONEYPOT_SECRET_67890" > /root/.env
chmod 600 /root/.ssh/* /root/.aws/credentials

# Start file monitoring on honeypot locations
(
  inotifywait -m /root/.ssh /root/.aws /root/.config/gcloud /root --format '%T %w%f %e' --timefmt '%s' 2>/dev/null | while read line; do
    echo "$line" >> $FILE_LOG
    # Check if honeypot was accessed
    if echo "$line" | grep -qE "(id_rsa|id_ed25519|credentials|.env)"; then
      echo "$line" >> $HONEYPOT_LOG
    fi
  done
) &
INOTIFY_PID=$!

# Start network monitoring (capture DNS and HTTP)
timeout 30 tcpdump -i any -l -n 2>/dev/null > $NETWORK_LOG &
TCPDUMP_PID=$!

# Give monitors time to start
sleep 1

# Run the skill test with strace
cd /skill

# Copy skill to writable location and run scripts
cp -r /skill /tmp/skill-copy
cd /tmp/skill-copy

# Find and run any shell scripts (use bash directly, no chmod needed)
if [ -f "scripts/backup.sh" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 bash scripts/backup.sh 2>&1 || true
elif [ -f "scripts/setup.sh" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 bash scripts/setup.sh 2>&1 || true
elif [ -f "scripts/init.sh" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 bash scripts/init.sh 2>&1 || true
elif [ -f "scripts/install.sh" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 bash scripts/install.sh 2>&1 || true
elif ls scripts/*.sh 1>/dev/null 2>&1; then
    for script in scripts/*.sh; do
        strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 bash "$script" 2>&1 || true
    done
elif [ -f "package.json" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 npm install --ignore-scripts 2>&1 || true
elif [ -f "requirements.txt" ]; then
    strace -f -e trace=open,openat,read,connect,execve -o $STRACE_LOG timeout 30 pip3 install -r requirements.txt 2>&1 || true
fi

# Wait a bit for any delayed actions
sleep 2

# Cleanup
kill $INOTIFY_PID 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true

# Output results
echo "=== STRACE ===" 
cat $STRACE_LOG 2>/dev/null || echo ""
echo "=== NETWORK ==="
cat $NETWORK_LOG 2>/dev/null || echo ""
echo "=== FILES ==="
cat $FILE_LOG 2>/dev/null || echo ""
echo "=== HONEYPOT ==="
cat $HONEYPOT_LOG 2>/dev/null || echo ""
echo "=== DONE ==="
`;

  // Create temp build context
  const buildDir = join(tmpdir(), `clawguard-build-${randomUUID()}`);
  await mkdir(buildDir, { recursive: true });
  await writeFile(join(buildDir, 'Dockerfile'), dockerfile);
  await writeFile(join(buildDir, 'monitor.sh'), monitorScript);

  // Build image
  try {
    execSync(`docker build -t ${imageName} ${buildDir}`, { 
      stdio: 'pipe',
      timeout: 120000 // 2 min timeout
    });
  } finally {
    await rm(buildDir, { recursive: true, force: true });
  }

  return imageName;
}

/**
 * Run a skill in the sandbox
 */
async function runInSandbox(skillPath: string, timeout: number = 60000): Promise<SandboxResult> {
  const imageName = await ensureSandboxImage();
  const containerId = `clawguard-${randomUUID().slice(0, 8)}`;
  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const args = [
      'run',
      '--rm',
      '--name', containerId,
      '--network', 'bridge', // Allow network but can monitor
      '--memory', '512m',
      '--cpus', '1',
      '-v', `${skillPath}:/skill:ro`,
      imageName
    ];

    let stdout = '';
    let stderr = '';

    const proc = spawn('docker', args, {
      timeout,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });

    proc.on('error', reject);
    proc.on('close', (code) => {
      const duration = Date.now() - startTime;
      
      // Parse the output
      const result = parseMonitorOutput(stdout, stderr, code || 0, duration);
      resolve(result);
    });

    // Kill container if timeout
    setTimeout(() => {
      try {
        execSync(`docker kill ${containerId}`, { stdio: 'pipe' });
      } catch {
        // Container might have already exited
      }
    }, timeout);
  });
}

/**
 * Parse strace and other monitor output
 */
function parseMonitorOutput(
  stdout: string, 
  stderr: string, 
  exitCode: number, 
  duration: number
): SandboxResult {
  const fileAccess: FileAccessEvent[] = [];
  const networkActivity: NetworkEvent[] = [];
  const processExecution: ProcessEvent[] = [];
  const honeypotHits: HoneypotHit[] = [];

  // Honeypot paths to detect
  const honeypotPaths = [
    'id_rsa', 'id_ed25519', '.ssh', 
    'credentials', '.aws', 
    'gcloud', '.env', '.netrc', '.npmrc'
  ];

  // Split output by sections
  const straceSection = extractSection(stdout, '=== STRACE ===', '=== NETWORK ===');
  const networkSection = extractSection(stdout, '=== NETWORK ===', '=== FILES ===');
  const filesSection = extractSection(stdout, '=== FILES ===', '=== HONEYPOT ===');
  const honeypotSection = extractSection(stdout, '=== HONEYPOT ===', '=== DONE ===');

  // Parse strace output - this is the most reliable
  const straceLines = straceSection.split('\n');
  for (const line of straceLines) {
    // openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3
    const openMatch = line.match(/open(?:at)?\([^,]*,\s*"([^"]+)"/);
    if (openMatch) {
      const path = openMatch[1];
      fileAccess.push({ path, operation: 'open', timestamp: Date.now() });
      
      // Check if this is a honeypot file access
      if (honeypotPaths.some(hp => path.includes(hp))) {
        honeypotHits.push({ path, operation: 'open', timestamp: Date.now() });
      }
    }

    // read(3, "HONEYPOT_SSH...", 4096) - detect actual read of honeypot content
    if (line.includes('HONEYPOT') && line.includes('read(')) {
      const pathFromContext = fileAccess[fileAccess.length - 1]?.path || 'unknown';
      honeypotHits.push({ path: pathFromContext, operation: 'read', timestamp: Date.now() });
    }

    // execve("/bin/bash", ["bash", "script.sh"], ...)
    const execMatch = line.match(/execve\("([^"]+)",\s*\[([^\]]+)\]/);
    if (execMatch) {
      const command = execMatch[1];
      const argsStr = execMatch[2];
      const args = argsStr.match(/"([^"]+)"/g)?.map(s => s.replace(/"/g, '')) || [];
      processExecution.push({ command, args, timestamp: Date.now() });
    }

    // connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16)
    const connectMatch = line.match(/connect\([^,]+,.*sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\)/);
    if (connectMatch) {
      networkActivity.push({
        destination: connectMatch[2],
        port: parseInt(connectMatch[1]),
        protocol: 'tcp',
        timestamp: Date.now()
      });
    }
  }

  // Parse honeypot section (from inotifywait)
  const honeypotLines = honeypotSection.split('\n');
  for (const line of honeypotLines) {
    if (line.trim()) {
      const parts = line.trim().split(' ');
      if (parts.length >= 2) {
        honeypotHits.push({ 
          path: parts[1] || line, 
          operation: 'access', 
          timestamp: Date.now() 
        });
      }
    }
  }

  // Parse tcpdump output for DNS and HTTP
  const networkLines = networkSection.split('\n');
  for (const line of networkLines) {
    // DNS query
    const dnsMatch = line.match(/A\? ([^\s]+)/);
    if (dnsMatch) {
      networkActivity.push({
        destination: dnsMatch[1],
        port: 53,
        protocol: 'dns',
        timestamp: Date.now()
      });
    }

    // HTTP/HTTPS connection - look for IP addresses
    const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.(\d+)/g);
    if (ipMatch) {
      for (const match of ipMatch) {
        const parts = match.split('.');
        const port = parseInt(parts.pop() || '0');
        const ip = parts.join('.');
        if (port === 80 || port === 443 || port > 1024) {
          networkActivity.push({
            destination: ip,
            port,
            protocol: port === 443 ? 'https' : 'http',
            timestamp: Date.now()
          });
        }
      }
    }
  }

  // Parse inotify output for additional file access
  const fileLines = filesSection.split('\n');
  for (const line of fileLines) {
    const parts = line.trim().split(' ');
    if (parts.length >= 3) {
      const path = parts[1];
      const operation = parts[2]?.toLowerCase().includes('read') ? 'read' : 
                       parts[2]?.toLowerCase().includes('write') ? 'write' : 'stat';
      fileAccess.push({ path, operation: operation as 'read' | 'write' | 'stat', timestamp: Date.now() });
    }
  }

  // Deduplicate honeypot hits
  const uniqueHoneypotHits = honeypotHits.filter((hit, idx, arr) => 
    arr.findIndex(h => h.path === hit.path) === idx
  );

  return {
    exitCode,
    stdout,
    stderr,
    fileAccess,
    networkActivity,
    processExecution,
    honeypotHits: uniqueHoneypotHits,
    duration
  };
}

function extractSection(text: string, start: string, end: string): string {
  const startIdx = text.indexOf(start);
  const endIdx = text.indexOf(end);
  if (startIdx === -1) return '';
  if (endIdx === -1) return text.slice(startIdx + start.length);
  return text.slice(startIdx + start.length, endIdx);
}

/**
 * Analyze sandbox results for security findings
 */
function analyzeResults(result: SandboxResult, skillPath: string): Finding[] {
  const findings: Finding[] = [];

  // Critical: Honeypot hits (definitive credential theft)
  if (result.honeypotHits.length > 0) {
    findings.push({
      id: 'T-SANDBOX-HONEYPOT',
      category: 'honeypot',
      severity: 'critical',
      title: '🚨 Credential Theft Detected (Honeypot Hit)',
      description: `Skill accessed honeypot credential files during execution. This is definitive evidence of credential theft behavior.`,
      location: skillPath,
      evidence: result.honeypotHits.map(h => `${h.operation}: ${h.path}`).join('\n'),
      remediation: 'DO NOT INSTALL. This skill attempts to steal credentials.'
    });
  }

  // Critical: Sensitive file access
  const sensitiveAccess = result.fileAccess.filter(f => 
    SENSITIVE_PATHS.some(p => p.test(f.path))
  );
  if (sensitiveAccess.length > 0 && result.honeypotHits.length === 0) {
    findings.push({
      id: 'T-SANDBOX-SENSITIVE-FILES',
      category: 'honeypot',
      severity: 'high',
      title: 'Sensitive File Access Detected',
      description: `Skill accessed sensitive system files during execution.`,
      location: skillPath,
      evidence: [...new Set(sensitiveAccess.map(f => f.path))].join('\n'),
      remediation: 'Review why this skill needs access to sensitive files.'
    });
  }

  // High: Suspicious network activity
  const suspiciousNetwork = result.networkActivity.filter(n =>
    SUSPICIOUS_DOMAINS.some(d => d.test(n.destination))
  );
  if (suspiciousNetwork.length > 0) {
    findings.push({
      id: 'T-SANDBOX-SUSPICIOUS-NETWORK',
      category: 'honeypot',
      severity: 'critical',
      title: 'Suspicious Network Destination',
      description: `Skill contacted known suspicious/exfiltration domains.`,
      location: skillPath,
      evidence: suspiciousNetwork.map(n => `${n.protocol}://${n.destination}:${n.port}`).join('\n'),
      remediation: 'DO NOT INSTALL. Network activity suggests data exfiltration.'
    });
  }

  // Medium: Any external network activity
  if (result.networkActivity.length > 0 && suspiciousNetwork.length === 0) {
    findings.push({
      id: 'T-SANDBOX-NETWORK',
      category: 'honeypot',
      severity: 'medium',
      title: 'External Network Activity',
      description: `Skill made external network connections during execution.`,
      location: skillPath,
      evidence: result.networkActivity.slice(0, 10).map(n => 
        `${n.protocol}://${n.destination}:${n.port}`
      ).join('\n'),
      remediation: 'Verify these network destinations are expected for this skill.'
    });
  }

  // High: Suspicious command execution
  const dangerousCommands = result.processExecution.filter(p =>
    /curl|wget|nc|netcat|bash.*-c|sh.*-c|python.*-c|eval|base64/i.test(p.command + ' ' + p.args.join(' '))
  );
  if (dangerousCommands.length > 0) {
    findings.push({
      id: 'T-SANDBOX-DANGEROUS-EXEC',
      category: 'honeypot',
      severity: 'high',
      title: 'Dangerous Command Execution',
      description: `Skill executed potentially dangerous commands.`,
      location: skillPath,
      evidence: dangerousCommands.map(p => `${p.command} ${p.args.join(' ')}`).join('\n'),
      remediation: 'Review these commands carefully before installing.'
    });
  }

  return findings;
}

/**
 * Create a sandbox analyzer instance
 */
export function createSandboxAnalyzer(): SandboxAnalyzer {
  return {
    async analyze(skillPath: string): Promise<Finding[]> {
      // Check Docker availability
      if (!await isDockerAvailable()) {
        console.warn('⚠️  Sandbox analysis requires Docker. Skipping.');
        return [{
          id: 'T-SANDBOX-UNAVAILABLE',
          category: 'meta',
          severity: 'info',
          title: 'Sandbox Analysis Skipped',
          description: 'Docker is not available. Install Docker to enable behavioral sandbox analysis.',
          location: skillPath,
          remediation: 'Install Docker: https://docs.docker.com/get-docker/'
        }];
      }

      try {
        console.log('🔒 Starting sandbox analysis...');
        console.log('   Building isolated environment...');
        
        const result = await runInSandbox(skillPath, 60000);
        
        console.log(`   Execution completed in ${result.duration}ms`);
        console.log(`   File accesses: ${result.fileAccess.length}`);
        console.log(`   Network events: ${result.networkActivity.length}`);
        console.log(`   Honeypot hits: ${result.honeypotHits.length}`);
        
        return analyzeResults(result, skillPath);
      } catch (error) {
        console.error('Sandbox analysis error:', error);
        return [{
          id: 'T-SANDBOX-ERROR',
          category: 'meta',
          severity: 'info',
          title: 'Sandbox Analysis Failed',
          description: `Error during sandbox execution: ${(error as Error).message}`,
          location: skillPath,
          remediation: 'Check Docker configuration and try again.'
        }];
      }
    }
  };
}

export { HONEYPOT_FILES, SandboxResult, runInSandbox, isDockerAvailable };
export default createSandboxAnalyzer;
