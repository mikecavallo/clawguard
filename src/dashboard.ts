/**
 * ClawGuard Dashboard
 * 
 * Web-based fleet visibility:
 * - Scan results overview
 * - Alert timeline
 * - Skill inventory
 * - Risk heat map
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { getMonitor } from './monitor.js';

const DEFAULT_PORT = 18790;

interface ScanRecord {
  skillPath: string;
  skillName: string;
  scannedAt: string;
  riskLevel: string;
  riskScore: number;
  findings: { critical: number; high: number; medium: number; low: number };
}

// Simple HTML template
const DASHBOARD_HTML = `
<!DOCTYPE html>
<html>
<head>
  <title>ClawGuard Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1a1a2e; color: #eee; padding: 20px;
    }
    .header { 
      display: flex; align-items: center; gap: 20px; 
      margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #333;
    }
    .logo { color: #e63946; font-size: 28px; font-weight: bold; }
    .stats { display: flex; gap: 20px; }
    .stat { 
      background: #252540; padding: 15px 25px; border-radius: 8px;
      text-align: center;
    }
    .stat-value { font-size: 32px; font-weight: bold; }
    .stat-label { color: #888; font-size: 12px; text-transform: uppercase; }
    .stat.critical .stat-value { color: #e63946; }
    .stat.warning .stat-value { color: #f4a261; }
    .stat.safe .stat-value { color: #2a9d8f; }
    
    .section { margin-bottom: 30px; }
    .section-title { 
      font-size: 18px; margin-bottom: 15px; 
      display: flex; align-items: center; gap: 10px;
    }
    
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
    
    .card {
      background: #252540; border-radius: 8px; padding: 15px;
      border-left: 4px solid #333;
    }
    .card.critical { border-left-color: #e63946; }
    .card.high { border-left-color: #f4a261; }
    .card.medium { border-left-color: #e9c46a; }
    .card.safe { border-left-color: #2a9d8f; }
    
    .card-title { font-weight: bold; margin-bottom: 8px; }
    .card-meta { color: #888; font-size: 12px; }
    .card-findings { margin-top: 10px; display: flex; gap: 10px; }
    .finding-badge { 
      padding: 2px 8px; border-radius: 4px; font-size: 12px;
    }
    .finding-badge.critical { background: #e63946; }
    .finding-badge.high { background: #f4a261; color: #000; }
    .finding-badge.medium { background: #e9c46a; color: #000; }
    
    .alert-list { }
    .alert-item {
      padding: 12px 15px; background: #252540; margin-bottom: 8px;
      border-radius: 6px; display: flex; gap: 15px; align-items: center;
    }
    .alert-icon { font-size: 20px; }
    .alert-content { flex: 1; }
    .alert-title { font-weight: 500; }
    .alert-time { color: #888; font-size: 12px; }
    
    .refresh-btn {
      background: #e63946; color: white; border: none;
      padding: 8px 16px; border-radius: 4px; cursor: pointer;
    }
    .refresh-btn:hover { background: #d62839; }
    
    .empty { color: #666; font-style: italic; padding: 20px; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️ CLAWGUARD</div>
    <div class="stats" id="stats"></div>
    <button class="refresh-btn" onclick="refresh()">↻ Refresh</button>
  </div>
  
  <div class="section">
    <div class="section-title">📊 Recent Scans</div>
    <div class="grid" id="scans"></div>
  </div>
  
  <div class="section">
    <div class="section-title">🚨 Recent Alerts</div>
    <div class="alert-list" id="alerts"></div>
  </div>
  
  <script>
    async function loadData() {
      const [statsRes, scansRes, alertsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/scans'),
        fetch('/api/alerts')
      ]);
      
      const stats = await statsRes.json();
      const scans = await scansRes.json();
      const alerts = await alertsRes.json();
      
      renderStats(stats);
      renderScans(scans);
      renderAlerts(alerts);
    }
    
    function renderStats(stats) {
      document.getElementById('stats').innerHTML = \`
        <div class="stat critical">
          <div class="stat-value">\${stats.critical || 0}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat warning">
          <div class="stat-value">\${stats.high || 0}</div>
          <div class="stat-label">High Risk</div>
        </div>
        <div class="stat safe">
          <div class="stat-value">\${stats.safe || 0}</div>
          <div class="stat-label">Safe</div>
        </div>
        <div class="stat">
          <div class="stat-value">\${stats.total || 0}</div>
          <div class="stat-label">Total Scans</div>
        </div>
      \`;
    }
    
    function renderScans(scans) {
      if (!scans.length) {
        document.getElementById('scans').innerHTML = '<div class="empty">No scans yet</div>';
        return;
      }
      
      document.getElementById('scans').innerHTML = scans.map(s => \`
        <div class="card \${s.riskLevel.toLowerCase()}">
          <div class="card-title">\${s.skillName}</div>
          <div class="card-meta">\${new Date(s.scannedAt).toLocaleString()}</div>
          <div class="card-meta">Score: \${s.riskScore}/100</div>
          <div class="card-findings">
            \${s.findings.critical ? \`<span class="finding-badge critical">\${s.findings.critical} critical</span>\` : ''}
            \${s.findings.high ? \`<span class="finding-badge high">\${s.findings.high} high</span>\` : ''}
            \${s.findings.medium ? \`<span class="finding-badge medium">\${s.findings.medium} medium</span>\` : ''}
            \${!s.findings.critical && !s.findings.high && !s.findings.medium ? '<span style="color:#2a9d8f">✓ Clean</span>' : ''}
          </div>
        </div>
      \`).join('');
    }
    
    function renderAlerts(alerts) {
      if (!alerts.length) {
        document.getElementById('alerts').innerHTML = '<div class="empty">No alerts</div>';
        return;
      }
      
      const icons = { critical: '🚨', warning: '⚠️', info: 'ℹ️' };
      
      document.getElementById('alerts').innerHTML = alerts.slice(0, 20).map(a => \`
        <div class="alert-item">
          <div class="alert-icon">\${icons[a.severity] || 'ℹ️'}</div>
          <div class="alert-content">
            <div class="alert-title">[\${a.skillName}] \${a.message}</div>
            <div class="alert-time">\${new Date(a.timestamp).toLocaleString()}</div>
          </div>
        </div>
      \`).join('');
    }
    
    function refresh() { loadData(); }
    loadData();
    setInterval(loadData, 30000);
  </script>
</body>
</html>
`;

// In-memory scan records (would be persisted in production)
const scanRecords: ScanRecord[] = [];

export function recordScan(record: ScanRecord): void {
  scanRecords.unshift(record);
  if (scanRecords.length > 100) {
    scanRecords.pop();
  }
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url || '/';
  
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  try {
    if (url === '/' || url === '/dashboard') {
      res.setHeader('Content-Type', 'text/html');
      res.end(DASHBOARD_HTML);
      return;
    }
    
    if (url === '/api/stats') {
      const stats = {
        total: scanRecords.length,
        critical: scanRecords.filter(s => s.riskLevel === 'CRITICAL').length,
        high: scanRecords.filter(s => s.riskLevel === 'HIGH').length,
        safe: scanRecords.filter(s => s.riskLevel === 'SAFE').length
      };
      res.end(JSON.stringify(stats));
      return;
    }
    
    if (url === '/api/scans') {
      res.end(JSON.stringify(scanRecords.slice(0, 20)));
      return;
    }
    
    if (url === '/api/alerts') {
      const monitor = getMonitor();
      const alerts = await monitor.getAlerts(20);
      res.end(JSON.stringify(alerts));
      return;
    }
    
    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'Not found' }));
    
  } catch (error) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: (error as Error).message }));
  }
}

export async function startDashboard(port = DEFAULT_PORT): Promise<void> {
  const server = createServer(handleRequest);
  
  server.listen(port, () => {
    console.log(`🛡️  ClawGuard Dashboard running at http://localhost:${port}`);
  });
}

export { DASHBOARD_HTML };
