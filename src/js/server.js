"use strict";

const http = require('http');
const fs = require('fs');
const path = require('path');
const { ProtectionEngine } = require('./engine');
const { ThreatEngine } = require('./threat');
const { AdvancedThreatEngine } = require('./adv_threat');

const PORT = 12701;
const SILICONFLOW_MODEL = 'deepseek-ai/DeepSeek-V4-Flash';
const engine = new ProtectionEngine();
const threat = new ThreatEngine();
const advThreat = new AdvancedThreatEngine();

function getUIPath() {
  // When packaged with pkg, __dirname starts with /snapshot/
  if (__dirname.startsWith('/snapshot/')) {
    return path.join(__dirname, '..', 'ui');
  }
  // When running from source
  return path.join(__dirname, '..', '..', 'src', 'ui');
}

function serveStatic(res, filePath, contentType) {
  try {
    const content = fs.readFileSync(path.join(getUIPath(), filePath), 'utf8');
    res.writeHead(200, { 'Content-Type': contentType + '; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(content);
  } catch (e) {
    res.writeHead(404);
    res.end('Not Found');
  }
}

function apiJSON(res, data, code = 200) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve) => {
    if (req.method !== 'POST' && req.method !== 'PUT') { resolve(null); return; }
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch (e) { resolve(null); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    // ── Static ──
    if (url.pathname === '/' || url.pathname === '/index.html') {
      serveStatic(res, 'index.html', 'text/html');
    }
    // ── Engine API ──
    else if (url.pathname === '/api/status') {
      apiJSON(res, engine.getAuditReport());
    }
    else if (url.pathname === '/api/toggle') {
      const result = await engine.toggle();
      apiJSON(res, result);
    }
    else if (url.pathname === '/api/activate') {
      apiJSON(res, await engine.start());
    }
    else if (url.pathname === '/api/deactivate') {
      apiJSON(res, engine.stop());
    }
    else if (url.pathname === '/api/audit') {
      const protections = [];
      for (const [, m] of engine.protection.methods) {
        protections.push({ id: m.id, category: m.category, number: m.number, name: m.name, active: m.active });
      }
      apiJSON(res, { total: protections.length, protections });
    }
    else if (url.pathname === '/api/category') {
      const cat = parseInt(url.searchParams.get('id') || '1');
      apiJSON(res, { category: cat, methods: engine.protection.getCategory(cat) });
    }
    // ── Threat Scanner API ──
    else if (url.pathname === '/api/scan/file' && req.method === 'POST') {
      const body = await parseBody(req);
      if (!body || !body.data) { apiJSON(res, { error: 'Missing data field (base64)' }, 400); return; }
      const buf = Buffer.from(body.data, 'base64');
      const result = await threat.scanBuffer(buf, body.filename || 'uploaded');
      apiJSON(res, result);
    }
    else if (url.pathname === '/api/scan/hash') {
      const hash = url.searchParams.get('h') || '';
      if (!hash) { apiJSON(res, { error: 'Missing hash parameter' }, 400); return; }
      const local = threat.scanLocal(hash);
      const vt = await threat.vtLookupHash(hash);
      apiJSON(res, { local, virustotal: vt });
    }
    else if (url.pathname === '/api/scan/url') {
      const target = url.searchParams.get('u') || '';
      if (!target) { apiJSON(res, { error: 'Missing url parameter' }, 400); return; }
      apiJSON(res, await threat.vtScanUrl(target));
    }
    else if (url.pathname === '/api/scan/eicar') {
      const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const buf = Buffer.from(eicar, 'utf8');
      const result = await threat.scanBuffer(buf, 'eicar-test.txt');
      apiJSON(res, { ...result, note: 'EICAR test file - harmless test signature' });
    }
    else if (url.pathname === '/api/scan/history') {
      apiJSON(res, { history: threat.getHistory(), stats: threat.getStats() });
    }
    else if (url.pathname === '/api/scan/test') {
      const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const buf = Buffer.from(eicar, 'utf8');
      const md5 = threat.md5(buf);
      const local = threat.scanLocal(md5);
      apiJSON(res, { selfTest: local.found, eicarMd5: md5, localSigs: threat.getStats().localSigs, apiKeyConfigured: !!process.env.VT_API_KEY, message: local.found ? 'Threat engine operational.' : 'Needs initialization.' });
    }
    // ── Advanced Threat API ──
    else if (url.pathname === '/api/adv/rules') {
      const cat = parseInt(url.searchParams.get('cat') || '0');
      const rules = [];
      for (const [, r] of advThreat.rules) { if (cat === 0 || r.category === cat) rules.push(r); }
      apiJSON(res, { total: advThreat.rules.size, rules });
    }
    else if (url.pathname === '/api/adv/scan') {
      const quick = url.searchParams.get('quick') === '1';
      const result = advThreat.scanAllDrives(quick);
      // Auto-isolate + create alerts for each threat found
      if (result.threats > 0) {
        for (const t of result.threats_found) {
          advThreat.createAlert(t.path, t.threat, t.severity, t.recommendation || 'Delete this file');
        }
      }
      apiJSON(res, result);
    }
    else if (url.pathname === '/api/adv/alerts') {
      apiJSON(res, { alerts: advThreat.getPendingAlerts(), count: advThreat.getPendingAlerts().length });
    }
    else if (url.pathname === '/api/adv/alerts/dismiss') {
      const id = parseInt(url.searchParams.get('id') || '0');
      const action = url.searchParams.get('action') || 'delete';
      const result = advThreat.dismissAlert(id, action);
      apiJSON(res, result || { error: 'Alert not found' });
    }
    else if (url.pathname === '/api/adv/malb/recent') {
      const r = await advThreat.malbRecent(50);
      apiJSON(res, r);
    }
    else if (url.pathname === '/api/adv/malb/hash') {
      const hash = url.searchParams.get('h') || '';
      if (!hash) { apiJSON(res, { error: 'Missing hash' }, 400); return; }
      const r = await advThreat.malbLookupHash(hash);
      apiJSON(res, r);
    }
    else if (url.pathname === '/api/adv/multi') {
      const hash = url.searchParams.get('h') || '';
      if (!hash) { apiJSON(res, { error: 'Missing hash' }, 400); return; }
      const r = await advThreat.multiEngineScan('unknown', hash);
      apiJSON(res, r);
    }
    else if (url.pathname === '/api/adv/processes') {
      const procs = advThreat.getRunningProcesses();
      const risky = procs.map(p => ({ ...p, ...advThreat.analyzeProcessRisk(p.name) }));
      apiJSON(res, { total: procs.length, processes: risky });
    }
    else if (url.pathname === '/api/adv/sandbox') {
      if (req.method !== 'POST') { apiJSON(res, { error: 'POST required' }, 400); return; }
      const body = await parseBody(req);
      const result = advThreat.sandboxAnalyze(body?.filename || 'unknown', body?.data || '');
      apiJSON(res, result);
    }
    else if (url.pathname === '/api/adv/score') {
      const s = engine.getAuditReport();
      const score = advThreat.calculateSecurityScore({
        threatsDetected: advThreat.detections.length,
        suspiciousProcesses: advThreat.getRunningProcesses().filter(p => advThreat.analyzeProcessRisk(p.name).risk === 'high' || advThreat.analyzeProcessRisk(p.name).risk === 'critical').length,
        unpatchedVulnerabilities: 0,
        firewallEnabled: true,
        realTimeProtection: s.engine.active,
        outdatedOS: false,
        quarantinedItems: advThreat.quarantine.length
      });
      apiJSON(res, score);
    }
    else if (url.pathname === '/api/adv/quarantine') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const q = advThreat.quarantineFile(body?.path || 'unknown', body?.reason || 'Threat detected');
        apiJSON(res, q);
      } else {
        apiJSON(res, { items: advThreat.getQuarantineList(), rollbacks: advThreat.getRollbackHistory() });
      }
    }
    else if (url.pathname === '/api/adv/quarantine/rollback') {
      const id = parseInt(url.searchParams.get('id') || '0');
      const result = advThreat.rollbackQuarantine(id);
      apiJSON(res, result ? { success: true, item: result } : { success: false, error: 'Not found' });
    }
    else if (url.pathname === '/api/adv/report') {
      apiJSON(res, advThreat.generateSecurityReport());
    }
    else if (url.pathname === '/api/adv/db-status') {
      apiJSON(res, { databases: advThreat.getDbStatus() });
    }
    else if (url.pathname === '/api/adv/ai') {
      const body = req.method === 'POST' ? await parseBody(req) : null;
      const target = body?.filePath || body?.filename || url.searchParams.get('target') || '';
      const content = body?.content || body?.data || '';
      
      // If content provided, use real AI analysis
      if (content || target) {
        const aiResult = await advThreat.aiAnalyze(target || 'unknown', content || 'N/A', {
          processList: advThreat.getRunningProcesses()
        });
        apiJSON(res, aiResult);
      } else {
        // Default AI status
        apiJSON(res, {
          model: SILICONFLOW_MODEL,
          status: 'ready',
          provider: 'SiliconFlow (DeepSeek-V4-Flash)',
          capabilities: ['Static analysis', 'Heuristic scan', 'Behavior prediction', 'MITRE ATT&CK mapping', 'Malware classification']
        });
      }
    }
    else if (url.pathname === '/api/adv/ai/sandbox') {
      if (req.method !== 'POST') { apiJSON(res, { error: 'POST required' }, 400); return; }
      const body = await parseBody(req);
      const sandboxResult = advThreat.sandboxAnalyze(body?.filename || 'unknown', body?.content || body?.data || '');
      const aiEnhanced = await advThreat.aiSandboxAnalyze(
        body?.filename || 'unknown',
        body?.content || body?.data || '',
        sandboxResult
      );
      apiJSON(res, aiEnhanced);
    }
    else if (url.pathname === '/api/adv/comprehensive-scan') {
      if (req.method !== 'POST') { apiJSON(res, { error: 'POST required' }, 400); return; }
      const body = await parseBody(req);
      const filePath = body?.filePath || body?.filename || 'uploaded-file';
      const content = body?.content || body?.data || '';
      const buffer = content ? Buffer.from(content, 'utf8') : null;
      const result = advThreat.comprehensiveFileScan(filePath, content, buffer);
      apiJSON(res, result);
    }
    else if (url.pathname === '/api/adv/log') {
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const logs = engine.getAuditReport();
      apiJSON(res, { ...logs, advancedRules: advThreat.rules.size, quarantine: advThreat.quarantine.length, detections: advThreat.detections.length });
    }
    else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Not Found' }));
    }
  } catch (e) {
    console.error('[Server] Route error:', e);
    apiJSON(res, { error: e.message }, 500);
  }
});

async function main() {
  await engine.init();
  server.listen(PORT, '127.0.0.1', () => {
    console.log('\n╔══════════════════════════════════════════╗');
    console.log('║  SilentShield Web Console Ready          ║');
    console.log('║  URL: http://localhost:' + PORT + '           ║');
    console.log('║  API: http://localhost:' + PORT + '/api/status ║');
    console.log('║  Threat Scanner: /api/scan/*             ║');
    console.log('║  Local sigs: ' + threat.getStats().localSigs + ' (VirusTotal API optional)     ║');
    console.log('║  Open browser to control SilentShield    ║');
    console.log('╚══════════════════════════════════════════╝\n');
    console.log('[Server] Press Ctrl+C to stop\n');

    // Auto-open native window with Edge/Chrome app mode
     const uiPath = getUIPath();
     const indexPath = path.join(uiPath, 'index.html');
     const fileUrl = 'file:///' + indexPath.replace(/\\/g, '/');
    const edgePaths = [
      process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\Application\\msedge.exe',
      'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    ];
    let edgePath = null;
    for (const p of edgePaths) {
      try { require('fs').accessSync(p, require('fs').constants.X_OK); edgePath = p; break; } catch(e) {}
    }
    if (edgePath) {
      try {
        require('child_process').spawn(edgePath, ['--app=' + fileUrl, '--no-first-run', '--window-size=1200,850'], {
          detached: true, stdio: 'ignore'
        }).unref();
        console.log('[UI] Opened in Edge app mode');
      } catch(e) {
        console.log('[UI] Could not open Edge:', e.message);
        console.log('[UI] Please open ' + fileUrl + ' manually');
      }
    } else {
      // Fallback: try opening in default browser
      try { require('child_process').exec('start ' + fileUrl); } catch(e) {}
    }
  });
}

main().catch(err => { console.error('[Server] Fatal:', err); process.exit(1); });
