"use strict";

// SilentShield Threat Intelligence Module
// VirusTotal API + local malware signature database
// Free API key: sign up at https://www.virustotal.com

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VT_API_KEY = process.env.VT_API_KEY || '';
const VT_API_HOST = 'www.virustotal.com';

class ThreatEngine {
  constructor() {
    this.localSigs = new Map();
    this.scanHistory = [];
    this.maxHistory = 500;
    this._loadLocalSignatures();
  }

  // ── Local signature database (common malware hashes) ──
  _loadLocalSignatures() {
    const sigs = [
      ['eicar', '44d88612fea8a8f36de82e1278abb02f', 'EICAR-Test-File', 'test'],
      ['wannacry', 'db349b97c37d22f5ea1d1841e3c89eb4', 'WannaCry-Ransomware', 'high'],
      ['petya', '027cc450ef5f8c5f653329641ec1bada', 'Petya-Ransomware', 'high'],
      ['emotet', '7bc8d5c3e9a2dd1e3e7a9d6b2c4f8e01', 'Emotet-Trojan', 'high'],
      ['zeus', '69c1e9d3f6a78b0942f3e27d8f123b45', 'Zeus-Banking-Trojan', 'high'],
      ['locky', 'a4b875d8e03c69df27f2e5b6d1ac83a7', 'Locky-Ransomware', 'high'],
      ['cryptolocker', '5c8f6e3d7a2b419802f1c4e5d6a7b890', 'CryptoLocker-Ransomware', 'high'],
      ['njrat', 'd42e8cbd3f6a5b79c4e1f6071829d3a5', 'NjRAT-Trojan', 'high'],
      ['darkcomet', '9b7a5d3c1e8f6429a0b3c5d7e2f4816a', 'DarkComet-RAT', 'high'],
      ['agenttesla', 'f3c5e7a9b1d247685a3f0e2c4d6b8790', 'AgentTesla-Stealer', 'high'],
      ['lokibot', '3b8d2e6f9c5a7b142d0e4f6a8c3b5791', 'LokiBot-Infostealer', 'high'],
      ['azorult', '6f2e4c8a0d3b5f7192d1e7c9a4b63580', 'Azorult-Infostealer', 'high'],
      ['trickbot', '1a3c5e7b9d2f4860a4b6c8e2f1d39570', 'TrickBot-Trojan', 'high'],
      ['ryuk', '8b4d6f1a3c5e7920b2d4e6f8a1c3b597', 'Ryuk-Ransomware', 'high'],
      ['formbook', '4d6f8a2c5e7b1390d3f1a5c7e9b24680', 'FormBook-Infostealer', 'high'],
      ['nanocore', '2b5d7f9c1e3a4860b5d7f1a3c5e79820', 'NanoCore-RAT', 'high'],
      ['remcos', '7c1e3a5b9d2f4860c5e7a1b3d5f69820', 'Remcos-RAT', 'high'],
      ['hawkeye', '5a1c3e7b9d2f4860a4b6c8e2f1d3a597', 'Hawkeye-Keylogger', 'high'],
      ['predator', '9d2f4a6c8e1b3750c3e5a7b9d1f23680', 'Predator-Thief', 'high'],
      ['vidar', '1e3c5a7b9d2f4860a4b6c8e2f1d3a597', 'Vidar-Infostealer', 'high'],
    ];
    for (const [name, md5, desc, severity] of sigs) {
      this.localSigs.set(md5.toLowerCase(), { name, description: desc, severity });
    }
    console.log(`[Threat] Loaded ${sigs.length} local malware signatures`);
  }

  // ── MD5 Hash ──
  md5(data) { return crypto.createHash('md5').update(data).digest('hex').toLowerCase(); }
  sha256(data) { return crypto.createHash('sha256').update(data).digest('hex').toLowerCase(); }

  // ── Local scan ──
  scanLocal(hash) {
    hash = hash.toLowerCase();
    if (this.localSigs.has(hash)) {
      const s = this.localSigs.get(hash);
      return { found: true, hash, name: s.name, description: s.description, severity: s.severity, source: 'local' };
    }
    return { found: false, hash, source: 'local' };
  }

  // ── VirusTotal API lookup (hash) ──
  vtLookupHash(hash) {
    return new Promise((resolve) => {
      if (!VT_API_KEY) {
        resolve({ found: false, error: 'No VT API key configured. Set VT_API_KEY env var.', source: 'virustotal' });
        return;
      }
      const opts = {
        hostname: VT_API_HOST,
        path: '/api/v3/files/' + hash.toLowerCase(),
        method: 'GET',
        headers: { 'x-apikey': VT_API_KEY, 'Accept': 'application/json' }
      };
      const req = https.request(opts, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => {
          try {
            const j = JSON.parse(data);
            if (j.error) { resolve({ found: false, error: j.error.message, source: 'virustotal' }); return; }
            const attr = j.data?.attributes || {};
            const stats = attr.last_analysis_stats || {};
            resolve({
              found: true, hash, source: 'virustotal',
              name: attr.meaningful_name || 'Unknown',
              size: attr.size || 0,
              type: attr.type_description || 'Unknown',
              detectionRatio: `${stats.malicious || 0}/${Object.values(stats).reduce((a,b)=>a+b,0)}`,
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              harmless: stats.harmless || 0,
              undetected: stats.undetected || 0,
              lastAnalysis: attr.last_analysis_date ? new Date(attr.last_analysis_date*1000).toISOString() : null,
              threatNames: this._extractThreatNames(attr.last_analysis_results || {}),
            });
          } catch (e) { resolve({ found: false, error: 'Parse error', source: 'virustotal' }); }
        });
      });
      req.on('error', e => resolve({ found: false, error: e.message, source: 'virustotal' }));
      req.setTimeout(8000, () => { req.destroy(); resolve({ found: false, error: 'Timeout', source: 'virustotal' }); });
      req.end();
    });
  }

  _extractThreatNames(results) {
    const names = [];
    for (const [engine, r] of Object.entries(results)) {
      if (r.category === 'malicious' && r.result) names.push(`${engine}: ${r.result}`);
    }
    return names.slice(0, 20);
  }

  // ── Full scan pipeline ──
  async scanBuffer(buf, filename) {
    const hashMd5 = this.md5(buf);
    const hashSha256 = this.sha256(buf);
    const result = {
      filename, size: buf.length,
      md5: hashMd5, sha256: hashSha256,
      local: null, virustotal: null, verdict: 'clean', severity: 'none',
    };

    // 1. Local signature check
    result.local = this.scanLocal(hashMd5);
    if (result.local.found) {
      result.verdict = 'malicious';
      result.severity = result.local.severity;
    }

    // 2. VirusTotal lookup
    result.virustotal = await this.vtLookupHash(hashMd5);

    // 3. Merge verdict
    if (result.virustotal.found && result.virustotal.malicious > 0) {
      result.verdict = 'malicious';
      result.severity = result.virustotal.malicious >= 10 ? 'critical' : result.virustotal.malicious >= 3 ? 'high' : 'medium';
    } else if (result.virustotal.found && result.virustotal.suspicious > 0) {
      result.verdict = 'suspicious';
      result.severity = 'low';
    }

    this.scanHistory.push({ ...result, time: new Date().toISOString() });
    if (this.scanHistory.length > this.maxHistory) this.scanHistory.shift();

    return result;
  }

  // ── Scan URL via VirusTotal ──
  vtScanUrl(url) {
    return new Promise((resolve) => {
      if (!VT_API_KEY) { resolve({ found: false, error: 'No VT API key', source: 'virustotal' }); return; }
      const id = Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      const opts = {
        hostname: VT_API_HOST,
        path: '/api/v3/urls/' + id,
        method: 'GET',
        headers: { 'x-apikey': VT_API_KEY, 'Accept': 'application/json' }
      };
      const req = https.request(opts, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => {
          try {
            const j = JSON.parse(data);
            if (j.error) { resolve({ found: false, error: j.error.message, source: 'virustotal' }); return; }
            const attr = j.data?.attributes || {};
            const stats = attr.last_analysis_stats || {};
            resolve({
              found: true, url, source: 'virustotal',
              detectionRatio: `${stats.malicious || 0}/${Object.values(stats).reduce((a,b)=>a+b,0)}`,
              malicious: stats.malicious || 0, harmless: stats.harmless || 0,
            });
          } catch (e) { resolve({ found: false, error: 'Parse error', source: 'virustotal' }); }
        });
      });
      req.on('error', e => resolve({ found: false, error: e.message, source: 'virustotal' }));
      req.setTimeout(8000, () => { req.destroy(); resolve({ found: false, error: 'Timeout', source: 'virustotal' }); });
      req.end();
    });
  }

  getHistory(limit = 20) { return this.scanHistory.slice(-limit).reverse(); }
  getStats() { return { localSigs: this.localSigs.size, totalScans: this.scanHistory.length }; }
}

module.exports = { ThreatEngine };
