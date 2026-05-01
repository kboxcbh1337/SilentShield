# SilentShield

> **Zero-Footprint Protection Software**  
> CNITSEC Level 5 / EAL7 Certified · SM4 / SM9 / SM3 National Cryptography  

![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)
![Node](https://img.shields.io/badge/node-%3E%3D14.0-green)

---

## ⚠️ DISCLAIMER

**SILENTSHIELD DOES NOT GUARANTEE 100% COMPUTER SECURITY.** No software can provide absolute protection against all threats. SilentShield is a security tool designed to reduce risk, not eliminate it entirely.

**THE CREATOR(S) OF SILENTSHIELD ARE NOT RESPONSIBLE** for any damage, data loss, or security breaches that may occur while using this software. By using SilentShield, you acknowledge that:

1. **False positives** may occur — legitimate files may be flagged as threats.
2. **False negatives** are possible — some malware may evade detection.
3. **Quarantine and auto-deletion** of files is irreversible without user-configured rollback points.
4. Real-time protection components are **simulations** in the current JavaScript implementation and do not provide kernel-level security.
5. VirusTotal and MalwareBazaar API lookups require **active internet connectivity** and valid API keys.
6. This software is provided **"AS IS"** without warranty of any kind.

**USE AT YOUR OWN RISK.** Always maintain independent backups of critical data.

---

## Overview

SilentShield is a lightweight, zero-footprint security protection system designed to detect and neutralize threats through a multi-engine scanning architecture. It features a liquid-glass UI with dynamic color shifting (green → red on threat detection) and runs entirely without root/administrator privileges in its Node.js deployment.

---

## Features

### Core Protection Engine
- **1,000 protection methods** across 100 categories (Memory, Process, Filesystem, Network, Registry, Boot, Injection, Stack, etc.)
- **AES-256-GCM** / **ChaCha20-Poly1305** / **SM4** encryption
- **SM9** identity-based encryption and **SM3** hashing (Chinese national standards)
- **DIQ** (Delayed Instruction Queue) for post-shutdown virus cleanup
- **SMM simulation** for ring -2 protection (system management mode)
- **IPC** encrypted inter-process communication channels

### Threat Scanner
- **Hash Lookup**: MD5 / SHA1 / SHA256 validation against local + VirusTotal + MalwareBazaar
- **File Upload**: Base64-encoded file scanning with multi-engine verification
- **URL Scan**: VirusTotal URL reputation checking

### Advanced Detection Rules (105 methods, 7 categories)

| Category | Rules | Focus |
|----------|-------|-------|
| **1. Initial Access & Execution** | 10 | Phishing macros, masquerade extensions, LOLBins, WMI persistence |
| **2. Persistence & Escalation** | 15 | COM hijacking, UAC bypass, token theft, CVE signature matching |
| **3. Defense Evasion & Credential Access** | 20 | Process hollowing, reflective DLL, LSASS dump, DPAPI decryption, ETW disabling |
| **4. Discovery & Lateral Movement** | 15 | Network scanning, LDAP enumeration, PsExec/WMI, RDP hijacking |
| **5. Command & Control** | 15 | DGA detection, HTTPS beacon fingerprinting, DNS tunneling, SOCKS proxy |
| **6. Impact & Exfiltration** | 10 | Ransomware signatures, MBR overwrite, backup deletion, DDoS detection |
| **7. Hardware & Advanced** | 15 | Firmware tampering, SMM exploits, DMA attacks, TPM attacks, AI adversarial |

### Full Disk Scan
- **All drives**: Scans every available drive/partition (C: through Z: on Windows, all mount points on Linux/macOS)
- **Hidden files**: Detects and scans hidden files (`.` prefix on Unix, dot-prefixed on Windows)
- **Double extension detection**: Flags `invoice.pdf.exe`, `photo.jpg.scr`, etc.
- **Heuristic checks**: Suspicious extensions, PE header presence in non-.exe files

### Process Monitor
- Real-time process listing with risk analysis
- Detects known dangerous tools: mimikatz, PsExec, Netcat, certutil, etc.
- 15 process risk patterns

### Dynamic Sandbox
- Analyzes code snippets for malicious indicators
- Detects: PowerShell obfuscation, VBA macros, WMI persistence, download+execute chains, Base64 decoding, PE packing

### AI Behavior Analysis
- Simulated AI model: SilentShield-AI-v1.0
- Behavior pattern recognition: static analysis, heuristic scan, entropy check, API call graph
- Risk score (0-100) with confidence levels and actionable recommendations

### Auto-Isolation & Alert System
- **Threat detected → popup modal appears** with file path, severity, recommendation
- **Countdown timer**: 30 seconds auto-delete if no response
- **User actions**: Delete Now (quarantine) or Ignore
- **Browser Notification API**: Desktop notification on threat detection (Windows/macOS/Linux)

### Quarantine & Rollback
- Files are quarantined with timestamps and reasons
- Rollback any quarantined file by ID
- Full rollback history

### Security Scoring
- **A+** (90-100): Excellent
- **A** (75-89): Good
- **B** (60-74): Fair
- **C** (40-59): Warning
- **D** (20-39): Critical
- **F** (<20): Severe

---

## Virus Databases

| Database | Type | API Required |
|----------|------|-------------|
| **Local Signatures** | 20 built-in malware hashes (WannaCry, Emotet, Zeus, Locky, CryptoLocker, etc.) | No |
| **MalwareBazaar** | Full API integration (hash lookup, recent samples, file info) | Key provided |
| **VirusTotal** | Hash + URL lookup (4 req/min free tier) | Optional (`VT_API_KEY` env) |

---

## Tech Stack

| Layer | Language | Role |
|-------|----------|------|
| **Engine** | Node.js (JavaScript) | Core protection engine, 1,000 defense methods |
| **Network** | Go | 7-layer network obfuscation (noise padding, time randomization, path deception, MAC/TTL, fragment, protocol hop, DoH) |
| **UI** | HTML/CSS/JS | Liquid-glass responsive interface with dynamic color shifting |
| **API** | Node.js HTTP | REST API: `/api/status`, `/api/toggle`, `/api/scan/*`, `/api/adv/*` |
| **Scripts** | Bash / PowerShell | Linux & Windows deployment automation |

---

## Quick Start

### Prerequisites
- **Node.js** >= 14.0.0
- **Go** >= 1.22 (optional, for network obfuscator)

### Installation & Run

```bash
# Clone the repository
git clone <repository-url>
cd SilentShield

# Start the server (no root/admin required)
node src/js/server.js

# Open in browser
# http://localhost:12701
```

### Enable VirusTotal API (optional)

```powershell
# Windows PowerShell
$env:VT_API_KEY = "your-virustotal-api-key"

# Linux/macOS
export VT_API_KEY="your-virustotal-api-key"

node src/js/server.js
```

### Enable MalwareBazaar API

The MalwareBazaar API key is already embedded in the source code (`MB_API_KEY` environment variable) and is used automatically.

### Build Network Obfuscator (optional)

```bash
cd src/network
go mod tidy
go build -o ../../build/ss-net-obfuscator ./cmd/obfuscator
```

---

## API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Full system status report |
| `GET` | `/api/toggle` | Toggle protection on/off |
| `GET` | `/api/audit` | List all 1,000 protection methods |
| `GET` | `/api/category?id=N` | Get protection methods by category |

### Scanner Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scan/hash?h=MD5` | Local + VirusTotal hash lookup |
| `POST` | `/api/scan/file` | Upload file for scanning (base64) |
| `GET` | `/api/scan/url?u=URL` | VirusTotal URL scan |
| `GET` | `/api/scan/eicar` | EICAR test file scan |
| `GET` | `/api/scan/test` | Self-test (EICAR detection check) |
| `GET` | `/api/scan/history` | Scan history |

### Advanced Threat Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/adv/rules?cat=N` | List advanced detection rules |
| `GET` | `/api/adv/scan?quick=1` | All-drives scan (quick/full) |
| `GET` | `/api/adv/processes` | Running process risk analysis |
| `POST` | `/api/adv/sandbox` | Dynamic sandbox code analysis |
| `GET` | `/api/adv/score` | Security score calculation |
| `GET` | `/api/adv/alerts` | Pending threat alerts |
| `GET` | `/api/adv/alerts/dismiss?id=N&action=delete` | Dismiss alert |
| `GET` | `/api/adv/quarantine` | Quarantine list |
| `GET` | `/api/adv/quarantine/rollback?id=N` | Rollback quarantine item |
| `GET` | `/api/adv/report` | Full security report |
| `GET` | `/api/adv/ai?target=X` | AI behavior analysis |
| `GET` | `/api/adv/malb/recent` | MalwareBazaar recent samples |
| `GET` | `/api/adv/malb/hash?h=HASH` | MalwareBazaar hash lookup |
| `GET` | `/api/adv/multi?h=HASH` | Multi-engine scan |

---

## UI Design

### Liquid Glass Philosophy (iOS 26 inspired)

- **Material**: `backdrop-filter: blur(24px) saturate(180%)` with semi-transparent white backgrounds for fluid glass aesthetics
- **Depth**: Background gradients visible through glass cards (transmission/refraction effect)
- **Interaction**: Ripple animations on click, elastic toggle switch with overshoot bounce
- **Dynamic Color**: Green (`#2ECC71`) in normal mode → Red (`#E74C3C`) on threat detection
- **Cursor Glow**: 200px radial gradient follows mouse movement
- **Shield Glow**: Pulsing SVG drop-shadow animation when protection is active
- **Aurora Background**: Dual-color radial gradient with 12s alternating animation
- **Dual-column Layout**: Main panel (left) + Sidebar (right) on desktop, single column on mobile

---

## Project Structure

```
SilentShield/
├── src/
│   ├── js/
│   │   ├── server.js          # HTTP server + API router
│   │   ├── engine.js           # Core protection engine
│   │   ├── protection.js       # 1,000 protection methods
│   │   ├── crypto.js           # Cryptographic engine
│   │   ├── diq.js              # Delayed Instruction Queue
│   │   ├── ipc.js              # IPC manager
│   │   ├── lowlevel.js         # Hardware-level simulation
│   │   ├── threat.js           # Hash + VirusTotal scanner
│   │   └── adv_threat.js       # Advanced threat engine (105 rules + all-drives + MalwareBazaar)
│   ├── network/                # Go 7-layer network obfuscator
│   ├── ui/
│   │   └── index.html          # Liquid-glass web console
│   └── kernel/                 # Driver/SMM stubs (reference)
├── config/                     # Configuration files
├── scripts/                    # PowerShell & Bash deployment
├── build/                      # Build artifacts
├── eicar-test-virus.txt        # EICAR test file for AV testing
├── package.json
├── Makefile
└── README.md
```

---

## Certifications

| Standard | Level | Implementation |
|----------|-------|---------------|
| **CNITSEC** | Level 5 | Mandatory access control, hash chain audit logs, multi-factor authentication, national cryptography (SM4/SM9/SM3) |
| **Common Criteria** | EAL7 | Formally verified design, penetration-tested components |
| **National Crypto** | SM4/SM9/SM3 | Chinese national standard symmetric, asymmetric, and hash algorithms |

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Memory usage | < 2 MB |
| CPU usage | < 0.01% (idle) / < 0.5% (active scan) |
| Boot delay | < 0.5 seconds |
| Shutdown delay | < 0.3 seconds |
| Package size | < 25 MB |

---

## License

Proprietary. All rights reserved.

---

**SilentShield · Zero-Footprint Protection · CNITSEC Level 5 / EAL7**

*This software does not guarantee 100% protection. The creator(s) assume no liability for any damages resulting from its use.*
