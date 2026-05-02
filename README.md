# ThreatScribe AI

**Intelligent CVE triage and incident response — powered by IBM watsonx.ai and IBM Bob**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)

---

## 🎯 Overview

ThreatScribe AI is a full-stack cybersecurity analyst tool that automates CVE triage and incident response using IBM watsonx.ai for intelligent analysis and IBM Bob for quality assurance. The system can detect sophisticated obfuscation techniques (like `L0g4j` where attackers use `0` instead of `o`) that traditional tools miss.

### Team

- **Takaomi** — Backend Lead (watsonx.ai pipeline, API, data processing)
- **Musfirah** — Frontend Lead (SOC dashboard, UI, visualizations)
- **IBM Bob** — QA Engineer (automated test suite, obfuscation detection, rule validation)

---

## ✨ Key Features

### 1. **Threat Feed Ingestion**
Parse raw CVE text from NVD, vendor advisories, and OSINT feeds with pre-scan obfuscation detection.

### 2. **CVE Triage Autopilot** 
watsonx.ai classifies severity, extracts CVSS scores, maps to MITRE ATT&CK, and detects character-substitution obfuscation.

### 3. **IBM Bob QA Gate** ⭐
Automated quality assurance engine that validates every triage output with 4 mandatory checks:
- **CHECK-A**: Obfuscation detection (O vs 0, l vs 1, $ vs S, etc.)
- **CHECK-B**: CVSS 3.1 recalculation and validation (±0.1 tolerance)
- **CHECK-C**: MITRE ATT&CK consistency validation
- **CHECK-D**: Test coverage completeness (≥3 test cases)

### 4. **Post-Detection Action Chain**
Parallel execution of 4 response lanes:
- **Lane 1**: Auto-containment (WAF rules, network ACLs, segmentation)
- **Lane 2**: Patch orchestration (vendor commands, CI/CD, rollback)
- **Lane 3**: Stakeholder alerting (Slack, email, PagerDuty)
- **Lane 4**: Forensic evidence (logs, memory dumps, chain-of-custody)

### 5. **SOC Analyst Dashboard**
Real-time threat feed, severity heatmap, IBM Bob QA status panel, MITRE ATT&CK coverage chart, and generated report preview.

---

## 🏗️ Architecture

```
threatscribe/
├── backend/                    # Node.js/Express API
│   ├── server.js              # Express entry point
│   ├── routes/                # API endpoints
│   │   ├── ingest.js          # POST /api/ingest
│   │   ├── triage.js          # POST /api/triage
│   │   ├── qa.js              # POST /api/qa (IBM Bob)
│   │   ├── actions.js         # POST /api/actions
│   │   └── report.js          # POST /api/report
│   ├── services/              # Business logic
│   │   ├── obfuscationDetector.js  # IBM Bob core algorithm
│   │   ├── ibmBob.js          # QA engine with 4 checks
│   │   ├── watsonx.js         # IBM watsonx.ai client
│   │   ├── mitre.js           # MITRE ATT&CK service
│   │   └── actionChain.js     # 4-lane orchestrator
│   ├── models/                # Data models
│   │   └── cveRecord.js       # CVE schema + in-memory store
│   ├── data/                  # Mock data
│   │   └── mockCVEs.json      # Demo CVEs (L0g4j, F0rt1net)
│   └── __tests__/             # Unit tests
│       └── obfuscationDetector.test.js  # 100% coverage
├── frontend/                   # React + Vite
│   ├── src/
│   │   ├── App.jsx            # Main application
│   │   ├── components/        # UI components
│   │   ├── hooks/             # Custom React hooks
│   │   └── styles/            # Dark terminal theme
│   └── public/
└── docs/                       # Documentation
```

---

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm 9+
- (Optional) IBM watsonx.ai API credentials for production mode

### Installation

```bash
# Clone the repository
cd threatscribe

# Install all dependencies (backend + frontend)
npm install

# Start backend server (port 3001)
npm run dev:backend

# In a new terminal, start frontend (port 5173)
npm run dev:frontend

# Or start both simultaneously
npm run dev
```

### Environment Configuration

```bash
# backend/.env
PORT=3001
DEMO_MODE=true                    # Set to false for real watsonx.ai API
WATSONX_API_KEY=your_key_here     # Only needed if DEMO_MODE=false
WATSONX_PROJECT_ID=your_project
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL=ibm/granite-13b-instruct-v2
IBM_BOB_STRICT_MODE=true          # FAIL on any QA issue vs warnings
```

---

## 🎬 Demo Walkthrough

### The L0g4j Obfuscation Catch (Showcase Feature)

This demo highlights IBM Bob's ability to detect sophisticated evasion techniques:

1. **Open the dashboard** at `http://localhost:5173`

2. **Navigate to CVE Ingestion** and paste this advisory:
   ```
   Critical vulnerability discovered in Apache L0g4j library version 2.x. 
   Remote code execution possible through JNDI lookup exploitation.
   ```

3. **Click "Run ThreatScribe ↗"** and watch the pipeline:
   - ✅ Ingestion (pre-scan detects suspicious chars)
   - ✅ Triage (watsonx.ai extracts CVE details)
   - ⚠️ **IBM Bob QA** — CHECK-A catches the obfuscation!

4. **IBM Bob QA Panel shows**:
   ```
   CHECK-A: WARN
   Detected obfuscation at position 48: '0' suspected to be 'o' (95% confidence)
   Detected obfuscation at position 50: '4' suspected to be 'a' (85% confidence)
   Pattern: L0g4j → Log4j
   ```

5. **QA Status**: `APPROVED_WITH_WARNINGS`
   - CVE is valid but contains obfuscation
   - Report includes dedicated "Obfuscation Findings" section
   - Jira ticket flagged with obfuscation alert

6. **Action Chain executes** (4 lanes in parallel):
   - Containment rules generated
   - Patch commands ready
   - Stakeholders alerted
   - Forensic collection initiated

7. **Report Preview** shows the incident report with typewriter effect, including:
   ```markdown
   ## Obfuscation Findings
   
   ⚠️ Character-level obfuscation detected by IBM Bob QA engine:
   - Position 48 in "raw_text": Character '0' suspected to be 'o' 
     (obfuscation, confidence: 95.0%)
   - Position 50 in "raw_text": Character '4' suspected to be 'a' 
     (obfuscation, confidence: 85.0%)
   
   This obfuscation pattern suggests potential evasion techniques.
   ```

---

## 🧪 Testing

### Run Unit Tests

```bash
cd backend
npm test
```

### Run with Coverage

```bash
npm run test:coverage
```

**Coverage Requirements:**
- `obfuscationDetector.js`: 100% (branches, functions, lines, statements)
- Global: 80% minimum

### Test Cases

The obfuscation detector includes comprehensive tests:
- ✅ `"L0g4j"` → Detects `0` and `4` obfuscation
- ✅ `"l0gin"` → Detects `0` and `l` substitution
- ✅ `"CVES-2024"` → No false positives
- ✅ `"F0rt1net"` → Detects both `0` and `1`
- ✅ `"normal text"` → Returns empty array

---

## 📡 API Reference

### POST /api/ingest
Ingest raw CVE text for triage.

**Request:**
```json
{
  "raw_text": "CVE advisory text...",
  "source": "nvd | vendor | osint"
}
```

**Response:**
```json
{
  "ingest_id": "uuid",
  "status": "queued",
  "suspicious_chars_detected": true,
  "obfuscation_preview": [...]
}
```

### POST /api/triage
Run watsonx.ai CVE triage.

**Request:**
```json
{
  "ingest_id": "uuid",
  "raw_text": "CVE text..."
}
```

**Response:** Full triage JSON with CVSS, MITRE mapping, typo flags, test cases.

### POST /api/qa
Run IBM Bob QA checks (the QA gate).

**Request:**
```json
{
  "triage_output": {...},
  "raw_text": "original text"
}
```

**Response:**
```json
{
  "qa_status": "APPROVED | REJECTED | APPROVED_WITH_WARNINGS",
  "mandatory_checks": {
    "CHECK-A": { "result": "PASS|FAIL|WARN", "detail": "..." },
    "CHECK-B": { "result": "PASS|FAIL|WARN", "detail": "..." },
    "CHECK-C": { "result": "PASS|FAIL|WARN", "detail": "..." },
    "CHECK-D": { "result": "PASS|FAIL|WARN", "detail": "..." }
  },
  "bob_recommendation": "Escalate to SOC | Hold for review | Reject",
  "execution_time_ms": 1200
}
```

**QA Gate Rule:** If `qa_status === "REJECTED"`, `/api/actions` and `/api/report` return 409 Conflict.

### POST /api/actions
Execute 4-lane action chain (requires QA approval).

**Request:**
```json
{
  "triage_output": {...},
  "qa_report": {...}
}
```

**Response:** Action results from all 4 lanes + Sigma rule + test bundle.

### POST /api/report
Generate incident report, runbook, and Jira ticket.

**Request:**
```json
{
  "triage_output": {...},
  "qa_report": {...}
}
```

**Response:**
```json
{
  "incident_report": "markdown string",
  "runbook": "markdown string",
  "jira_ticket": { "summary": "...", "priority": "...", ... }
}
```

---

## 🔬 IBM Bob QA Engine

### Obfuscation Detection Algorithm

IBM Bob uses a sophisticated character-level analysis:

1. **Sliding window** (size 1-3 characters)
2. **Visual similarity scoring** using Unicode distance + weight table
3. **Context analysis** (surrounding characters, known patterns)
4. **Confidence thresholds**:
   - ≥0.7 = obfuscation (intentional evasion)
   - 0.5-0.69 = OCR error (possible mistake)

**Substitution Pairs:**
```javascript
'0' ↔ ['O', 'o']  // Zero vs Letter O
'1' ↔ ['l', 'I', 'i']  // One vs lowercase L/uppercase I
'$' ↔ ['S', 's']  // Dollar vs Letter S
'@' ↔ ['a', 'A']  // At sign vs Letter A
'3' ↔ ['E', 'e']  // Three vs Letter E
'4' ↔ ['A', 'a']  // Four vs Letter A
// ... and more
```

### CVSS 3.1 Recalculation

IBM Bob recalculates CVSS scores using the official formula:

```
ISS = 1 - (1-C)(1-I)(1-A)
Impact = 6.42 * ISS  (if Scope Unchanged)
Impact = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15  (if Changed)
Exploitability = 8.22 * AV * AC * PR * UI
Base Score = roundUp(min(Impact + Exploitability, 10))
```

Tolerance: ±0.1 (FAIL if difference exceeds)

---

## 🎨 Frontend Components

### Dark Terminal Theme

- Background: `#0a0f1e` (near-black)
- Accent: `#4af0c4` (green)
- Font: `JetBrains Mono` (monospace)
- No gradients, no blur — pure terminal aesthetic

### Key Components

- **Sidebar**: Navigation + IBM Bob live status
- **MetricCards**: Critical/High/Accuracy/Time metrics
- **ThreatFeed**: CVE table with severity badges + QA status
- **BobQAPanel**: Live test execution with CHECK-A through CHECK-D
- **ReportPreview**: Typewriter effect for incident reports
- **MitreHeatmap**: ATT&CK tactic coverage bar chart
- **ActionChainPanel**: 4-lane status display
- **IngestForm**: Demo input for raw CVE text

---

## 📊 Performance Requirements

- ✅ API responses < 3 seconds (demo mode)
- ✅ IBM Bob tests < 1 second
- ✅ Obfuscation detector: 100% test coverage
- ✅ CVSS recalculation: ±0.1 accuracy
- ✅ L0g4j demo: 100% reliability

---

## 🛡️ Security & Compliance

### Chain of Custody

All forensic artifacts include:
- Timestamp
- Actor (automated/manual)
- Hash (SHA-256)
- Retention period

### Compliance Frameworks

- **SOC 2**: 90-day minimum retention
- **ISO 27001**: Certification period + 3 years
- **NIST CSF**: Per organizational policy

---

## 🤝 Contributing

This is a hackathon project. For production use:

1. Replace mock watsonx.ai responses with real API calls
2. Implement persistent database (SQLite → PostgreSQL)
3. Add authentication and authorization
4. Expand MITRE ATT&CK technique database
5. Add more obfuscation patterns to IBM Bob

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- **IBM watsonx.ai** for intelligent CVE analysis
- **IBM Bob** for tireless QA validation
- **MITRE ATT&CK** framework for threat mapping
- **NVD** for CVE data standards

---

## 📞 Support

For questions or issues:
- Backend: Contact Takaomi
- Frontend: Contact Musfirah
- QA/Testing: Consult IBM Bob logs

---

**Built with ❤️ for SOC analysts everywhere**

*ThreatScribe AI — Because every CVE deserves a second pair of eyes (and IBM Bob has four)*