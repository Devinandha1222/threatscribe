# ThreatScribe AI - Setup Guide

## Quick Start

### 1. Install Dependencies

```bash
cd threatscribe

# Clean install (if you encounter module errors)
rm -rf node_modules
npm install

# This will install both backend and frontend dependencies via workspaces
```

### 2. Verify Installation

```bash
# Check that node_modules exists
ls node_modules

# Verify backend dependencies
cd backend
ls node_modules

# Verify frontend dependencies  
cd ../frontend
ls node_modules
```

### 3. Start Backend Server

```bash
# From threatscribe root directory
npm run dev:backend

# Or directly from backend directory
cd backend
node server.js
```

Expected output:
```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║              🛡️  ThreatScribe AI Backend 🛡️                ║
║                                                            ║
║  Intelligent CVE Triage + IBM Bob QA Engine               ║
║  Powered by IBM watsonx.ai                                 ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

🚀 Server running on http://localhost:3001
📊 Demo Mode: ENABLED
🤖 IBM Bob Strict Mode: ENABLED
```

### 4. Test Backend API

```bash
# Health check
curl http://localhost:3001/health

# Expected response:
{
  "status": "healthy",
  "service": "ThreatScribe AI Backend",
  "version": "1.0.0",
  "demo_mode": true,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 5. Start Frontend (When Ready)

```bash
# From threatscribe root directory
npm run dev:frontend

# Or directly from frontend directory
cd frontend
npm run dev
```

Frontend will be available at: `http://localhost:5173`

---

## Troubleshooting

### Issue: "Cannot find module" errors

**Solution:**
```bash
# Clean reinstall
cd threatscribe
rm -rf node_modules
rm -rf backend/node_modules
rm -rf frontend/node_modules
npm install
```

### Issue: Port 3001 already in use

**Solution:**
```bash
# Find and kill the process
# Windows:
netstat -ano | findstr :3001
taskkill /PID <PID> /F

# Linux/Mac:
lsof -ti:3001 | xargs kill -9
```

### Issue: DEMO_MODE not working

**Solution:**
```bash
# Verify .env file exists
cd backend
cat .env

# Should contain:
DEMO_MODE=true
```

---

## Testing

### Run Unit Tests

```bash
cd backend
npm test
```

### Run with Coverage

```bash
cd backend
npm run test:coverage
```

Expected coverage:
- `obfuscationDetector.js`: 100%
- Global: 80%+

---

## Demo Workflow

### Test the L0g4j Obfuscation Detection

```bash
# 1. Start backend
npm run dev:backend

# 2. In another terminal, test the API
curl -X POST http://localhost:3001/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "raw_text": "Critical vulnerability in Apache L0g4j library",
    "source": "nvd"
  }'

# 3. Note the ingest_id from response

# 4. Run triage
curl -X POST http://localhost:3001/api/triage \
  -H "Content-Type: application/json" \
  -d '{
    "ingest_id": "<your-ingest-id>"
  }'

# 5. Run IBM Bob QA
curl -X POST http://localhost:3001/api/qa \
  -H "Content-Type: application/json" \
  -d '{
    "triage_output": <triage-response>,
    "raw_text": "Critical vulnerability in Apache L0g4j library"
  }'

# IBM Bob will detect the obfuscation!
```

---

## Environment Variables

### Backend (.env)

```bash
# Server
PORT=3001

# Demo Mode (no API keys needed)
DEMO_MODE=true

# IBM watsonx.ai (only if DEMO_MODE=false)
WATSONX_API_KEY=your_api_key
WATSONX_PROJECT_ID=your_project_id
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL=ibm/granite-13b-instruct-v2

# IBM Bob
IBM_BOB_STRICT_MODE=true
```

---

## Project Structure

```
threatscribe/
├── package.json           # Root workspace config
├── backend/
│   ├── package.json       # Backend dependencies
│   ├── server.js          # Express server
│   ├── .env               # Environment config
│   └── ...
├── frontend/
│   ├── package.json       # Frontend dependencies
│   └── ...
└── node_modules/          # Shared dependencies
```

---

## Next Steps

1. ✅ Install dependencies
2. ✅ Start backend server
3. ✅ Test API endpoints
4. ⏳ Complete frontend components
5. ⏳ Run end-to-end demo
6. ⏳ Deploy (optional)

---

## Support

If you encounter issues:

1. Check this setup guide
2. Review error messages carefully
3. Verify Node.js version (18+)
4. Check that all files are in correct locations
5. Try clean reinstall

---

**Ready to detect threats!** 🔍