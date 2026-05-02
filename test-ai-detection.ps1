# ThreatScribe AI Detection Demo Script
# This script demonstrates the AI-powered threat detection system

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║         🛡️  ThreatScribe AI Detection Demo 🛡️              ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if server is running
Write-Host "🔍 Checking if backend server is running..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "http://localhost:3001/health" -Method Get -ErrorAction Stop
    Write-Host "✅ Backend server is healthy!" -ForegroundColor Green
    Write-Host "   Service: $($health.service)" -ForegroundColor Gray
    Write-Host "   Demo Mode: $($health.demo_mode)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "❌ Backend server is not running!" -ForegroundColor Red
    Write-Host "   Please start it with: cd threatscribe/backend; node server.js" -ForegroundColor Yellow
    exit 1
}

# Test 1: L0g4j Obfuscation Detection
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "TEST 1: L0g4j Obfuscation Detection (Classic)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$test1 = @{
    raw_text = "Critical vulnerability in Apache L0g4j library version 2.x allows remote code execution"
    source = "nvd"
} | ConvertTo-Json

Write-Host "📝 Input: Critical vulnerability in Apache L0g4j..." -ForegroundColor White
Write-Host ""

try {
    $ingest1 = Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -Body $test1 -ContentType "application/json"
    Write-Host "✅ Ingestion successful!" -ForegroundColor Green
    Write-Host "   Ingest ID: $($ingest1.ingest_id)" -ForegroundColor Gray
    Write-Host "   Suspicious chars detected: $($ingest1.suspicious_chars_detected)" -ForegroundColor Yellow
    Write-Host ""
    
    # Run triage
    Write-Host "🤖 Running watsonx.ai triage..." -ForegroundColor Yellow
    $triage1Body = @{
        ingest_id = $ingest1.ingest_id
        raw_text = "Critical vulnerability in Apache L0g4j library version 2.x allows remote code execution"
    } | ConvertTo-Json
    
    $triage1 = Invoke-RestMethod -Uri "http://localhost:3001/api/triage" -Method Post -Body $triage1Body -ContentType "application/json"
    Write-Host "✅ Triage complete!" -ForegroundColor Green
    Write-Host "   CVE ID: $($triage1.cve_id)" -ForegroundColor Gray
    Write-Host "   CVSS Score: $($triage1.cvss_score)" -ForegroundColor Gray
    Write-Host "   Severity: $($triage1.severity)" -ForegroundColor $(if ($triage1.severity -eq "CRITICAL") { "Red" } else { "Yellow" })
    Write-Host ""
    
    # Run IBM Bob QA with AI detection
    Write-Host "🔬 Running IBM Bob QA with AI-Powered Detection..." -ForegroundColor Yellow
    $qaBody = @{
        triage_output = $triage1
        raw_text = "Critical vulnerability in Apache L0g4j library version 2.x allows remote code execution"
        ingest_id = $ingest1.ingest_id
    } | ConvertTo-Json -Depth 10
    
    $qa1 = Invoke-RestMethod -Uri "http://localhost:3001/api/qa" -Method Post -Body $qaBody -ContentType "application/json"
    Write-Host "✅ QA Analysis complete!" -ForegroundColor Green
    Write-Host "   QA Status: $($qa1.qa_status)" -ForegroundColor $(if ($qa1.qa_status -eq "APPROVED") { "Green" } elseif ($qa1.qa_status -eq "APPROVED_WITH_WARNINGS") { "Yellow" } else { "Red" })
    Write-Host "   Tests Passed: $($qa1.passed)" -ForegroundColor Green
    Write-Host "   Warnings: $($qa1.warnings)" -ForegroundColor Yellow
    Write-Host "   Execution Time: $($qa1.execution_time_ms)ms" -ForegroundColor Gray
    Write-Host ""
    
    # Show CHECK-A results (AI Detection)
    $checkA = $qa1.mandatory_checks.'CHECK-A'
    Write-Host "🤖 CHECK-A: AI-Powered Threat Detection" -ForegroundColor Cyan
    Write-Host "   Result: $($checkA.result)" -ForegroundColor $(if ($checkA.result -eq "PASS") { "Green" } elseif ($checkA.result -eq "WARN") { "Yellow" } else { "Red" })
    Write-Host "   Detail: $($checkA.detail)" -ForegroundColor Gray
    
    if ($checkA.data.ai_analysis) {
        $ai = $checkA.data.ai_analysis
        Write-Host ""
        Write-Host "   🧠 AI Analysis:" -ForegroundColor Magenta
        Write-Host "      Threat Level: $($ai.threat_level)" -ForegroundColor $(if ($ai.threat_level -eq "CRITICAL") { "Red" } elseif ($ai.threat_level -eq "HIGH") { "Yellow" } else { "White" })
        Write-Host "      Confidence: $([math]::Round($ai.confidence * 100, 1))%" -ForegroundColor Gray
        Write-Host "      Obfuscation Detected: $($ai.obfuscation_detected)" -ForegroundColor Yellow
        Write-Host "      Obfuscation Techniques: $($ai.obfuscation_techniques.Count)" -ForegroundColor Yellow
        Write-Host "      Threat Indicators: $($ai.threat_indicators.Count)" -ForegroundColor Yellow
        Write-Host "      Sophistication: $($ai.semantic_analysis.sophistication)" -ForegroundColor Gray
        Write-Host "      Requires Human Review: $($ai.requires_human_review)" -ForegroundColor $(if ($ai.requires_human_review) { "Yellow" } else { "Green" })
        
        if ($ai.obfuscation_techniques.Count -gt 0) {
            Write-Host ""
            Write-Host "   📋 Detected Obfuscation Techniques:" -ForegroundColor Yellow
            foreach ($tech in $ai.obfuscation_techniques) {
                Write-Host "      • $($tech.type): $($tech.description)" -ForegroundColor White
                Write-Host "        Evidence: '$($tech.evidence)' (Confidence: $([math]::Round($tech.confidence * 100, 1))%)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host ""
    Write-Host "   Detection Method: $($checkA.data.detection_method)" -ForegroundColor Cyan
    Write-Host ""
    
} catch {
    Write-Host "❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Test 2: Advanced Obfuscation
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "TEST 2: Advanced Semantic Evasion" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$test2 = @{
    raw_text = "Security issue in F0rt1net firewall allows remote @ccess and c0mm@nd 1nj3ct10n"
    source = "vendor"
} | ConvertTo-Json

Write-Host "📝 Input: Security issue in F0rt1net firewall..." -ForegroundColor White
Write-Host ""

try {
    $ingest2 = Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -Body $test2 -ContentType "application/json"
    Write-Host "✅ Ingestion successful!" -ForegroundColor Green
    Write-Host "   Suspicious chars detected: $($ingest2.suspicious_chars_detected)" -ForegroundColor Yellow
    Write-Host "   Obfuscation preview count: $($ingest2.obfuscation_preview.Count)" -ForegroundColor Yellow
    
    if ($ingest2.obfuscation_preview.Count -gt 0) {
        Write-Host ""
        Write-Host "   🔍 Pre-scan detected:" -ForegroundColor Magenta
        foreach ($obf in $ingest2.obfuscation_preview) {
            Write-Host "      • Position $($obf.position): '$($obf.original)' -> '$($obf.suspected_intent)' ($([math]::Round($obf.confidence * 100, 1))%)" -ForegroundColor Gray
        }
    }
    Write-Host ""
    
} catch {
    Write-Host "❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Summary
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "✅ Demo Complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎯 Key Features Demonstrated:" -ForegroundColor Cyan
Write-Host "   ✅ AI-powered threat detection using IBM watsonx.ai" -ForegroundColor Green
Write-Host "   ✅ Character-level obfuscation detection (L0g4j, F0rt1net)" -ForegroundColor Green
Write-Host "   ✅ Semantic analysis and intent detection" -ForegroundColor Green
Write-Host "   ✅ Multi-layer validation (AI + pattern matching)" -ForegroundColor Green
Write-Host "   ✅ Confidence scoring and human review flagging" -ForegroundColor Green
Write-Host ""
Write-Host "📖 For more tests, see: threatscribe/TESTING_GUIDE.md" -ForegroundColor Yellow
Write-Host ""
Write-Host "🌐 Backend running at: http://localhost:3001" -ForegroundColor Cyan
Write-Host "📊 Health check: http://localhost:3001/health" -ForegroundColor Cyan
Write-Host ""

# Made with Bob
