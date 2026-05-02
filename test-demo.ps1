# Simple ThreatScribe Demo
Write-Host "=== ThreatScribe AI Detection Demo ===" -ForegroundColor Cyan
Write-Host ""

# Test health
Write-Host "Testing health endpoint..." -ForegroundColor Yellow
$health = Invoke-RestMethod -Uri "http://localhost:3001/health"
Write-Host "Status: $($health.status)" -ForegroundColor Green
Write-Host ""

# Test 1: L0g4j Detection
Write-Host "TEST 1: L0g4j Obfuscation Detection" -ForegroundColor Cyan
Write-Host "Input: Critical vulnerability in Apache L0g4j..." -ForegroundColor White

$body1 = @{
    raw_text = "Critical vulnerability in Apache L0g4j library version 2.x"
    source = "nvd"
} | ConvertTo-Json

$ingest = Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -Body $body1 -ContentType "application/json"
Write-Host "Ingest ID: $($ingest.ingest_id)" -ForegroundColor Gray
Write-Host "Suspicious chars: $($ingest.suspicious_chars_detected)" -ForegroundColor Yellow
Write-Host ""

# Triage
$triageBody = @{
    ingest_id = $ingest.ingest_id
    raw_text = "Critical vulnerability in Apache L0g4j library version 2.x"
} | ConvertTo-Json

$triage = Invoke-RestMethod -Uri "http://localhost:3001/api/triage" -Method Post -Body $triageBody -ContentType "application/json"
Write-Host "CVE ID: $($triage.cve_id)" -ForegroundColor Gray
Write-Host "CVSS: $($triage.cvss_score)" -ForegroundColor Gray
Write-Host "Severity: $($triage.severity)" -ForegroundColor Yellow
Write-Host ""

# QA with AI Detection
Write-Host "Running IBM Bob QA with AI Detection..." -ForegroundColor Cyan
$qaBody = @{
    triage_output = $triage
    raw_text = "Critical vulnerability in Apache L0g4j library version 2.x"
    ingest_id = $ingest.ingest_id
} | ConvertTo-Json -Depth 10

$qa = Invoke-RestMethod -Uri "http://localhost:3001/api/qa" -Method Post -Body $qaBody -ContentType "application/json"
Write-Host "QA Status: $($qa.qa_status)" -ForegroundColor Green
Write-Host "Tests Passed: $($qa.passed)" -ForegroundColor Green
Write-Host "Warnings: $($qa.warnings)" -ForegroundColor Yellow
Write-Host ""

# Show AI Analysis
$checkA = $qa.mandatory_checks.'CHECK-A'
Write-Host "CHECK-A Result: $($checkA.result)" -ForegroundColor Yellow
Write-Host "Detail: $($checkA.detail)" -ForegroundColor Gray

if ($checkA.data.ai_analysis) {
    $ai = $checkA.data.ai_analysis
    Write-Host ""
    Write-Host "AI Analysis:" -ForegroundColor Magenta
    Write-Host "  Threat Level: $($ai.threat_level)" -ForegroundColor White
    Write-Host "  Confidence: $([math]::Round($ai.confidence * 100))%" -ForegroundColor White
    Write-Host "  Obfuscation Detected: $($ai.obfuscation_detected)" -ForegroundColor White
    Write-Host "  Techniques Found: $($ai.obfuscation_techniques.Count)" -ForegroundColor White
    Write-Host "  Threat Indicators: $($ai.threat_indicators.Count)" -ForegroundColor White
    
    if ($ai.obfuscation_techniques.Count -gt 0) {
        Write-Host ""
        Write-Host "  Obfuscation Details:" -ForegroundColor Yellow
        foreach ($tech in $ai.obfuscation_techniques) {
            Write-Host "    - $($tech.description)" -ForegroundColor White
            Write-Host "      Evidence: $($tech.evidence)" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "Detection Method: $($checkA.data.detection_method)" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== Demo Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Backend is running at: http://localhost:3001" -ForegroundColor Cyan
Write-Host "See TESTING_GUIDE.md for more examples" -ForegroundColor Yellow

# Made with Bob
