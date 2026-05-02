# Load Demo Data into ThreatScribe
Write-Host "=== Loading ThreatScribe Demo Data ===" -ForegroundColor Cyan
Write-Host ""

# Check if backend is running
try {
    $health = Invoke-RestMethod -Uri "http://localhost:3001/health" -ErrorAction Stop
    Write-Host "✓ Backend is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Backend is not running. Please start it first." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Load mock CVE data
$mockData = Get-Content "threatscribe/backend/data/mockCVEs.json" | ConvertFrom-Json

Write-Host "Loading $($mockData.cves.Count) CVE records..." -ForegroundColor Yellow
Write-Host ""

$loaded = 0
foreach ($cve in $mockData.cves) {
    try {
        # Ingest the CVE
        $ingestBody = @{
            raw_text = $cve.raw_text
            source = $cve.source
        } | ConvertTo-Json
        
        $ingestResult = Invoke-RestMethod -Uri "http://localhost:3001/api/ingest" -Method Post -Body $ingestBody -ContentType "application/json"
        
        # Triage the CVE
        $triageBody = @{
            ingest_id = $ingestResult.ingest_id
            raw_text = $cve.raw_text
        } | ConvertTo-Json
        
        $triageResult = Invoke-RestMethod -Uri "http://localhost:3001/api/triage" -Method Post -Body $triageBody -ContentType "application/json"
        
        $loaded++
        Write-Host "✓ Loaded $($cve.cve_id) - $($triageResult.severity)" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to load $($cve.cve_id): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Demo Data Loaded ===" -ForegroundColor Green
Write-Host "Successfully loaded: $loaded / $($mockData.cves.Count) CVEs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Cyan
Write-Host "Backend:  http://localhost:3001" -ForegroundColor Cyan
Write-Host ""
Write-Host "Refresh your browser to see the data!" -ForegroundColor Yellow

# Made with Bob