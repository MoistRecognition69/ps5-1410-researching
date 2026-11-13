# Apply V18 Patch to V17.html
# Creates v18.html with Timer-Free Control dispatch

$ErrorActionPreference = "Stop"

Write-Host "V18 Patch Application" -ForegroundColor Cyan
Write-Host "=====================`n" -ForegroundColor Cyan

$v17Path = Join-Path $PSScriptRoot "v17.html"
$v18Path = Join-Path $PSScriptRoot "v18.html"
$patchPath = Join-Path $PSScriptRoot "v18-patch.js"

if (-not (Test-Path $v17Path)) {
    Write-Host "ERROR: v17.html not found at $v17Path" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $patchPath)) {
    Write-Host "ERROR: v18-patch.js not found at $patchPath" -ForegroundColor Red
    exit 1
}

Write-Host "[READ] Reading v17.html..." -ForegroundColor Green
$v17Content = Get-Content -Path $v17Path -Raw

Write-Host "[READ] Reading v18-patch.js..." -ForegroundColor Green
$patchContent = Get-Content -Path $patchPath -Raw

# Find the V17B dispatch section
$startMarker = "/* ==== V17B: THE DISPATCH (source-informed) ===="
$endMarker = "/* ==== V17B END ==== */"

$startIndex = $v17Content.IndexOf($startMarker)
$endIndex = $v17Content.IndexOf($endMarker)

if ($startIndex -lt 0 -or $endIndex -lt 0) {
    Write-Host "ERROR: Could not find V17B dispatch section markers" -ForegroundColor Red
    Write-Host "  Start marker found: $($startIndex -ge 0)" -ForegroundColor Yellow
    Write-Host "  End marker found: $($endIndex -ge 0)" -ForegroundColor Yellow
    exit 1
}

Write-Host "[FOUND] V17B dispatch section at offset $startIndex to $endIndex" -ForegroundColor Green

# Extract the parts
$beforeDispatch = $v17Content.Substring(0, $startIndex)
$afterDispatch = $v17Content.Substring($endIndex + $endMarker.Length)

# Update the header comment
$beforeDispatch = $beforeDispatch -replace 'V688 — Path B read-only identity \+ addrof-certification probe', 'V18 — Timer-Free Control Dispatch Test (Council-Recommended)'
$beforeDispatch = $beforeDispatch -replace '<title>v688 Path B identity \+ addrof certification</title>', '<title>v18 Timer-Free Control Dispatch</title>'
$beforeDispatch = $beforeDispatch -replace '<pre id="out">v688</pre>', '<pre id="out">v18</pre>'
$beforeDispatch = $beforeDispatch -replace "'/beacon/V17-'", "'/beacon/V18-'"

# Combine
$v18Content = $beforeDispatch + $patchContent + "`n" + $afterDispatch

Write-Host "[WRITE] Writing v18.html..." -ForegroundColor Green
$v18Content | Out-File -FilePath $v18Path -Encoding UTF8 -NoNewline

$v18Size = (Get-Item $v18Path).Length / 1KB
Write-Host "`n[SUCCESS] Created v18.html ($([math]::Round($v18Size, 2)) KB)" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Update index.html to point to v18.html" -ForegroundColor Gray
Write-Host "  2. Close/reopen the PS5 guide app" -ForegroundColor Gray
Write-Host "  3. Test Phase 1: v18.html?phase=1 (m_table=nullptr)" -ForegroundColor Gray
Write-Host "  4. Test Phase 2: v18.html?phase=2 (all-empty)" -ForegroundColor Gray
Write-Host "  5. Test Phase 3: v18.html?phase=3 (weak-null)" -ForegroundColor Gray
Write-Host "  6. Test Phase 4: v18.html?phase=4 (live-client)" -ForegroundColor Gray
