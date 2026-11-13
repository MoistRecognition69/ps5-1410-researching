# test-v21-modes.ps1 — V21 mode test runner

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('success','pending')]
    [string]$Mode
)

$ErrorActionPreference = "Stop"

Write-Host "V21 Mode Test Runner" -ForegroundColor Cyan
Write-Host "===================`n" -ForegroundColor Cyan

$modeDescriptions = @{
    'success' = @"
Mode: success (Arm B equivalent)
- Status = Success (3)
- Empty sources
- Original client table
- Expected: load() returns successfully (no transition)
"@
    'pending' = @"
Mode: pending (Arm C equivalent)
- Status = Pending (0)
- Empty sources
- Null client table
- Expected: load() crashes (Pending→Failure transition)
"@
}

Write-Host "Selected Mode: $Mode" -ForegroundColor Yellow
Write-Host "`n$($modeDescriptions[$Mode])" -ForegroundColor Gray

$indexPath = Join-Path $PSScriptRoot "index.html"

Write-Host "`n[ACTION] Updating index.html..." -ForegroundColor Green

$indexContent = @"
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Cache-Control" content="no-cache,no-store"><meta http-equiv="refresh" content="0;url=v21.html?v=1&rt=0&mode=$Mode"></head><body>dispatch V21 Mode $Mode</body></html>
"@

$indexContent | Out-File -FilePath $indexPath -Encoding ASCII -NoNewline

Write-Host "[SUCCESS] index.html updated to Mode $Mode" -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Ensure host.py is running" -ForegroundColor Gray
Write-Host "  2. Ensure auto_continue.py is running" -ForegroundColor Gray
Write-Host "  3. On PS5: Close and reopen Settings → User's Guide" -ForegroundColor Gray
Write-Host "  4. Watch for V21 bisection results" -ForegroundColor Gray

Write-Host "`nTo test other mode:" -ForegroundColor Yellow
Write-Host "  .\test-v21-modes.ps1 -Mode success  # Arm B equivalent" -ForegroundColor Gray
Write-Host "  .\test-v21-modes.ps1 -Mode pending  # Arm C equivalent" -ForegroundColor Gray
