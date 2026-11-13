# test-v20-arms.ps1 — V20 arm test runner

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('A','B','C')]
    [string]$Arm
)

$ErrorActionPreference = "Stop"

$armNames = @{
    'A' = 'Status Oracle (zero-risk)'
    'B' = 'Success Control (no-transition)'
    'C' = 'Timer Intervention (repair from sibling)'
}

$armDescriptions = @{
    'A' = @"
Arm A: Status Oracle
- Write +0x82 = 0, 1, 3, 4 in turn
- Read faces[zi].status via JS binding
- Expected: 0→unloaded, 1→loading, 3→loaded, 4→error
- STOP if any mismatch (layout problem)
"@
    'B' = @"
Arm B: Success Control
- Set status=Success (3), empty sources, preserve client table
- Call faces[zi].load() once
- Expected: no transition, no client iteration, no Timer operation
- Should return successfully with status='loaded'
- STOP if crash (need native capture)
"@
    'C' = @"
Arm C: Timer Intervention
- Reproduce V18C Pending/Block/empty-source/null-client-table craft
- Change ONLY Timer: harvest tVptr and tThread from sibling
- Install non-owning diagnostic Timer state
- Set Pending last, call load() once
- Expected: returns with status='error' if Timer was the cause
"@
}

Write-Host "V20 Arm Test Runner" -ForegroundColor Cyan
Write-Host "==================`n" -ForegroundColor Cyan

Write-Host "Selected Arm: $Arm - $($armNames[$Arm])" -ForegroundColor Yellow
Write-Host "`n$($armDescriptions[$Arm])" -ForegroundColor Gray

$indexPath = Join-Path $PSScriptRoot "index.html"

Write-Host "`n[ACTION] Updating index.html..." -ForegroundColor Green

$indexContent = @"
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Cache-Control" content="no-cache,no-store"><meta http-equiv="refresh" content="0;url=v20.html?v=1&rt=0&arm=$Arm"></head><body>dispatch V20 Arm $Arm ($($armNames[$Arm]))</body></html>
"@

$indexContent | Out-File -FilePath $indexPath -Encoding ASCII -NoNewline

Write-Host "[SUCCESS] index.html updated to Arm $Arm" -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Ensure host.py is running" -ForegroundColor Gray
Write-Host "  2. Ensure auto_continue.py is running" -ForegroundColor Gray
Write-Host "  3. On PS5: Close and reopen Settings → User's Guide" -ForegroundColor Gray
Write-Host "  4. Watch for V20 Arm $Arm results" -ForegroundColor Gray

Write-Host "`nTo test other arms:" -ForegroundColor Yellow
Write-Host "  .\test-v20-arms.ps1 -Arm A  # Status oracle" -ForegroundColor Gray
Write-Host "  .\test-v20-arms.ps1 -Arm B  # Success control" -ForegroundColor Gray
Write-Host "  .\test-v20-arms.ps1 -Arm C  # Timer intervention" -ForegroundColor Gray
