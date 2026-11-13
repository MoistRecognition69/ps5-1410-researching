# V18 Phase Test Runner
# Helps you test each phase of the Timer-Free Control dispatch

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(1,2,3,4)]
    [int]$Phase = 1
)

$ErrorActionPreference = "Stop"

Write-Host "V18 Phase Test Runner" -ForegroundColor Cyan
Write-Host "=====================`n" -ForegroundColor Cyan

$indexPath = Join-Path $PSScriptRoot "index.html"

$phaseNames = @{
    1 = "m_table=nullptr (empty set control)"
    2 = "all-empty table {0,0,7,8}"
    3 = "weak-null test {0,1,7,8}"
    4 = "live-client test {0,1,7,8}"
}

$phaseDescriptions = @{
    1 = @"
Phase 1: m_table == nullptr
- Empty set control
- No table allocated
- Expected: load() returns, no clients iterated
- Status should remain Pending (0)
"@
    2 = @"
Phase 2: All-empty table
- Metadata: {deletedCount=0, keyCount=0, mask=7, size=8}
- All 8 buckets = 0 (empty)
- Expected: load() returns, no clients iterated
- Status should remain Pending (0)
"@
    3 = @"
Phase 3: Weak-null test
- Metadata: {deletedCount=0, keyCount=1, mask=7, size=8}
- Bucket 0: WeakPtrImpl with m_ptr=null
- Buckets 1-7: empty
- Expected: bucket 0 removed by cleanup
- Metadata should become {1,0,7,8}
- No client virtual calls
"@
    4 = @"
Phase 4: Live-client test
- Metadata: {deletedCount=0, keyCount=1, mask=7, size=8}
- Bucket 0: WeakPtrImpl with m_ptr=fake client
- Fake client has fake vtable (slot 3 = fontStateChanged gadget)
- Expected: ref() → fontStateChanged → deref()
- Metadata unchanged by cleanup
- WIT-dispatch-WRITE should show client refcount changes
"@
}

Write-Host "Selected Phase: $Phase - $($phaseNames[$Phase])" -ForegroundColor Yellow
Write-Host "`n$($phaseDescriptions[$Phase])" -ForegroundColor Gray

Write-Host "`n[ACTION] Updating index.html..." -ForegroundColor Green

$indexContent = @"
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Cache-Control" content="no-cache,no-store"><meta http-equiv="refresh" content="0;url=v18.html?v=1&rt=16&phase=$Phase"></head><body>dispatch V18 Phase $Phase ($($phaseNames[$Phase]))</body></html>
"@

$indexContent | Out-File -FilePath $indexPath -Encoding ASCII -NoNewline

Write-Host "[SUCCESS] index.html updated to Phase $Phase" -ForegroundColor Green

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Ensure host.py is running (python host.py)" -ForegroundColor Gray
Write-Host "  2. On PS5: Close and reopen Settings → User's Guide" -ForegroundColor Gray
Write-Host "  3. Monitor beacons: .\scan-watch.ps1" -ForegroundColor Gray
Write-Host "  4. Look for V18-LOAD-RETURNED or V18-LOAD-THREW" -ForegroundColor Gray
Write-Host "  5. Check V18-STATUS-AFTER and V18-TABLE-META-AFTER" -ForegroundColor Gray

if ($Phase -lt 4) {
    Write-Host "`nTo test next phase:" -ForegroundColor Yellow
    Write-Host "  .\test-v18-phases.ps1 -Phase $($Phase + 1)" -ForegroundColor Gray
}

Write-Host "`nTo test a different phase:" -ForegroundColor Yellow
Write-Host "  .\test-v18-phases.ps1 -Phase <1|2|3|4>" -ForegroundColor Gray
