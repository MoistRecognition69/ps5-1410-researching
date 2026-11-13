# scan-watch-V26.ps1 — V26 returning-dispatch watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V26 Returning-Dispatch Watcher" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_
  if ($line -notmatch '/beacon/V26-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $msg = $p -replace '^/beacon/V26-',''

  if ($msg -match '^MODE=(\w+)') { Write-Host "`n[$t] ====== V26 MODE: $($Matches[1]) ======" -ForegroundColor Cyan; return }
  if ($msg -match '^PROMISE-ADDR=(0x[0-9a-f]+)') { Write-Host "[$t] [PROMISE] real promise at $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^PROMISE-BEFORE=') { Write-Host "[$t] [PROMISE] pre-dispatch snapshot taken" -ForegroundColor DarkYellow; return }
  if ($msg -match '^SIBLING-SCAN') { Write-Host "[$t] [SCAN] sibling search..." -ForegroundColor Yellow; return }
  if ($msg -match '^SIBLING=(0x[0-9a-f]+)-backing=(0x[0-9a-f]+)') { Write-Host "[$t] [OK] sibling $($Matches[1]) backing=$($Matches[2])" -ForegroundColor Green; return }
  if ($msg -match '^NO-SIBLING') { Write-Host "[$t] [FAIL] no sibling" -ForegroundColor Red; return }
  if ($msg -match '^TIMER-BORROWED=') { Write-Host "[$t] [OK] timer borrowed" -ForegroundColor Green; return }
  if ($msg -match '^FORGE-BUILD') { Write-Host "`n[$t] [FORGE] building..." -ForegroundColor Yellow; return }
  if ($msg -match '^CLIENT-PROMISE=(0x[0-9a-f]+)-(IS-REAL-OK|MISMATCH)') {
    if ($Matches[2] -eq 'IS-REAL-OK') { Write-Host "[$t] [OK] client promise = REAL promise (V26 fix active)" -ForegroundColor Green }
    else { Write-Host "[$t] [WARN] client promise $($Matches[1]) is NOT the real promise!" -ForegroundColor Red }
    return
  }
  if ($msg -match '^FORGE-BUILT-T=') { Write-Host "[$t] [OK] forge built" -ForegroundColor Green; return }
  if ($msg -match '^VERIFY-(.+)') { Write-Host "[$t] [VERIFY] $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^FACE-CRAFT') { Write-Host "`n[$t] [FACE] crafting..." -ForegroundColor Yellow; return }
  if ($msg -match '^FACE-VERIFY-status=(\d+)-override=(\d+)') { Write-Host "[$t] [FACE] status=$($Matches[1]) override=$($Matches[2])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^INSTALLED-tblPtr=(0x[0-9a-f]+)') { Write-Host "[$t] [INSTALL] table ptr $($Matches[1])" -ForegroundColor Green; return }
  if ($msg -match '^LOAD-PRE') { Write-Host "`n[$t] >>> CALLING faces[zi].load() <<<" -ForegroundColor Magenta; return }
  if ($msg -match '^LOAD-RETURNED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** load() RETURNED - DISPATCH SURVIVED ***" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    return
  }
  if ($msg -match '^LOAD-THREW-(.+)') { Write-Host "[$t] [FAIL] THREW: $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^POST-returned=(\w+)') { Write-Host "[$t] [POST] returned=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match '^STATUS-AFTER=(\d+)') { Write-Host "[$t] [STATUS] byte=$($Matches[1]) (expect 4=Failure)" -ForegroundColor Cyan; return }
  if ($msg -match '^JS-STATUS=(\w+)') { Write-Host "[$t] [JS] status=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match '^PROMISE-AFTER=') {
    Write-Host "[$t] [PROMISE] post-dispatch read complete" -ForegroundColor DarkYellow
    return
  }
  if ($msg -match 'WIT-V26-PROMISE-CHANGED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** WITNESS: PROMISE CHANGED ***" -ForegroundColor Green
    Write-Host "[$t] fontStateChanged EXECUTED - the virtual" -ForegroundColor Green
    Write-Host "[$t] dispatch through OUR fake vtable is REAL" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    return
  }
  if ($msg -match 'WIT-V26-PROMISE-UNCHANGED') { Write-Host "[$t] [WIT] promise unchanged (reject skipped - promise was fulfilled)" -ForegroundColor Gray; return }
  if ($msg -match 'WIT-V26-FORGE-WRITE-(.+)') { Write-Host "[$t] [WIT] forge buffer writes: $($Matches[1])" -ForegroundColor Green; return }
  if ($msg -match 'WIT-V26-FORGE-nowrite') { Write-Host "[$t] [WIT] forge buffer unchanged" -ForegroundColor Gray; return }
  if ($msg -match '^DONE-(\w+)-(RETURNED|CRASHED)') {
    $r = $Matches[2]
    if ($r -eq 'RETURNED') { Write-Host "`n[$t] [DONE] $($Matches[1]): RETURNED - full chain SURVIVED" -ForegroundColor Green }
    else { Write-Host "`n[$t] [DONE] $($Matches[1]): CRASHED" -ForegroundColor Red }
    return
  }
  if ($msg -match '^RESTORED') { Write-Host "[$t] [INFO] table restored" -ForegroundColor Gray; return }
  if ($msg -match '^ERR-(.+)') { Write-Host "[$t] [ERROR] $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^SKIP-(.+)') { Write-Host "[$t] [SKIP] $($Matches[1])" -ForegroundColor Yellow; return }
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
