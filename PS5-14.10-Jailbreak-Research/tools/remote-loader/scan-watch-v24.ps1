# scan-watch-v24.ps1 — V24 V55-faithful dispatch watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V24 V55-Faithful Dispatch Watcher" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_
  if ($line -notmatch '/beacon/V24-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $msg = $p -replace '^/beacon/V24-',''

  if ($msg -match '^MODE=(\w+)') {
    $mode = $Matches[1]
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] V24 MODE: $mode" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }
  if ($msg -match '^SIBLING-SCAN') { Write-Host "[$t] [SCAN] looking for sibling face..." -ForegroundColor Yellow; return }
  if ($msg -match '^SIBLING=(0x[0-9a-f]+)-backing=(0x[0-9a-f]+)') { Write-Host "[$t] [OK] sibling found: $($Matches[1]) backing=$($Matches[2])" -ForegroundColor Green; return }
  if ($msg -match '^NO-SIBLING') { Write-Host "[$t] [FAIL] no sibling - abort" -ForegroundColor Red; return }
  if ($msg -match '^TIMER-BORROWED=(\w+)') { Write-Host "[$t] [OK] timer region borrowed ($($Matches[1].Substring(0,16))...)" -ForegroundColor Green; return }
  if ($msg -match '^FORGE-BUILD') { Write-Host "`n[$t] [FORGE] building impl+table+client+vtable+promise..." -ForegroundColor Yellow; return }
  if ($msg -match '^FORGE-BUILT-T=') { Write-Host "[$t] [OK] forge built in marker buffer" -ForegroundColor Green; return }
  if ($msg -match '^VERIFY-(.+)') { Write-Host "[$t] [VERIFY] $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^FACE-CRAFT') { Write-Host "`n[$t] [FACE] crafting face (sources/status/override/timer)..." -ForegroundColor Yellow; return }
  if ($msg -match '^FACE-VERIFY-status=(\d+)-override=(\d+)') { Write-Host "[$t] [FACE] status=$($Matches[1]) override=$($Matches[2]) timer installed" -ForegroundColor DarkYellow; return }
  if ($msg -match '^INSTALLED-tblPtr=(0x[0-9a-f]+)') { Write-Host "[$t] [INSTALL] table ptr = $($Matches[1]) (last write done)" -ForegroundColor Green; return }
  if ($msg -match '^LOAD-PRE') { Write-Host "`n[$t] >>> CALLING faces[zi].load() <<<" -ForegroundColor Magenta; return }
  if ($msg -match '^LOAD-RETURNED') { Write-Host "[$t] [PASS] load() RETURNED" -ForegroundColor Green; return }
  if ($msg -match '^LOAD-THREW-(.+)') { Write-Host "[$t] [FAIL] load() THREW: $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^POST-returned=(\w+)') { Write-Host "[$t] [POST] returned=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match '^STATUS-AFTER=(\d+)') { Write-Host "[$t] [STATUS] byte=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match '^JS-STATUS=(\w+)') { Write-Host "[$t] [JS] status=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match 'WIT-V24-DISPATCH-WRITE-(.+)') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** COOP WRITE WITNESSED ***" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] $($Matches[1])" -ForegroundColor Green
    Write-Host "`n[NEXT] aim the promise at cell+0x10 -> ARW" -ForegroundColor Cyan
    return
  }
  if ($msg -match 'WIT-V24-nowrite') { Write-Host "[$t] [WIT] no engine writes to the forge" -ForegroundColor Gray; return }
  if ($msg -match '^DONE-(\w+)-(RETURNED|CRASHED)') {
    $r = $Matches[2]
    if ($r -eq 'RETURNED') { Write-Host "`n[$t] [DONE] $($Matches[1]): RETURNED (session survived)" -ForegroundColor Green }
    else { Write-Host "`n[$t] [DONE] $($Matches[1]): CRASHED (cleanup exonerated by table math; crash is in dispatch/gadget path)" -ForegroundColor Red }
    return
  }
  if ($msg -match '^RESTORED') { Write-Host "[$t] [INFO] original table restored" -ForegroundColor Gray; return }
  if ($msg -match '^ERR-(.+)') { Write-Host "[$t] [ERROR] $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^SKIP-(.+)') { Write-Host "[$t] [SKIP] $($Matches[1])" -ForegroundColor Yellow; return }
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
