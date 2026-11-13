# scan-watch-v20.ps1 — V20 three-arm timer investigation watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V20 Three-Arm Timer Investigation Watcher" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  if ($line -notmatch '/beacon/V20-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V20-',''

  # ==== ARM selection ====
  if ($msg -match '^ARM=([ABC])') {
    $arm = $Matches[1]
    $armName = switch ($arm) {
      'A' { 'Status Oracle (zero-risk)' }
      'B' { 'Success Control (no-transition)' }
      'C' { 'Timer Intervention (repair from sibling)' }
    }
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] ARM $arm : $armName" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }

  # ==== COMMON markers ====
  if ($msg -match '^COMMON-START') {
    Write-Host "`n[$t] [COMMON] Instrumentation start" -ForegroundColor Gray
    return
  }

  if ($msg -match '^(SELF|L1|L2|FB)=(.+)$') {
    $name = $Matches[1]
    $value = $Matches[2]
    Write-Host "[$t] [ADDR] $name = $value" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^BACKING-DUMP=(.+)$') {
    Write-Host "[$t] [DUMP] 192-byte backing captured" -ForegroundColor Gray
    return
  }

  if ($msg -match '^WRAPPER-DUMP=(.+)$') {
    Write-Host "[$t] [DUMP] Wrapper bytes captured" -ForegroundColor Gray
    return
  }

  # ==== ARM A markers ====
  if ($msg -match '^A-WRITE-status=(\d+)') {
    $status = $Matches[1]
    Write-Host "[$t] [A] Writing status=$status" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^A-READ-status=(\w+)-expected=(\w+)') {
    $got = $Matches[1]
    $expect = $Matches[2]
    if ($got -eq $expect) {
      Write-Host "[$t] [A] [PASS] status=$got (matches expected)" -ForegroundColor Green
    } else {
      Write-Host "[$t] [A] [FAIL] status=$got, expected=$expect" -ForegroundColor Red
    }
    return
  }

  if ($msg -match '^A-ALL-MATCH') {
    Write-Host "`n[$t] [A] [SUCCESS] All status values match - layout confirmed!" -ForegroundColor Green
    return
  }

  if ($msg -match '^A-LAYOUT-FAIL') {
    Write-Host "`n[$t] [A] [FAIL] Layout mismatch - STOP all load experiments" -ForegroundColor Red
    return
  }

  # ==== ARM B markers ====
  if ($msg -match '^B-STATUS-Success') {
    Write-Host "[$t] [B] Set status=Success (3)" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-SOURCES-empty') {
    Write-Host "[$t] [B] Sources vector emptied" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-CLIENTS-original') {
    Write-Host "[$t] [B] Client table preserved" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-OVERRIDE-Block') {
    Write-Host "[$t] [B] Override=Block set" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-TIMER-zeroed') {
    Write-Host "[$t] [B] Timer zeroed (should not be used)" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-VERIFY-(.+)$') {
    $verify = $Matches[1]
    Write-Host "[$t] [B] [VERIFY] $verify" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^B-LOAD-PRE') {
    Write-Host "`n[$t] [B] [RUN] Calling faces[zi].load()..." -ForegroundColor Yellow
    return
  }

  if ($msg -match '^B-LOAD-RETURNED') {
    Write-Host "[$t] [B] [PASS] load() RETURNED" -ForegroundColor Green
    return
  }

  if ($msg -match '^B-STATUS-AFTER=(\w+)') {
    $status = $Matches[1]
    Write-Host "[$t] [B] [STATUS] After load: $status" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^B-SUCCESS-no-transition-confirmed') {
    Write-Host "`n[$t] [B] [SUCCESS] No-transition control PASS!" -ForegroundColor Green
    return
  }

  if ($msg -match '^B-CRASH') {
    Write-Host "`n[$t] [B] [FAIL] CRASH - need native capture" -ForegroundColor Red
    return
  }

  # ==== ARM C markers ====
  if ($msg -match '^C-FIND-SIBLING') {
    Write-Host "[$t] [C] Searching for sibling face..." -ForegroundColor Yellow
    return
  }

  if ($msg -match '^C-SIBLING=(.+)-backing=(.+)$') {
    $sib = $Matches[1]
    $backing = $Matches[2]
    Write-Host "[$t] [C] [FOUND] Sibling=$sib, backing=$backing" -ForegroundColor Green
    return
  }

  if ($msg -match '^C-NO-SIBLING') {
    Write-Host "[$t] [C] [FAIL] No sibling found - cannot proceed" -ForegroundColor Red
    return
  }

  if ($msg -match '^C-HARVEST-tVptr=(.+)-tThread=(.+)$') {
    $tVptr = $Matches[1]
    $tThread = $Matches[2]
    Write-Host "[$t] [C] [HARVEST] tVptr=$tVptr, tThread=$tThread" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^C-CRAFT-START') {
    Write-Host "[$t] [C] Crafting face with Timer repair..." -ForegroundColor Yellow
    return
  }

  if ($msg -match '^C-TIMER-REPAIR') {
    Write-Host "[$t] [C] [REPAIR] Installing non-owning Timer state" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^C-TIMER-INSTALLED-tVptr=(.+)-tThread=(.+)$') {
    $tVptr = $Matches[1]
    $tThread = $Matches[2]
    Write-Host "[$t] [C] [TIMER] Installed: tVptr=$tVptr, tThread=$tThread" -ForegroundColor Green
    return
  }

  if ($msg -match '^C-FINAL-STATUS-WRITE') {
    Write-Host "[$t] [C] [FINAL] Writing status=Pending (LAST WRITE)" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^C-VERIFY-(.+)$') {
    $verify = $Matches[1]
    Write-Host "[$t] [C] [VERIFY] $verify" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^C-LOAD-PRE') {
    Write-Host "`n[$t] [C] [RUN] Calling faces[zi].load()..." -ForegroundColor Yellow
    return
  }

  if ($msg -match '^C-LOAD-RETURNED') {
    Write-Host "[$t] [C] [PASS] load() RETURNED" -ForegroundColor Green
    return
  }

  if ($msg -match '^C-STATUS-AFTER=(\w+)') {
    $status = $Matches[1]
    Write-Host "[$t] [C] [STATUS] After load: $status" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^C-SUCCESS-timer-was-the-cause') {
    Write-Host "`n[$t] [C] [SUCCESS] TIMER WAS THE CAUSE! Intervention works!" -ForegroundColor Green
    return
  }

  if ($msg -match '^C-UNEXPECTED-status=(\w+)') {
    $status = $Matches[1]
    Write-Host "`n[$t] [C] [FAIL] Unexpected status: $status (expected 'error')" -ForegroundColor Red
    return
  }

  if ($msg -match '^C-CRASH') {
    Write-Host "`n[$t] [C] [FAIL] CRASH - Timer repair insufficient, need native capture" -ForegroundColor Red
    return
  }

  # ==== DONE ====
  if ($msg -match '^DONE') {
    Write-Host "`n[$t] [DONE] Arm complete" -ForegroundColor Green
    return
  }

  if ($msg -match '^RESTORED') {
    Write-Host "[$t] [INFO] Original table pointer restored" -ForegroundColor Gray
    return
  }

  # ==== ERROR ====
  if ($msg -match '^ERR-(.+)$') {
    $error = $Matches[1]
    Write-Host "[$t] [ERROR] $error" -ForegroundColor Red
    return
  }

  if ($msg -match '^SKIP-(.+)$') {
    $reason = $Matches[1]
    Write-Host "[$t] [SKIP] $reason" -ForegroundColor Yellow
    return
  }

  # ==== OTHER ====
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
