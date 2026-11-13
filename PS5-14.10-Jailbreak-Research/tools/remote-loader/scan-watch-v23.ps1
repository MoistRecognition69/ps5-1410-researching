# scan-watch-v23.ps1 — V23 original clients test watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V23 Original Clients Test Watcher" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  if ($line -notmatch '/beacon/V23-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V23-',''

  # ==== VALIDATION ====
  if ($msg -match '^VALIDATE-ORIGINAL') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] VALIDATING ORIGINAL STATE" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^ORIGINAL-TIMER=(.+)$') {
    Write-Host "[$t] [TIMER] Original state captured" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^ORIGINAL-CLIENTS=(.+)$') {
    $clients = $Matches[1]
    Write-Host "[$t] [CLIENTS] Original table pointer: $clients" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^CLIENTS-MATCH-L1') {
    Write-Host "[$t] [OK] Clients match L1" -ForegroundColor Green
    return
  }

  if ($msg -match '^CLIENTS-MISMATCH-expect=(.+)$') {
    $expect = $Matches[1]
    Write-Host "[$t] [FAIL] Clients mismatch! Expected: $expect" -ForegroundColor Red
    return
  }

  # ==== CRAFT ====
  if ($msg -match '^CRAFT-START') {
    Write-Host "`n[$t] [CRAFT] Crafting face (ORIGINAL CLIENTS + TIMER)..." -ForegroundColor Cyan
    return
  }

  if ($msg -match '^FIELD-(.+)$') {
    $field = $Matches[1]
    if ($field -eq 'clients=ORIGINAL-no-modification' -or $field -eq 'timer=ORIGINAL-no-modification') {
      Write-Host "[$t] [FIELD] $field" -ForegroundColor Green
    } else {
      Write-Host "[$t] [FIELD] $field" -ForegroundColor DarkYellow
    }
    return
  }

  if ($msg -match '^CRAFT-COMPLETE') {
    Write-Host "[$t] [OK] Face craft complete (Clients + Timer preserved)" -ForegroundColor Green
    return
  }

  # ==== VERIFY ====
  if ($msg -match '^VERIFY-FINAL') {
    Write-Host "`n[$t] [VERIFY] Final state check" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^VERIFY-(.+)$') {
    $verify = $Matches[1]
    Write-Host "[$t] [VERIFY] $verify" -ForegroundColor DarkYellow
    return
  }

  # ==== LOAD ====
  if ($msg -match '^LOAD-PRE') {
    Write-Host "`n[$t] [RUN] Calling faces[zi].load() with ORIGINAL Clients + Timer..." -ForegroundColor Yellow
    return
  }

  if ($msg -match '^LOAD-RETURNED') {
    Write-Host "[$t] [PASS] load() RETURNED - SUCCESS!" -ForegroundColor Green
    return
  }

  if ($msg -match '^LOAD-THREW-(.+)$') {
    $error = $Matches[1]
    Write-Host "[$t] [FAIL] load() THREW - $error" -ForegroundColor Red
    return
  }

  # ==== POST-LOAD ====
  if ($msg -match '^POST-LOAD-returned=(\w+)-threw=(\w+)') {
    $returned = $Matches[1]
    $threw = $Matches[2]
    if ($returned -eq 'true') {
      Write-Host "[$t] [OK] Post-load: returned=true, threw=false" -ForegroundColor Green
    } else {
      Write-Host "[$t] [FAIL] Post-load: returned=false, threw=true" -ForegroundColor Red
    }
    return
  }

  if ($msg -match '^STATUS-AFTER=(\d+)') {
    $status = $Matches[1]
    $statusName = switch ($status) {
      '0' { 'Pending' }
      '1' { 'Loading' }
      '2' { 'TimedOut' }
      '3' { 'Success' }
      '4' { 'Failure' }
      default { 'Unknown' }
    }
    Write-Host "[$t] [STATUS] Final status: $status ($statusName)" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^JS-STATUS=(\w+)') {
    $jsStatus = $Matches[1]
    Write-Host "[$t] [JS] Status via binding: $jsStatus" -ForegroundColor Cyan
    return
  }

  # ==== WITNESS ====
  if ($msg -match '^WIT-WRITE-(.+)$') {
    $writes = $Matches[1]
    Write-Host "[$t] [WIT] Buffer writes: $writes" -ForegroundColor Green
    return
  }

  if ($msg -match '^WIT-nowrite') {
    Write-Host "[$t] [WIT] No buffer writes" -ForegroundColor Gray
    return
  }

  # ==== DONE ====
  if ($msg -match '^DONE-SUCCESS-null-clients-was-the-cause') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] V23 SUCCESS - NULL CLIENTS WAS THE CAUSE!" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    Write-Host "`n[RESULT] Original clients work! Null client table was causing the crash." -ForegroundColor Green
    Write-Host "[NEXT] Use original clients for dispatch to cell+0x10`n" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^DONE-FAILED-fundamental-issue') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Red
    Write-Host "[$t] V23 FAILED - FUNDAMENTAL ISSUE" -ForegroundColor Red
    Write-Host "[$t] =======================================" -ForegroundColor Red
    Write-Host "`n[RESULT] Even original clients crash. Something fundamental is wrong." -ForegroundColor Red
    Write-Host "[NEXT] Fork divergence or object identity issue - need native capture`n" -ForegroundColor Yellow
    return
  }

  # ==== RESTORED ====
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
