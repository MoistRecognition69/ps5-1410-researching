# scan-watch-v18c.ps1 — V18C fully-valid face craft watcher
# Highlights craft fields and load() result

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V18C Fully-Valid Face Craft Watcher" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  # Only process V18C beacons
  if ($line -notmatch '/beacon/V18C-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V18C-',''

  # ==== CRAFT START ====
  if ($msg -match '^CRAFT-START') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] CRAFTING FULLY-VALID FACE" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }

  # ==== FIELD markers ====
  if ($msg -match '^FIELD-(.+)$') {
    $field = $Matches[1]
    Write-Host "[$t] [FIELD] $field" -ForegroundColor DarkYellow
    return
  }

  # ==== CRAFT COMPLETE ====
  if ($msg -match '^CRAFT-COMPLETE') {
    Write-Host "[$t] [OK] Face craft complete - all fields set" -ForegroundColor Green
    return
  }

  # ==== LOAD PRE ====
  if ($msg -match '^LOAD-PRE') {
    Write-Host "`n[$t] [RUN] Calling faces[zi].load()..." -ForegroundColor Yellow
    return
  }

  # ==== LOAD RESULT ====
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

  # ==== STATUS AFTER ====
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

  # ==== STATUS CHANGE ====
  if ($msg -match '^STATUS-UNCHANGED-Pending') {
    Write-Host "[$t] [STATUS] Status unchanged: Pending (expected for empty sources)" -ForegroundColor Green
    return
  }

  if ($msg -match '^STATUS-CHANGED-(.+)$') {
    $newStatus = $Matches[1]
    Write-Host "[$t] [STATUS] Status changed to: $newStatus" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^STATUS-UNEXPECTED=(\d+)') {
    $status = $Matches[1]
    Write-Host "[$t] [WARN] Unexpected status: $status" -ForegroundColor Red
    return
  }

  # ==== WITNESS ====
  if ($msg -match '^WIT-WRITE-(.+)$') {
    $writes = $Matches[1]
    Write-Host "[$t] [WIT] Buffer writes detected: $writes" -ForegroundColor Green
    return
  }

  if ($msg -match '^WIT-nowrite') {
    Write-Host "[$t] [WIT] No buffer writes detected" -ForegroundColor Gray
    return
  }

  # ==== RESTORED ====
  if ($msg -match '^RESTORED') {
    Write-Host "[$t] [INFO] Original table pointer restored" -ForegroundColor Gray
    return
  }

  # ==== DONE ====
  if ($msg -match '^DONE-SUCCESS') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] V18C SUCCESS - FULLY-VALID FACE WORKS!" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    Write-Host "`n[RESULT] The fully-valid face craft allows load() to complete!" -ForegroundColor Green
    Write-Host "[NEXT] Ready to test with actual client table (Phase 2-4)`n" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^DONE-FAILED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Red
    Write-Host "[$t] V18C FAILED - STILL CRASHES" -ForegroundColor Red
    Write-Host "[$t] =======================================" -ForegroundColor Red
    Write-Host "`n[RESULT] Even with all fields crafted, load() still crashes." -ForegroundColor Red
    Write-Host "[NEXT] Need to analyze which field is still invalid`n" -ForegroundColor Yellow
    return
  }

  # ==== ERROR ====
  if ($msg -match '^ERR-(.+)$') {
    $error = $Matches[1]
    Write-Host "[$t] [ERROR] V18C ERROR: $error" -ForegroundColor Red
    return
  }

  if ($msg -match '^SKIP-(.+)$') {
    $reason = $Matches[1]
    Write-Host "[$t] [SKIP] V18C SKIP: $reason" -ForegroundColor Yellow
    return
  }

  # ==== OTHER ====
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
