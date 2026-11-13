# scan-watch-v18d.ps1 — V18D validation + alternative dispatch watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V18D Validation + Alternative Dispatch Watcher" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  if ($line -notmatch '/beacon/V18D-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V18D-',''

  # ==== VALIDATION markers ====
  if ($msg -match '^VALIDATE-(.+)$') {
    $check = $Matches[1]
    Write-Host "`n[$t] [CHECK] $check" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^FACE-VTABLE=(.+)$') {
    $vtable = $Matches[1]
    Write-Host "[$t] [DATA] Face vtable: $vtable" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^VTABLE-MATCH-VP') {
    Write-Host "[$t] [OK] Face vtable matches VP" -ForegroundColor Green
    return
  }

  if ($msg -match '^VTABLE-MISMATCH-expect=(.+)$') {
    $expect = $Matches[1]
    Write-Host "[$t] [FAIL] Face vtable mismatch! Expected: $expect" -ForegroundColor Red
    return
  }

  if ($msg -match '^FACE-BACKING=(.+)$') {
    $backing = $Matches[1]
    Write-Host "[$t] [DATA] Face backing: $backing" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^BACKING-MATCH-SELF') {
    Write-Host "[$t] [OK] Face backing matches SELF" -ForegroundColor Green
    return
  }

  if ($msg -match '^BACKING-MISMATCH-expect=(.+)$') {
    $expect = $Matches[1]
    Write-Host "[$t] [FAIL] Face backing mismatch! Expected: $expect" -ForegroundColor Red
    return
  }

  if ($msg -match '^MEMORY-READABLE-len=(\d+)') {
    $len = $Matches[1]
    Write-Host "[$t] [OK] Face memory readable ($len bytes)" -ForegroundColor Green
    return
  }

  if ($msg -match '^MEMORY-UNREADABLE-(.+)$') {
    $error = $Matches[1]
    Write-Host "[$t] [FAIL] Face memory unreadable: $error" -ForegroundColor Red
    return
  }

  if ($msg -match '^WRAPPER-VTABLE=(.+)$') {
    $vtable = $Matches[1]
    Write-Host "[$t] [DATA] Wrapper vtable: $vtable" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^WRAPPER-MATCH-VP') {
    Write-Host "[$t] [OK] Wrapper vtable matches VP" -ForegroundColor Green
    return
  }

  if ($msg -match '^WRAPPER-MISMATCH') {
    Write-Host "[$t] [FAIL] Wrapper vtable mismatch!" -ForegroundColor Red
    return
  }

  # ==== CRAFT markers ====
  if ($msg -match '^CRAFT-START') {
    Write-Host "`n[$t] [CRAFT] Crafting face..." -ForegroundColor Cyan
    return
  }

  if ($msg -match '^CRAFT-COMPLETE') {
    Write-Host "[$t] [OK] Face craft complete" -ForegroundColor Green
    return
  }

  # ==== TEST markers ====
  if ($msg -match '^TEST(\d+)-(.+)-PRE$') {
    $testNum = $Matches[1]
    $testName = $Matches[2]
    Write-Host "`n[$t] [TEST $testNum] $testName" -ForegroundColor Yellow
    return
  }

  if ($msg -match '^TEST(\d+)-(.+)-RETURNED$') {
    $testNum = $Matches[1]
    $testName = $Matches[2]
    Write-Host "[$t] [PASS] Test $testNum ($testName) RETURNED" -ForegroundColor Green
    return
  }

  if ($msg -match '^TEST(\d+)-(.+)-THREW-(.+)$') {
    $testNum = $Matches[1]
    $testName = $Matches[2]
    $error = $Matches[3]
    Write-Host "[$t] [FAIL] Test $testNum ($testName) THREW: $error" -ForegroundColor Red
    return
  }

  if ($msg -match '^TEST3-HAS-FACE=(\w+)') {
    $hasFace = $Matches[1]
    Write-Host "[$t] [DATA] Face in set: $hasFace" -ForegroundColor Cyan
    return
  }

  if ($msg -match '^TEST4-STATUS=(\w+)') {
    $status = $Matches[1]
    Write-Host "[$t] [DATA] Face status: $status" -ForegroundColor Cyan
    return
  }

  # ==== DONE ====
  if ($msg -match '^DONE') {
    Write-Host "`n[$t] [DONE] V18D complete" -ForegroundColor Green
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
