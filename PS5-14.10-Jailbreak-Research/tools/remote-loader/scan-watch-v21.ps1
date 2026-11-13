# scan-watch-v21.ps1 — V21 beacon bisection watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V21 Beacon Bisection Watcher" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  if ($line -notmatch '/beacon/V21-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V21-',''

  # ==== MODE selection ====
  if ($msg -match '^MODE=(success|pending)') {
    $mode = $Matches[1]
    $modeColor = if ($mode -eq 'success') { 'Green' } else { 'Yellow' }
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] MODE: $mode" -ForegroundColor $modeColor
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }

  # ==== BISECTION POINTS ====
  if ($msg -match '^BP(\d+)-(.+)$') {
    $bp = $Matches[1]
    $rest = $Matches[2]

    # Color code by bisection point
    $color = switch ($bp) {
      '1' { 'Cyan' }      # Pre-load validation
      '2' { 'Yellow' }    # Craft face
      '3' { 'DarkYellow' }# Verify final state
      '4' { 'Magenta' }   # Pre-load beacon
      '5' { 'Green' }     # Call load
      '6' { 'Cyan' }      # Post-load analysis
      '7' { 'DarkCyan' }  # Witness check
      '8' { 'Gray' }      # Restore
      default { 'White' }
    }

    # Special handling for key events
    if ($rest -match '^LOAD-PRE') {
      Write-Host "`n[$t] [BP$bp] >>> CALLING load() <<<" -ForegroundColor Magenta
      return
    }

    if ($rest -match '^LOAD-RETURNED') {
      Write-Host "[$t] [BP$bp] [PASS] load() RETURNED" -ForegroundColor Green
      return
    }

    if ($rest -match '^LOAD-THREW-(.+)$') {
      $error = $Matches[1]
      Write-Host "[$t] [BP$bp] [FAIL] load() THREW: $error" -ForegroundColor Red
      return
    }

    if ($rest -match '^STATUS-AFTER=(\d+)') {
      $status = $Matches[1]
      Write-Host "[$t] [BP$bp] [STATUS] Final status: $status" -ForegroundColor Cyan
      return
    }

    if ($rest -match '^JS-STATUS=(\w+)') {
      $jsStatus = $Matches[1]
      Write-Host "[$t] [BP$bp] [JS] Status via binding: $jsStatus" -ForegroundColor Cyan
      return
    }

    if ($rest -match '^WIT-WRITE-(.+)$') {
      $writes = $Matches[1]
      Write-Host "[$t] [BP$bp] [WIT] Buffer writes: $writes" -ForegroundColor Green
      return
    }

    if ($rest -match '^WIT-nowrite') {
      Write-Host "[$t] [BP$bp] [WIT] No buffer writes" -ForegroundColor Gray
      return
    }

    # Default: show the bisection point
    Write-Host "[$t] [BP$bp] $rest" -ForegroundColor $color
    return
  }

  # ==== DONE ====
  if ($msg -match '^DONE-(success|pending)-(SUCCESS|FAILED)') {
    $mode = $Matches[1]
    $result = $Matches[2]
    $color = if ($result -eq 'SUCCESS') { 'Green' } else { 'Red' }
    Write-Host "`n[$t] [DONE] $mode : $result" -ForegroundColor $color
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
