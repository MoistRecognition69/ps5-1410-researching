# scan-watch-v30.ps1 — V30 dispatch-control watcher (d0a / d0b / d1)

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V30 Dispatch-Control Watcher" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

$armNames = @{
  'd0a' = 'REAL client (impl.m_ptr = FB) - machinery-vs-fake split'
  'd0b' = 'Fake copy + REAL vtable (client+0x00 unpatched) - vtable-vs-fields split'
  'd0'  = 'Full fake (8x NOPG vtable)'
  'd1'  = 'slot3 = real fontStateChanged (THE dispatch)'
}

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_
  if ($line -notmatch '/beacon/V30-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $msg = $p -replace '^/beacon/V30-',''

  if ($msg -match '^ARM=([\w]+)') {
    $arm = $Matches[1]
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] V30 ARM: $arm - $($armNames[$arm])" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }
  if ($msg -match '^IMPL-rc=(\d+)-m_ptr=(0x[0-9a-f]+)') {
    $ptr = $Matches[2]
    $kind = if ($ptr -eq '0x0') {'NULL'} elseif ($ptr -match 'f0450$|f0450') {'FAKE-CLIENT'} else {$ptr}
    Write-Host "[$t] [IMPL] rc=$($Matches[1]) m_ptr=$ptr" -ForegroundColor DarkYellow
    return
  }
  if ($msg -match '^CLIENT-VT-REAL=(0x[0-9a-f]+)') { Write-Host "[$t] [CLIENT] real vtable kept: $($Matches[1]) (d0b)" -ForegroundColor DarkYellow; return }
  if ($msg -match '^GATES-ALL-OK') { Write-Host "[$t] [GATES] all passed" -ForegroundColor Green; return }
  if ($msg -match '^GATE-FAIL-ABORT-NO-LOAD') { Write-Host "[$t] [ABORT] gate failed - no load()" -ForegroundColor Red; return }
  if ($msg -match '^LOAD-PRE') { Write-Host "`n[$t] >>> CALLING faces[zi].load() <<<" -ForegroundColor Magenta; return }
  if ($msg -match '^LOAD-RETURNED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** load() RETURNED ***" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    return
  }
  if ($msg -match '^LOAD-THREW-(.+)') { Write-Host "[$t] [FAIL] THREW: $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^WIT-status=(\d+)-opcount=(\d+)-meta=([0-9a-f]+)-bk0=(0x[0-9a-f]+)-implrc=(\d+)-timerVptrOK=(\w+)') {
    Write-Host "[$t] [WIT] status=$($Matches[1]) opcount=$($Matches[2]) meta=$($Matches[3])" -ForegroundColor Cyan
    Write-Host "[$t] [WIT] bk0=$($Matches[4]) implrc=$($Matches[5]) timerOK=$($Matches[6])" -ForegroundColor Cyan
    return
  }
  if ($msg -match '^JS-STATUS=(\w+)') { Write-Host "[$t] [JS] status=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match 'WIT-V30-PROMISE-CHANGED') {
    Write-Host "`n[$t] *** WITNESS: PROMISE CHANGED - fontStateChanged EXECUTED ***" -ForegroundColor Green
    return
  }
  if ($msg -match 'WIT-V30-PROMISE-UNCHANGED') { Write-Host "[$t] [WIT] promise unchanged" -ForegroundColor Gray; return }
  if ($msg -match 'WIT-V30-FORGE-WRITE-(.+)') { Write-Host "[$t] [WIT] forge writes: $($Matches[1])" -ForegroundColor Green; return }
  if ($msg -match 'WIT-V30-FORGE-nowrite') { Write-Host "[$t] [WIT] forge unchanged" -ForegroundColor Gray; return }
  if ($msg -match '^DONE-([\w]+)-(RETURNED|CRASHED)') {
    $arm2 = $Matches[1]; $r = $Matches[2]
    if ($r -eq 'RETURNED') {
      Write-Host "`n[$t] [DONE] ${arm2}: RETURNED" -ForegroundColor Green
      $nxt = switch ($arm2) { 'd0a' {'d0b'} 'd0b' {'d1'} 'd0' {'d0a'} 'd1' {'poison'} }
      Write-Host "[$t] [NEXT] flip index.html to arm=$nxt" -ForegroundColor Cyan
    } else { Write-Host "`n[$t] [DONE] ${arm2}: CRASHED" -ForegroundColor Red }
    return
  }
  if ($msg -match '^RESTORED') { Write-Host "[$t] [INFO] table restored" -ForegroundColor Gray; return }
  if ($msg -match '^ERR-(.+)') { Write-Host "[$t] [ERROR] $($Matches[1])" -ForegroundColor Red; return }
  Write-Host "[$t] $msg" -ForegroundColor Gray
}