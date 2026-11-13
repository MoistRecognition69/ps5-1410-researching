# scan-watch-v29.ps1 — V29 fixed-forge ladder watcher

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V29 Fixed-Forge Ladder Watcher" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

$armNames = @{
  'born' = 'Born-empty (pure machinery test)'
  'weak' = 'Weaknull removal (deleteBucket + deref test)'
  'd0'   = 'No-op dispatch (all slots NOPG)'
  'd1'   = 'REAL dispatch (slot3 = fontStateChanged gadget)'
}

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_
  if ($line -notmatch '/beacon/V29-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $msg = $p -replace '^/beacon/V29-',''

  if ($msg -match '^ARM=(\w+)') {
    $arm = $Matches[1]
    Write-Host "`n[$t] =======================================" -ForegroundColor Cyan
    Write-Host "[$t] V29 ARM: $arm - $($armNames[$arm])" -ForegroundColor Cyan
    Write-Host "[$t] =======================================" -ForegroundColor Cyan
    return
  }
  if ($msg -match '^PROMISE-ADDR=(0x[0-9a-f]+)') { Write-Host "[$t] [PROMISE] real promise at $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^PROMISE-BEFORE=') { Write-Host "[$t] [PROMISE] pre-dispatch snapshot taken" -ForegroundColor DarkYellow; return }
  if ($msg -match '^SIBLING-SCAN') { Write-Host "[$t] [SCAN] sibling search..." -ForegroundColor Yellow; return }
  if ($msg -match '^SIBLING=(0x[0-9a-f]+)-backing=(0x[0-9a-f]+)') { Write-Host "[$t] [OK] sibling $($Matches[1]) backing=$($Matches[2])" -ForegroundColor Green; return }
  if ($msg -match '^NO-SIBLING') { Write-Host "[$t] [FAIL] no sibling" -ForegroundColor Red; return }
  if ($msg -match '^TIMER-BORROWED=') { Write-Host "[$t] [OK] timer borrowed" -ForegroundColor Green; return }
  if ($msg -match '^FORGE-BUILD') { Write-Host "`n[$t] [FORGE] building (setUint32 metadata - THE FIX)..." -ForegroundColor Yellow; return }
  if ($msg -match '^IMPL-rc=(\d+)-m_ptr=(0x[0-9a-f]+)') { Write-Host "[$t] [IMPL] rc=$($Matches[1]) m_ptr=$($Matches[2])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^CLIENT-PROMISE=(0x[0-9a-f]+)-(IS-REAL-OK|MISMATCH)') {
    if ($Matches[2] -eq 'IS-REAL-OK') { Write-Host "[$t] [OK] client promise = REAL" -ForegroundColor Green }
    else { Write-Host "[$t] [WARN] client promise NOT real!" -ForegroundColor Red }
    return
  }
  if ($msg -match '^FORGE-BUILT-T=') { Write-Host "[$t] [OK] forge built" -ForegroundColor Green; return }
  if ($msg -match '^FACE-CRAFT') { Write-Host "`n[$t] [FACE] crafting..." -ForegroundColor Yellow; return }

  # ==== GATES ====
  if ($msg -match '^G1-meta-hex=([0-9a-f]+)-expect=([0-9a-f]+)') {
    $got = $Matches[1]; $exp = $Matches[2]
    if ($got -eq $exp) { Write-Host "[$t] [G1 PASS] metadata = $got" -ForegroundColor Green }
    else { Write-Host "[$t] [G1 FAIL] got=$got expected=$exp" -ForegroundColor Red }
    return
  }
  if ($msg -match '^G1-dwords-d=(\d+)-kc=(\d+)-mask=(\d+)-size=(\d+)') {
    Write-Host "[$t] [G1] d=$($Matches[1]) kc=$($Matches[2]) mask=$($Matches[3]) size=$($Matches[4])" -ForegroundColor DarkYellow
    return
  }
  if ($msg -match '^G1-FAIL') { Write-Host "[$t] [G1 FAIL] metadata mismatch" -ForegroundColor Red; return }
  if ($msg -match '^G1-FAIL-MARKER-A') { Write-Host "[$t] [G1 FAIL] MARKER A STILL PRESENT - fix not applied!" -ForegroundColor Red; return }
  if ($msg -match '^G2-face58=(0x[0-9a-f]+)') { Write-Host "[$t] [G2] face+0x58 = $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^G2-FAIL') { Write-Host "[$t] [G2 FAIL]" -ForegroundColor Red; return }
  if ($msg -match '^G3-face60=(0x[0-9a-f]+)') { Write-Host "[$t] [G3] counters = $($Matches[1])" -ForegroundColor DarkYellow; return }
  if ($msg -match '^G3-FAIL') { Write-Host "[$t] [G3 FAIL]" -ForegroundColor Red; return }
  if ($msg -match '^G4-sources=([0-9a-f]+)') {
    if ($Matches[1] -eq '0'*32) { Write-Host "[$t] [G4 PASS] sources all zero" -ForegroundColor Green }
    else { Write-Host "[$t] [G4] sources bytes: $($Matches[1])" -ForegroundColor DarkYellow }
    return
  }
  if ($msg -match '^G4-FAIL') { Write-Host "[$t] [G4 FAIL] SOURCES DIRTY - aborting" -ForegroundColor Red; return }
  if ($msg -match '^G5-status=(\d+)-ovr=(\d+)-vptr=(0x[0-9a-f]+)-thread=(0x[0-9a-f]+)-heap=(0x[0-9a-f]+)-fire=(0x[0-9a-f]+)') {
    Write-Host "[$t] [G5] status=$($Matches[1]) ovr=$($Matches[2]) vptr=$($Matches[3]) thread=$($Matches[4]) heap=$($Matches[5]) fire=$($Matches[6])" -ForegroundColor DarkYellow
    return
  }
  if ($msg -match '^G5-FAIL') { Write-Host "[$t] [G5 FAIL] timer/status predicate" -ForegroundColor Red; return }
  if ($msg -match '^GATE-FAIL-ABORT-NO-LOAD') { Write-Host "`n[$t] [ABORT] Gate failed - load() NOT called" -ForegroundColor Red; return }
  if ($msg -match '^GATES-ALL-OK') { Write-Host "[$t] [ALL GATES PASS]" -ForegroundColor Green; return }

  # ==== DISPATCH ====
  if ($msg -match '^LOAD-PRE') { Write-Host "`n[$t] >>> CALLING faces[zi].load() <<<" -ForegroundColor Magenta; return }
  if ($msg -match '^LOAD-RETURNED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** load() RETURNED ***" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    return
  }
  if ($msg -match '^LOAD-THREW-(.+)') { Write-Host "[$t] [FAIL] THREW: $($Matches[1])" -ForegroundColor Red; return }

  # ==== COMPOSITE WITNESS ====
  if ($msg -match '^WIT-status=(\d+)-opcount=(\d+)-meta=([0-9a-f]+)-bk0=(0x[0-9a-f]+)-implrc=(\d+)-timerVptrOK=(\w+)') {
    Write-Host "[$t] [WIT] status=$($Matches[1]) opcount=$($Matches[2]) meta=$($Matches[3])" -ForegroundColor Cyan
    Write-Host "[$t] [WIT] bk0=$($Matches[4]) implrc=$($Matches[5]) timerOK=$($Matches[6])" -ForegroundColor Cyan
    return
  }
  if ($msg -match '^JS-STATUS=(\w+)') { Write-Host "[$t] [JS] status=$($Matches[1])" -ForegroundColor Cyan; return }
  if ($msg -match 'WIT-V29-PROMISE-CHANGED') {
    Write-Host "`n[$t] =======================================" -ForegroundColor Green
    Write-Host "[$t] *** WITNESS: PROMISE CHANGED ***" -ForegroundColor Green
    Write-Host "[$t] fontStateChanged EXECUTED - dispatch REAL" -ForegroundColor Green
    Write-Host "[$t] =======================================" -ForegroundColor Green
    return
  }
  if ($msg -match 'WIT-V29-PROMISE-UNCHANGED') { Write-Host "[$t] [WIT] promise unchanged (fulfilled - reject skipped)" -ForegroundColor Gray; return }
  if ($msg -match 'WIT-V29-FORGE-WRITE-(.+)') { Write-Host "[$t] [WIT] forge writes: $($Matches[1])" -ForegroundColor Green; return }
  if ($msg -match 'WIT-V29-FORGE-nowrite') { Write-Host "[$t] [WIT] forge unchanged" -ForegroundColor Gray; return }

  # ==== DONE ====
  if ($msg -match '^DONE-(\w+)-(RETURNED|CRASHED)') {
    $r = $Matches[2]
    if ($r -eq 'RETURNED') {
      Write-Host "`n[$t] [DONE] $($Matches[1]): RETURNED" -ForegroundColor Green
      $nxt = switch ($Matches[1]) { 'born' {'weak'} 'weak' {'d0'} 'd0' {'d1'} 'd1' {'poison'} }
      Write-Host "[$t] [NEXT] flip index.html to arm=$nxt" -ForegroundColor Cyan
    } else { Write-Host "`n[$t] [DONE] $($Matches[1]): CRASHED" -ForegroundColor Red }
    return
  }
  if ($msg -match '^RESTORED') { Write-Host "[$t] [INFO] table restored" -ForegroundColor Gray; return }
  if ($msg -match '^ERR-(.+)') { Write-Host "[$t] [ERROR] $($Matches[1])" -ForegroundColor Red; return }
  if ($msg -match '^SKIP-(.+)') { Write-Host "[$t] [SKIP] $($Matches[1])" -ForegroundColor Yellow; return }
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
