# scan-watch-v61.ps1 - live follow for the V50+ campaign (census/swap/RIP era)
# Tails host-beacons.log and shows every V50-V69 beacon, color-coded:
#   GREEN  = milestone lines (swap witness, PC redirection, names decoded, ARW)
#   YELLOW = census/counters/drift (informational)
#   RED    = errors, aborts, gate failures, crashes
#   CYAN   = stage transitions
# Ctrl+C to stop.

$log = Join-Path $PSScriptRoot 'host-beacons.log'
if (-not (Test-Path $log)) { New-Item -ItemType File -Path $log | Out-Null }
Write-Host "watching $log  (V50+ campaign; Ctrl+C to stop)" -ForegroundColor Cyan

# Beacon prefix pattern: the probe version (V50..V69), stage prefixes ride inside the message.
# Newer probes double-prefix (e.g. /beacon/V61-V61-BSCAN-... or /beacon/V61-V49-OOB-RW-...).
$prefix = '/beacon/V(5[0-9]|6[0-9])'

# Milestone patterns (GREEN)
$milestone = 'PC-REDIRECTION-CONFIRMED|SWAP-A=|SWAP-B=|BEHAVIORAL-CHANGE=true|READBACK=.*match=true|RESTORED=.*match=true|STRDBG|name=(sqrt|abs|floor|ceil|round|max|min|parseInt)|OOB-RW-CONFIRMED|ABS-READ-OK|COOP-WRITE-CONFIRMED|A-MATCH=true|ELF-MAGIC|SAME-CONFIRMED'
# Error patterns (RED)
$errorPat = 'ERR|FAIL|ABORT|CRASH|DEAD|SKIP-|OOR|<err>|<len='
# Stage transition patterns (CYAN)
$stagePat = '-START|BOOT-|PATHB-DONE|DONE|LOWB|BSCAN-range|CSCAN-START|PREFLIGHT|FIRE-'

Get-Content $log -Wait -Tail 30 | ForEach-Object {
  $line = $_
  if ($line -notmatch $prefix) { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/',''
  $out = "$t  [$u]  $msg"
  if     ($msg -match $milestone) { Write-Host $out -ForegroundColor Green }
  elseif ($msg -match $errorPat) { Write-Host $out -ForegroundColor Red }
  elseif ($msg -match $stagePat) { Write-Host $out -ForegroundColor Cyan }
  else                            { Write-Host $out -ForegroundColor DarkGray }
}
