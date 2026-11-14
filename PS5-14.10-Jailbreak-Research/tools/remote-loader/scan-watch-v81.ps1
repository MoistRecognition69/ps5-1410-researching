# scan-watch-v81.ps1 - live follow for the V50+ campaign (census/swap/RIP/recon/preflight era)
# Tails host-beacons.log and shows every probe beacon, ALL VERSIONS, color-coded:
#   GREEN  = milestones (anchor confirmed, JF accepted, VM calibration, preflight results)
#   YELLOW = informational (scans, chunks, structural-only, drift)
#   RED    = errors, aborts, misses, not-confirmed
#   CYAN   = stage transitions
# Ctrl+C to stop.
#
# FIXES vs scan-watch-v61: the prefix now matches ALL probe versions
# (v61 only matched V50-V69 - that is why recent runs "didn't log").

$log = Join-Path $PSScriptRoot 'host-beacons.log'
if (-not (Test-Path $log)) { New-Item -ItemType File -Path $log | Out-Null }
Write-Host "watching $log  (all probe versions; Ctrl+C to stop)" -ForegroundColor Cyan

# Beacon prefix pattern: ANY probe version (V50, V81, V99, V123, ...).
$prefix = '/beacon/V\d+'

# Milestone patterns (GREEN)
$milestone = 'ANCHOR-CONFIRMED|ANCHOR-RESULT=FOUND|VERIFY-DIFF=|JF-CAND-.*(hdrOK=true|execOK=true)|SCOPE-G=|VM-WINDIFF-.*changed=[1-9]|VM-CONFIRM-.*w=true|VM-RESULT=CALIBRATED|BASELINE-RETURNED|FAKE-RESULT|FAKE-BUILT|POST-scope=|PC-REDIRECTION-CONFIRMED|OPENSWAP-RESTORED|COOP-WRITE-CONFIRMED|OOB-RW-CONFIRMED'
# Error patterns (RED)
$errorPat = 'ERR-|FAIL|ABORT|CRASH|DEAD|SKIP-|MISS-all-routes|not-confirmed|FAKE-ABORT|LOOP-ERR|<err>|<len='
# Stage transition patterns (CYAN)
$stagePat = '-START|BOOT-|PATHB-DONE|(^|[-A-Z0-9])DONE|PREFLIGHT|LOWB|CENSUS-START|FAMILIES='
# Informational (YELLOW): scan chunks and structural-only
$infoPat = 'CHUNK|RAWSCAN|WINDIFF-0-changed=0|STRUCTURAL-ONLY|VM-TRY|DRIFT|BSCAN|ASCAN|JFSCAN|NE-\d'

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
  elseif ($msg -match $errorPat)  { Write-Host $out -ForegroundColor Red }
  elseif ($msg -match $stagePat)  { Write-Host $out -ForegroundColor Cyan }
  elseif ($msg -match $infoPat)   { Write-Host $out -ForegroundColor Yellow }
  else                            { Write-Host $out -ForegroundColor DarkGray }
}
