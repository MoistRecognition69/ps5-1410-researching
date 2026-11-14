# scan-watch.ps1 v2 — live probe view + V683 sift DELTA analysis
# Computes pageStart from each session's SIFT-START (hypo+0x5424000), annotates
# every HIT with its module-relative delta, and tallies deltas ACROSS sessions:
#   yellow HIT  = raw hit
#   green HIT   = delta stable in 3+ sessions (real module self-pointer candidate)
#   green DSOHIT/BASE = money lines
# Startup seeds the tally from the entire existing log, then live-tails.

$log = Join-Path $PSScriptRoot 'host-beacons.log'
if (-not (Test-Path $log)) { New-Item -ItemType File -Path $log | Out-Null }
Write-Host "watching $log  (Ctrl+C to stop)" -ForegroundColor Cyan

# --- seed pass over existing log (encoded patterns, fast single read) ---
$HYPe = [regex]'/beacon/V683-SIFT-START[^"]*?hypo%3D0x([0-9a-f]+)[^"]*?u=(\w+)'
$HITe = [regex]'/beacon/V683-HIT-at%3D0x([0-9a-f]+)-v%3D0x([0-9a-f]+)[^"]*?u=(\w+)'
$psByUid = @{}
$deltaSessions = @{}          # delta -> HashSet of uids
try {
  $raw = [System.IO.File]::ReadAllText($log)
  foreach($m in $HYPe.Matches($raw)){ $psByUid[$m.Groups[2].Value] = [Convert]::ToInt64($m.Groups[1].Value,16) + 0x5424000 }
  foreach($m in $HITe.Matches($raw)){
    $uid=$m.Groups[3].Value; $v=[Convert]::ToInt64($m.Groups[2].Value,16)
    if($psByUid.ContainsKey($uid)){
      $d = $psByUid[$uid] - $v
      if(-not $deltaSessions.ContainsKey($d)){ $deltaSessions[$d] = New-Object 'System.Collections.Generic.HashSet[string]' }
      [void]$deltaSessions[$d].Add($uid)
    }
  }
  Write-Host ("seeded: {0} sessions, {1} deltas, stable(2+): {2}" -f $psByUid.Count, $deltaSessions.Count,
    (($deltaSessions.GetEnumerator() | Where-Object { $_.Value.Count -ge 2 } | ForEach-Object { 'd-0x{0:x} x{1}' -f $_.Key, $_.Value.Count }) -join '  ')) -ForegroundColor DarkCyan
} catch { Write-Host "seed pass failed: $_" -ForegroundColor DarkRed }

function fmt-delta([long]$d){ if($d -ge 0){ '-0x{0:x}' -f $d } else { '+0x{0:x}' -f (-$d) } }

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_
  if ($line -notmatch '/beacon/V(6(78V2|83|84|86|87|88)|17|3[89])') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }
  $t = $Matches[1]; $p = [uri]::UnescapeDataString($Matches[2]); $u = $Matches[3]
  $msg = $p -replace '^/beacon/V(6(78V2Z?|83|84|86|87|88)|17|3[89])-',''

  if ($msg -match '^SIFT-START.*-hypo=0x([0-9a-f]+)') {
    $script:psByUid[$u] = [Convert]::ToInt64($Matches[1],16) + 0x5424000
  }

  if ($msg -match '^HIT-at=0x([0-9a-f]+)-v=0x([0-9a-f]+)') {
    $v = [Convert]::ToInt64($Matches[2],16)
    if ($script:psByUid.ContainsKey($u)) {
      $d = $script:psByUid[$u] - $v
      if (-not $script:deltaSessions.ContainsKey($d)) { $script:deltaSessions[$d] = New-Object 'System.Collections.Generic.HashSet[string]' }
      [void]$script:deltaSessions[$d].Add($u)
      $n = $script:deltaSessions[$d].Count
      $c = 'Yellow'; $tag = ''
      if ($n -ge 2) { $tag = " [x$n sessions]" }
      if ($n -ge 3) { $c = 'Green' }
      Write-Host ("{0} [{1}] HIT v=0x{2:x} D={3}{4}" -f $t,$u,$v,(fmt-delta $d),$tag) -ForegroundColor $c
    } else {
      Write-Host ("{0} [{1}] {2}" -f $t,$u,$msg) -ForegroundColor Yellow
    }
    return
  }

  if ($msg -match '^SCAN-(START|RESUME|HOP|MAPPED)|^BASE|^PASS-|^ZONE|^ISL|^LEAK-CONFIRMED|^NOLEAK|^WALK-ok|^VT-s0|^SCAN-\d+-off|^RTTI|^FPROBE|^SLOTS|^DSOHIT|^SIFT-(START|END|FLIP|DONE|SUICIDE)|^DUMP-(START|END|DONE|PAUSE|SUICIDE)|^IDUMP|^IDUMPN|^FOUND|^HOP|^RT-|^NOTFOUND|^DUMPN|^\d+-d-0x|^PATHB|^MSCAN|^MBUF|^V17|^V17[CPASRD]|^TRIG|^WIT|^CAL|^CSCAN|^CELLFOUND|^CELL-CACHED|^JSCPROBE|^JSCRAW|^BUFVERIFIED|^MBUFVER|^FACE|^L2RAW|^FBRAW|^FB=|^PROXY|^CBWRAP|^DVHDR|^DV-|^DVMARK|^ADDROF|^PROMISE|^VERIFY|^T[135]-|^LM[12]-|^SLOT-|^PV-SLOT|^GADGET|^CLIENT|^SELF|^PH2|^PH3|^VTAB|^INTABLE|^HIGH-|^B0CLASS|^TAG-|^ARM|^PHASE-|^SENTINEL|^FORGE|^IMPL-|^HEAD|^SIBLING|^TIMER|^PROMISE-|^REAL-PROMISE|^GATES|^GATE-|^G[12345PHI]-|^GP-|^LOAD-|^A-LOAD|^A-WIT|^A-COOP|^A-NO-DIFFS|^A-POST|^WRITE-MASK|^CLASS-|^STRING-FIELD|^B-LOAD|^B-WIT|^B-TIMER|^B-PROMISE|^B-FACE|^B-GATES|^B-GATE|^B-WRITE|^B-NO-DIFFS|^MULTISHOT|^RESTORED|^DONE|^SKIP|^ERR-') {
    $c = 'Gray'
    if ($msg -match '^SCAN-\d+-off|^SIFT-\d+-dir|^DUMPN')   { $c = 'DarkGray' }
    if ($msg -match '^SCAN-MAPPED|^ISL')             { $c = 'Yellow' }
    if ($msg -match '^DSOHIT|^BASE-0x|^DUMP-DONE|^FOUND')    { $c = 'Green' }
    if ($msg -match '^RTTI|^FPROBE|^SLOTS')          { $c = 'Cyan' }
    if ($msg -match '^DUMP-o=|^ISLDUMP')                       { $c = 'DarkYellow' }  # text island chunks
    if ($msg -match '^PASS-ROLLOVER|^ZONE|^SIFT-(START|END|FLIP|DONE|SUICIDE)') { $c = 'DarkCyan' }
    if ($msg -match '^SCAN-START')                   { $c = 'White' }
    # V688 Path B milestones
    if ($msg -match '^L2RAW|^FBRAW|^PROXYRAW|^CBWRAP|^DVHDR|^PH2-|^PH3-|^VTAB|^T[135]-|^LM[12]-|^SLOT-|^VERIFY') { $c = 'DarkYellow' }
    if ($msg -match '^FACE-|^PROXY-|^DV-|^DVMARK-|^CBWRAP-|^HIGH-|^B0CLASS|^CLIENT|^SELF-|^GADGET') { $c = 'Cyan' }
    if ($msg -match '^PATHB-vp|^FB=|^INTABLE|^LEAK-CONFIRMED|^WALK-ok=true|^VT-s') { $c = 'White' }
    if ($msg -match '^FACE-IDENTITY-OK|^ADDROF-CERTIFIED|^PATHB-DONE|^PROMISE-CALLBACK-OWNER-OK|^CLIENT-0x|^SELF-0x') { $c = 'Green' }
    if ($msg -match 'IDENTITY-FAIL|^ADDROF-FAIL|^PATHB-STOP|^NOVP|^WALK-FAIL|^NOLEAK|^NOSELF|^NOCLIENT') { $c = 'Red' }
    # V39 colors
    if ($msg -match '^TAG-|^ARM|^FORGE-BUILD|^IMPL-|^HEAD-|^SIBLING|^TIMER-|^SENTINEL|^FORGE-BUILT') { $c = 'DarkYellow' }
    if ($msg -match '^PHASE-A|^PHASE-B|^GATES-ALL-OK|^B-GATES-OK') { $c = 'White' }
    if ($msg -match '^WRITE-MASK|^CLASS-|^STRING-FIELD|^A-POST') { $c = 'Cyan' }
    if ($msg -match '^A-COOP-WRITE|^MULTISHOT-CONFIRMED|^DONE') { $c = 'Green' }
    if ($msg -match '^GATE-FAIL|^B-GATE-FAIL|^ERR-|^A-NO-DIFFS.*crashed|^B-NO-DIFFS.*crashed|^SKIP') { $c = 'Red' }
    if ($msg -match '^A-LOAD-|^B-LOAD-') { $c = 'Yellow' }
    Write-Host ("{0} [{1}] {2}" -f $t,$u,$msg) -ForegroundColor $c
  }
}
