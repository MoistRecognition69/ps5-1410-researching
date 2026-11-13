# scan-watch-v18.ps1 — V18B dispatch test watcher
# Highlights important dispatch test results, filters noise

$log = Join-Path $PSScriptRoot 'host-beacons.log'
Write-Host "V18B Dispatch Test Watcher" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host "watching $log  (Ctrl+C to stop)`n" -ForegroundColor Cyan

# Track test results
$testResults = @{}
$currentTest = ""

Get-Content $log -Wait -Tail 0 | ForEach-Object {
  $line = $_

  # Only process V18B beacons
  if ($line -notmatch '/beacon/V18B-') { return }
  if ($line -notmatch '"t": "([^"]+)".*"path": "([^"?]+).*u=(\w+)') { return }

  $t = $Matches[1]
  $p = [uri]::UnescapeDataString($Matches[2])
  $u = $Matches[3]
  $msg = $p -replace '^/beacon/V18B-',''

  # ==== TEST START markers ====
  if ($msg -match '^TEST(\d+)-(.+)$') {
    $testNum = $Matches[1]
    $testName = $Matches[2]
    $currentTest = "TEST$testNum"
    Write-Host "`n[$t] ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "[$t] TEST $testNum : $testName" -ForegroundColor Cyan
    Write-Host "[$t] ═══════════════════════════════════════" -ForegroundColor Cyan
    return
  }

  # ==== TEST RESULT markers (RETURNED = success, THREW = exception) ====
  if ($msg -match '^(REAL-FACE|RECLAIMED-NOMOD|STATUS-ONLY|STATUS-OVERRIDE|EMPTY-SOURCES|NULL-TABLE)-(RETURNED|THREW)-?(.*)$') {
    $testType = $Matches[1]
    $result = $Matches[2]
    $error = $Matches[3]

    if ($result -eq 'RETURNED') {
      Write-Host "[$t] ✅ $testType : SUCCESS" -ForegroundColor Green
      $testResults[$testType] = 'SUCCESS'
    } else {
      Write-Host "[$t] ❌ $testType : CRASHED - $error" -ForegroundColor Red
      $testResults[$testType] = 'CRASHED'
    }
    return
  }

  # ==== PRE-LOAD markers (about to call load()) ====
  if ($msg -match '^NULL-TABLE-PRE-LOAD') {
    Write-Host "[$t] ⚠️  Calling faces[zi].load() with m_table=nullptr..." -ForegroundColor Yellow
    return
  }

  # ==== ANALYSIS markers ====
  if ($msg -match '^TIMER-REGION=(.+)$') {
    $timerData = $Matches[1]
    Write-Host "[$t] 📊 Timer Region: $timerData" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^PROMISE-PTR=(.+)$') {
    $promisePtr = $Matches[1]
    Write-Host "[$t] 📊 Promise Pointer: $promisePtr" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^PROMISE-RAW=(.+)$') {
    $promiseData = $Matches[1]
    Write-Host "[$t] 📊 Promise Data: $promiseData" -ForegroundColor DarkYellow
    return
  }

  if ($msg -match '^PROMISE-INVALID') {
    Write-Host "[$t] ⚠️  Promise pointer is invalid!" -ForegroundColor Red
    return
  }

  # ==== COMPLETION markers ====
  if ($msg -match '^RESTORED') {
    Write-Host "[$t] 🔄 Original table pointer restored" -ForegroundColor Gray
    return
  }

  if ($msg -match '^DONE') {
    Write-Host "`n[$t] ═══════════════════════════════════════" -ForegroundColor Green
    Write-Host "[$t] V18B INSTRUMENTATION COMPLETE" -ForegroundColor Green
    Write-Host "[$t] ═══════════════════════════════════════" -ForegroundColor Green

    # Print summary
    Write-Host "`n📋 TEST SUMMARY:" -ForegroundColor Cyan
    Write-Host "═══════════════" -ForegroundColor Cyan

    $summary = @{
      'REAL-FACE' = 'Test 1: Real face load()'
      'RECLAIMED-NOMOD' = 'Test 2: Reclaimed, no modifications'
      'STATUS-ONLY' = 'Test 3: Status=Pending only'
      'STATUS-OVERRIDE' = 'Test 4: Status + Override=Block'
      'EMPTY-SOURCES' = 'Test 5: Empty sources'
      'NULL-TABLE' = 'Test 6: m_table=nullptr (V18 config)'
    }

    foreach ($key in $summary.Keys) {
      $result = if ($testResults.ContainsKey($key)) { $testResults[$key] } else { 'NOT RUN' }
      $color = switch ($result) {
        'SUCCESS' { 'Green' }
        'CRASHED' { 'Red' }
        default { 'Gray' }
      }
      $icon = switch ($result) {
        'SUCCESS' { '✅' }
        'CRASHED' { '❌' }
        default { '⏸️' }
      }
      Write-Host "$icon $($summary[$key]) : $result" -ForegroundColor $color
    }

    Write-Host "`n📊 ANALYSIS:" -ForegroundColor Cyan
    Write-Host "═══════════" -ForegroundColor Cyan

    if ($testResults['REAL-FACE'] -eq 'CRASHED') {
      Write-Host "⚠️  Real face load() crashed - load() machinery itself may be broken" -ForegroundColor Red
    } elseif ($testResults['REAL-FACE'] -eq 'SUCCESS') {
      Write-Host "✅ Real face load() works - machinery is functional" -ForegroundColor Green

      if ($testResults['RECLAIMED-NOMOD'] -eq 'CRASHED') {
        Write-Host "⚠️  Reclaimed face crashes - the reclaim itself is the problem" -ForegroundColor Yellow
      } elseif ($testResults['RECLAIMED-NOMOD'] -eq 'SUCCESS') {
        Write-Host "✅ Reclaimed face works - reclaim is not the problem" -ForegroundColor Green

        if ($testResults['STATUS-ONLY'] -eq 'CRASHED') {
          Write-Host "⚠️  Status=Pending causes crash - status field is the problem" -ForegroundColor Yellow
        } elseif ($testResults['STATUS-OVERRIDE'] -eq 'CRASHED') {
          Write-Host "⚠️  Override=Block causes crash - override field is the problem" -ForegroundColor Yellow
        } elseif ($testResults['EMPTY-SOURCES'] -eq 'CRASHED') {
          Write-Host "⚠️  Empty sources causes crash - sources vector is the problem" -ForegroundColor Yellow
        } elseif ($testResults['NULL-TABLE'] -eq 'CRASHED') {
          Write-Host "⚠️  m_table=nullptr causes crash - table pointer is the problem" -ForegroundColor Yellow
        }
      }
    }

    Write-Host "`n"
    return
  }

  # ==== ERROR markers ====
  if ($msg -match '^ERR-(.+)$') {
    $error = $Matches[1]
    Write-Host "[$t] ❌ V18B ERROR: $error" -ForegroundColor Red
    return
  }

  if ($msg -match '^SKIP-(.+)$') {
    $reason = $Matches[1]
    Write-Host "[$t] ⏭️  V18B SKIP: $reason" -ForegroundColor Yellow
    return
  }

  # ==== OTHER markers (show in gray) ====
  Write-Host "[$t] $msg" -ForegroundColor Gray
}
