# run-v18b.ps1 — Launch V18B dispatch test with watcher
# Starts host.py, auto_continue.py, and scan-watch-v18.ps1

$ErrorActionPreference = "Stop"

Write-Host "V18B Dispatch Test Launcher" -ForegroundColor Cyan
Write-Host "===========================`n" -ForegroundColor Cyan

$scriptDir = $PSScriptRoot

# Check if host.py is already running
$hostRunning = Get-CimInstance Win32_Process -Filter "name='python.exe'" | Where-Object {$_.CommandLine -like "*host.py*"}

if ($hostRunning) {
    Write-Host "[SKIP] host.py already running (PID $($hostRunning.ProcessId))" -ForegroundColor Yellow
} else {
    Write-Host "[START] Starting host.py..." -ForegroundColor Green
    $env:PYTHONIOENCODING="utf-8"
    Start-Process python -ArgumentList "host.py" -WorkingDirectory $scriptDir -RedirectStandardOutput "$scriptDir\host-console-v18b.log" -RedirectStandardError "$scriptDir\host-error-v18b.log"
    Start-Sleep -Seconds 2
}

# Check if auto_continue.py is already running
$autoRunning = Get-CimInstance Win32_Process -Filter "name='python.exe'" | Where-Object {$_.CommandLine -like "*auto_continue.py*"}

if ($autoRunning) {
    Write-Host "[SKIP] auto_continue.py already running (PID $($autoRunning.ProcessId))" -ForegroundColor Yellow
} else {
    Write-Host "[START] Starting auto_continue.py..." -ForegroundColor Green
    Start-Process python -ArgumentList "auto_continue.py" -WorkingDirectory $scriptDir -RedirectStandardOutput "$scriptDir\auto-continue-v18b.log" -RedirectStandardError "$scriptDir\auto-continue-error-v18b.log"
    Start-Sleep -Seconds 1
}

Write-Host "`n[READY] All services started!" -ForegroundColor Green
Write-Host "`nPS5 Instructions:" -ForegroundColor Yellow
Write-Host "  1. Reboot PS5 (if memory warning)" -ForegroundColor Gray
Write-Host "  2. Close and reopen Settings → User's Guide" -ForegroundColor Gray
Write-Host "  3. Watch this window for V18B test results`n" -ForegroundColor Gray

Write-Host "Starting V18B watcher...`n" -ForegroundColor Cyan

# Start the watcher (this blocks)
& "$scriptDir\scan-watch-v18.ps1"
