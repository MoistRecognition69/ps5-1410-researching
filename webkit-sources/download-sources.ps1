# Download Sony PS5 WebKit Source Archives
# For firmware 14.10 research

$ErrorActionPreference = "Stop"

Write-Host "PS5 WebKit Source Downloader" -ForegroundColor Cyan
Write-Host "============================`n" -ForegroundColor Cyan

$webkitDir = $PSScriptRoot
if (-not $webkitDir) {
    $webkitDir = Get-Location
}

# URLs
$webkit1400Url = "https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit_1400.zip"
$webkit1200Url = "https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit-1200.zip"

$webkit1400Path = Join-Path $webkitDir "WebKit_1400.zip"
$webkit1200Path = Join-Path $webkitDir "WebKit-1200.zip"

# Download WebKit_1400.zip (for 14.10)
if (Test-Path $webkit1400Path) {
    Write-Host "[SKIP] WebKit_1400.zip already exists" -ForegroundColor Yellow
} else {
    Write-Host "[DOWNLOAD] WebKit_1400.zip (for firmware 14.00+)..." -ForegroundColor Green
    Write-Host "  URL: $webkit1400Url" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $webkit1400Url -OutFile $webkit1400Path -UseBasicParsing
        $size = (Get-Item $webkit1400Path).Length / 1MB
        Write-Host "  Downloaded: $([math]::Round($size, 2)) MB" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Download WebKit-1200.zip (for comparison)
if (Test-Path $webkit1200Path) {
    Write-Host "[SKIP] WebKit-1200.zip already exists" -ForegroundColor Yellow
} else {
    Write-Host "`n[DOWNLOAD] WebKit-1200.zip (for comparison)..." -ForegroundColor Green
    Write-Host "  URL: $webkit1200Url" -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $webkit1200Url -OutFile $webkit1200Path -UseBasicParsing
        $size = (Get-Item $webkit1200Path).Length / 1MB
        Write-Host "  Downloaded: $([math]::Round($size, 2)) MB" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Verify hashes
Write-Host "`n[VERIFY] Computing SHA-256 hashes..." -ForegroundColor Cyan

$hash1400 = (Get-FileHash -Algorithm SHA256 $webkit1400Path).Hash
$hash1200 = (Get-FileHash -Algorithm SHA256 $webkit1200Path).Hash

Write-Host "`nWebKit_1400.zip SHA-256:" -ForegroundColor Yellow
Write-Host "  $hash1400" -ForegroundColor White
Write-Host "`nWebKit-1200.zip SHA-256:" -ForegroundColor Yellow
Write-Host "  $hash1200" -ForegroundColor White

# Save hashes to file
$hashFile = Join-Path $webkitDir "SHA256.txt"
@"
WebKit Source Archive Hashes
Downloaded: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

WebKit_1400.zip (for PS5 firmware 14.00+)
SHA-256: $hash1400
Size: $((Get-Item $webkit1400Path).Length) bytes

WebKit-1200.zip (for PS5 firmware 12.00-12.60)
SHA-256: $hash1200
Size: $((Get-Item $webkit1200Path).Length) bytes
"@ | Out-File -FilePath $hashFile -Encoding UTF8

Write-Host "`n[SAVED] Hashes written to SHA256.txt" -ForegroundColor Green

Write-Host "`n[DONE] Download complete!" -ForegroundColor Cyan
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Extract archives: Expand-Archive -Path WebKit_1400.zip -DestinationPath WebKit_1400" -ForegroundColor Gray
Write-Host "  2. Examine Source/WebCore/css/CSSFontFace.cpp" -ForegroundColor Gray
Write-Host "  3. Examine Source/WTF/wtf/WeakHashSet.h" -ForegroundColor Gray
Write-Host "  4. Compare implementations between versions" -ForegroundColor Gray
