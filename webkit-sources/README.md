# WebKit Source Archives

This directory should contain the official Sony PS5 WebKit source code archives.

## Download Instructions

Run the download script:

```powershell
.\download-sources.ps1
```

Or download manually from Sony's official site:

### For PS5 Firmware 14.10 (Current Target)
- **WebKit_1400.zip** (covers 14.00 and later)
- URL: https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit_1400.zip

### For Comparison
- **WebKit-1200.zip** (covers 12.00 - 12.60)
- URL: https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit-1200.zip

## Official Source Page

https://www.playstation.com/en-us/oss/ps5/webkit

## Verification

After downloading, verify the SHA-256 hashes:

```powershell
Get-FileHash -Algorithm SHA256 WebKit_1400.zip
Get-FileHash -Algorithm SHA256 WebKit-1200.zip
```

Record the hashes in this file for reproducibility:

```
WebKit_1400.zip SHA-256: [TODO: Record after download]
WebKit-1200.zip SHA-256: [TODO: Record after download]
```

## Extraction

Extract the relevant files for analysis:

```powershell
# Extract WebKit_1400.zip
Expand-Archive -Path WebKit_1400.zip -DestinationPath WebKit_1400

# Key files to examine:
# - Source/WebCore/css/CSSFontFace.cpp
# - Source/WTF/wtf/WeakHashSet.h
# - Source/WTF/wtf/Algorithms.h
# - Source/WTF/wtf/HashTable.h
# - PlayStation build configuration files
```

## Notes

- Both archives identify internally as **616.1.27.211.1** (same version string)
- WebKit-1200 has `virtual ~CSSFontFace();` while WebKit-1400 has non-virtual `~CSSFontFace();`
- Device measurements (no vtable on CSSFontFace) match WebKit-1400's non-virtual destructor
- WebKit_1400.zip is the leading candidate for the 14.10 console's actual source code

## License

WebKit is open source software with portions licensed under BSD and LGPL licenses.
See the archives for full license text.
