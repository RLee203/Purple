# Purple

Purple is a dual-mode Cardputer ADV firmware built for Red Team and Blue Team field workflows, combining wireless recon, RF visibility, GPS tools, IR/NFC utilities, and on-device analysis in a compact handheld platform.

## Highlights

- Red Team and Blue Team mode split
- WiFi and BLE monitoring / operations workflows
- CC1101 and nRF24 RF tooling
- GPS status, tracker, and wardriving tools
- IR and NFC utilities
- SD-backed saved captures and logs

## Repo Layout

- `src/` firmware source
- `data/` filesystem payload/data files
- `releases/` release-ready firmware artifacts
- `platformio.ini` PlatformIO build config

## Build

```powershell
& "$env:USERPROFILE\.platformio\penv\Scripts\platformio.exe" run
```

## Flash

Merged flash image:

- `releases/Purple-2026-05-21-final-release-merged.bin`

PlatformIO upload:

```powershell
& "$env:USERPROFILE\.platformio\penv\Scripts\platformio.exe" run --target upload --upload-port COM19
```
