# Purple Feature Plan

This file is the working plan for features that should make Purple feel like its own firmware instead of a renamed CardputerOS build.

## Keep From CardputerOS

- modular source layout
- fast launcher navigation
- Cardputer hardware target
- PlatformIO build flow

## Change For Purple

- two primary modes: `Red Team` and `Blue Team`
- different default home experience
- different naming and visual identity
- only add modules we really plan to support
- shared capability families with different `Red` and `Blue` behaviors

## Mode Buckets

### Red Team

- active WiFi tooling
- active BLE tooling
- IR and payload delivery
- active CC1101 / nRF24 tooling
- field operator utilities

### Blue Team

- WiFi / BLE monitoring
- diagnostics
- logging
- CC1101 / nRF24 analysis
- incident response utilities

## Shared Capability Families

- WiFi: `Recon` on Red, `Monitor` on Blue
- BLE: `Ops` on Red, `Monitor` on Blue
- CC1101: `Ops` on Red, `Scanner` on Blue
- nRF24: `Ops` on Red, `Analyzer` on Blue
- Notes: `Field Notes` on Red, `Response Notes` on Blue
- Storage: `Files` on both
- Config: `Settings` on both

## Candidate First-Pass Apps

### Red Team

- WiFi Ops
- BLE Ops
- IR Toolkit
- Payloads
- CC1101 Ops
- nRF24 Ops
- RF Tools
- Field Notes
- Files
- Settings

### Blue Team

- WiFi Monitor
- BLE Monitor
- CC1101 Scan
- nRF Analyzer
- Alerts
- Logs
- Device Health
- Response Notes
- Files
- Settings

## Questions To Resolve

- which exact active vs passive actions should each shared capability family ship first?
- should both modes share one launcher style or have different colors and layouts?
- what are the must-have apps for version `0.1`?
