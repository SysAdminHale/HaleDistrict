# Runbook: HealthCheck (HD1.0)

This runbook describes how to execute the HaleDistrict HealthCheck script on DC01 and where to find evidence output.

---

## Purpose

Verify basic domain controller health and confirm expected HaleDistrict execution and logging paths exist.

This script is intentionally read-only and safe to re-run.

---

## Preconditions

- Script exists on DC01 at:
  - `C:\HaleDistrict\Scripts\HD1_HealthCheck_v1.0.ps1`
- Logs directory exists:
  - `C:\HaleDistrict\Logs\`
- Script version matches a validated Git tag (e.g., `v1.0.0`)

---

## Run procedure (DC01)

1. Log in to **HALE-DC01**
2. Open **PowerShell as Administrator**
3. Run:

```powershell
PowerShell -NoProfile -ExecutionPolicy Bypass -File "C:\HaleDistrict\Scripts\HD1_HealthCheck_v1.0.ps1"
```
