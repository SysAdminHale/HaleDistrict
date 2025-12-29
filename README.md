# HaleDistrict (HD1.0)

HaleDistrict is a virtual “school district” homelab built to practice real-world Windows infrastructure operations: Hyper-V, Windows Server domain services (AD DS/DNS/DHCP), file services, Group Policy, and repeatable automation via PowerShell.

This repo is the **Source of Truth** for all HaleDistrict scripts and documentation.

---

## Architecture contract (non-negotiable)

### SurfaceBook = Source of Truth
- Location: `C:\Projects\HaleDistrict`
- Responsibilities:
  - Authoring/editing scripts
  - Version control (Git)
  - Tags/releases
  - Pushing to GitHub

### DC01 (HALE-DC01) = Execution + Evidence
- Scripts execute from: `C:\HaleDistrict\Scripts`
- Logs are written to: `C:\HaleDistrict\Logs`
- Rule: **No primary editing and no Git authoring on DC01**

**One-way flow:**  
SurfaceBook (Git / versioned) → DC01 (execution / logs)

---

## Repository layout

- `Scripts/`  
  - `HealthCheck/` – health check scripts and related utilities  
  - `Provisioning/` – user provisioning automation scripts (CSV-driven)  
- `Config/` – input files (CSV templates, environment config)
- `docs/` – deeper technical documentation
- `runbooks/` – operational “how-to run” procedures

---

## Releases / tags

A Git tag represents a “frozen” validated state of the script set.

- `v1.0.0` – Validated `HD1_HealthCheck_v1.0` executed on DC01 and committed to this repo.

---

## Quick start: run HealthCheck on DC01

On DC01:

```powershell
PowerShell -NoProfile -ExecutionPolicy Bypass -File "C:\HaleDistrict\Scripts\HD1_HealthCheck_v1.0.ps1"
