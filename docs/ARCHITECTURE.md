
---

## docs/ARCHITECTURE.md


# HaleDistrict Architecture (HD1.0)

This document describes the HaleDistrict HD1.0 architecture at a level that allows an administrator to understand the lab quickly and operate it safely.

---

## Goals

- Practice Windows district-style infrastructure operations:
  - AD DS / DNS / DHCP basics
  - File services and permissions
  - GPO baselines and testing
  - Repeatable scripting + logging
  - Controlled change management (Git)

---

## Primary nodes

### SurfaceBook (host workstation)
**Role:** Authoring + version control  
**Repo location:** `C:\Projects\HaleDistrict`

Responsibilities:
- Edit scripts and docs
- Commit and tag versions
- Push to GitHub

### HALE-DC01 (Windows Server Domain Controller VM)
**Role:** Execution + evidence  
**Execution path:** `C:\HaleDistrict\Scripts`  
**Evidence path:** `C:\HaleDistrict\Logs`

Rules:
- No Git repo on DC01
- No primary authoring on DC01
- DC01 runs only validated scripts copied from the SurfaceBook repo

---

## “One-way flow” model

1. Author scripts on SurfaceBook in the Git repo  
2. Commit changes with a meaningful message  
3. Tag release versions when validated  
4. Copy validated script(s) to DC01 execution folder  
5. Run scripts on DC01 and store logs as evidence

This ensures the DC remains stable and reproducible.

---

## Folder conventions

### SurfaceBook (Source of Truth)
- `C:\Projects\HaleDistrict\` – Git repository root
  - `Scripts\HealthCheck\` – health check scripts
  - `Scripts\Provisioning\` – user provisioning scripts
  - `Config\` – CSV templates and configuration files
  - `docs\` – technical documentation
  - `runbooks\` – operational procedures

### DC01 (Execution + Evidence)
- `C:\HaleDistrict\Scripts\` – scripts copied for execution
- `C:\HaleDistrict\Logs\` – script logs and evidence output

Optional future:
- `C:\HaleDistrict\Proof\` – periodic snapshots (dcdiag, scope summaries, etc.)
- `C:\_HD_Quarantine\YYYY-MM-DD\` – safe quarantine for legacy artifacts (no deletes)

---

## Versioning policy

- Commits represent atomic, explainable changes.
- Tags represent validated milestones (e.g., scripts executed successfully on DC01).
- The tag’s meaning must match reality (i.e., tag points to the commit containing the validated artifact).

---

## Security / safety policy (HD lab)

- Prefer “read-only” checks by default.
- Any write/change operations must:
  - Log intent and result
  - Support `-WhatIf` or a dry-run mode when feasible
  - Be idempotent where possible (safe re-runs)
