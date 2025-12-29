# Runbook: Describe Environment (HD1.0)

## Purpose
Collects a read-only inventory of the HaleDistrict domain controller environment
(OS, AD DS, DNS, DHCP, services, paths) and writes timestamped evidence artifacts
to disk.

This script performs **no destructive actions**.

---

## Source of Truth
- Script authored and versioned on: **SurfaceBook**
- Repository: `C:\Projects\HaleDistrict`
- Script path: `Scripts\HD1_Describe_Environment.ps1`

---

## Deployment (SurfaceBook → DC01)

Run on the **SurfaceBook**:

```powershell
Copy-Item `
  "C:\Projects\HaleDistrict\Scripts\HD1_Describe_Environment.ps1" `
  "\\HALE-DC01\C$\HaleDistrict\Scripts\HD1_Describe_Environment.ps1" `
  -Force
