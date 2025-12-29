<# 
HALEDISTRICT HD1.0 - Health Check
Script:     HD1_HealthCheck.ps1
Version:    1.0
Author:     Dave Hale
Date:       2025-12-28
Purpose:    Domain-core diagnostics (Checks 1–10) with PASS/WARN/FAIL + summary + logs
Notes:      Read-only. Safe to run repeatedly. Designed for future scheduling/alerting.
#>

[CmdletBinding()]
param(
    [switch]$NoBanner,     # Suppress the big "starting..." header
    [switch]$SummaryOnly,  # Only show summary at the end (still logs everything)
    [switch]$FailOnly,     # Only show FAIL (and WARN) lines to console
    [string]$LogDir = "C:\HaleDistrict\Logs"
)


# ============================================================
# HALEDISTRICT HD1.0 - Quick Health Check v1
# Date: 2025-12-28
# Purpose: Core services + simple logging (baseline script)
# ============================================================

$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$LogFile   = Join-Path $LogDir ("HD1_HealthCheck_{0}.log" -f $Timestamp)

# Ensure log folder exists
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# Result counters (script scope)
$script:PassCount = 0
$script:WarnCount = 0
$script:FailCount = 0

function Write-Result {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet("PASS","WARN","FAIL")][string]$Status,
        [string]$Details = ""
    )

    # Update counters
    switch ($Status) {
        "PASS" { $script:PassCount++ }
        "WARN" { $script:WarnCount++ }
        "FAIL" { $script:FailCount++ }
    }

    $line = "{0,-30} {1,-5} {2}" -f $Check, $Status, $Details

    # Always log
    Add-Content -Path $LogFile -Value $line

    # Console output logic
    if (-not $SummaryOnly) {
        if ($FailOnly) {
            if ($Status -ne "PASS") {
                Write-Host $line
            }
        }
        else {
            Write-Host $line
        }
    }
}


"HD1.0 Health Check started at $(Get-Date)" | Out-File -FilePath $LogFile -Encoding UTF8
"Log file: $LogFile" | Add-Content -Path $LogFile

Write-Host ""
Write-Host "HD1.0 Health Check - starting..."
Write-Host ""

# ============================================================
# CHECK 1: Core Services Running
# ============================================================

$Services = @(
    @{ Display="AD DS (NTDS)"; Name="NTDS" },
    @{ Display="DNS Server";   Name="DNS" },
    @{ Display="DHCP Server";  Name="DHCPServer" },
    @{ Display="File Server";  Name="LanmanServer" }
)

foreach ($svc in $Services) {
    try {
        $s = Get-Service -Name $svc.Name -ErrorAction Stop

        if ($s.Status -eq "Running") {
            Write-Result -Check $svc.Display -Status "PASS" -Details "Running"
        }
        else {
            Write-Result -Check $svc.Display -Status "FAIL" -Details ("Status={0}" -f $s.Status)
        }
    }
    catch {
        Write-Result -Check $svc.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 2: Required Shares Exist (UNC reachable)
# ============================================================

$Shares = @(
    @{ Display="Share: Students$";      Path="\\HALE-DC01\Students$" },
    @{ Display="Share: Teachers$";      Path="\\HALE-DC01\Teachers$" },
    @{ Display="Share: TeacherHomes$";  Path="\\HALE-DC01\TeacherHomes$" }
)


foreach ($sh in $Shares) {
    try {
        if (Test-Path -Path $sh.Path) {
            Write-Result -Check $sh.Display -Status "PASS" -Details $sh.Path
        }
        else {
            Write-Result -Check $sh.Display -Status "FAIL" -Details ("Not found: {0}" -f $sh.Path)
        }
    }
    catch {
        Write-Result -Check $sh.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 3: Share Backend Paths Exist (Local filesystem)
# ============================================================

$BackendPaths = @(
    @{ Display="Backend: Students";     Path="C:\Shares\Students" },
    @{ Display="Backend: Teachers";     Path="C:\Shares\Teachers" },
    @{ Display="Backend: TeacherHomes"; Path="C:\Shares\TeacherHomes" }
)

foreach ($bp in $BackendPaths) {
    try {
        if (Test-Path -Path $bp.Path) {
            Write-Result -Check $bp.Display -Status "PASS" -Details $bp.Path
        }
        else {
            Write-Result -Check $bp.Display -Status "FAIL" -Details ("Not found: {0}" -f $bp.Path)
        }
    }
    catch {
        Write-Result -Check $bp.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 4: Folder Redirection Target Paths Exist
# ============================================================

$RedirectionPaths = @(
    @{ Display="Redirection: Students";  Path="C:\Shares\Redirected\Students" },
    @{ Display="Redirection: Teachers";  Path="C:\Shares\Redirected\Teachers" }
)

foreach ($rp in $RedirectionPaths) {
    try {
        if (Test-Path -Path $rp.Path) {
            Write-Result -Check $rp.Display -Status "PASS" -Details $rp.Path
        }
        else {
            Write-Result -Check $rp.Display -Status "FAIL" -Details ("Not found: {0}" -f $rp.Path)
        }
    }
    catch {
        Write-Result -Check $rp.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 5: Disk Space (C:)
# ============================================================

try {
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $sizeGB = [math]::Round($drive.Size / 1GB, 1)
    $freeGB = [math]::Round($drive.FreeSpace / 1GB, 1)
    $freePct = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)

    if ($freePct -ge 20) {
        Write-Result -Check "Disk: C:" -Status "PASS" -Details ("Free {0} GB ({1}%) of {2} GB" -f $freeGB, $freePct, $sizeGB)
    }
    elseif ($freePct -ge 10) {
        Write-Result -Check "Disk: C:" -Status "WARN" -Details ("Low space: Free {0} GB ({1}%) of {2} GB" -f $freeGB, $freePct, $sizeGB)
    }
    else {
        Write-Result -Check "Disk: C:" -Status "FAIL" -Details ("CRITICAL: Free {0} GB ({1}%) of {2} GB" -f $freeGB, $freePct, $sizeGB)
    }
}
catch {
    Write-Result -Check "Disk: C:" -Status "FAIL" -Details ($_.Exception.Message)
}

# ============================================================
# CHECK 6: SYSVOL and NETLOGON
# ============================================================

$SysvolChecks = @(
    @{ Display="SYSVOL: Backend"; Path="C:\Windows\SYSVOL\sysvol" },
    @{ Display="SYSVOL: Domain Folder"; Path="C:\Windows\SYSVOL\sysvol\haledistrict.local" },
    @{ Display="SYSVOL: UNC"; Path="\\HALE-DC01\SYSVOL" },
    @{ Display="NETLOGON: UNC"; Path="\\HALE-DC01\NETLOGON" }
)

foreach ($sv in $SysvolChecks) {
    try {
        if (Test-Path -Path $sv.Path) {
            Write-Result -Check $sv.Display -Status "PASS" -Details $sv.Path
        }
        else {
            Write-Result -Check $sv.Display -Status "FAIL" -Details ("Not found: {0}" -f $sv.Path)
        }
    }
    catch {
        Write-Result -Check $sv.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 7: DNS Resolution
# ============================================================

$DnsTests = @(
    @{ Display="DNS: Resolve DC Hostname"; Name="HALE-DC01" },
    @{ Display="DNS: Resolve Domain";      Name="haledistrict.local" },
    @{ Display="DNS: Resolve External";    Name="www.microsoft.com" }
)

foreach ($t in $DnsTests) {
    try {
        $res = Resolve-DnsName -Name $t.Name -ErrorAction Stop

        # Prefer A/AAAA answers for clean output if present
        $ips = $res |
            Where-Object { $_.Type -in @("A","AAAA") } |
            Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue

        if ($ips -and $ips.Count -gt 0) {
            Write-Result -Check $t.Display -Status "PASS" -Details ($ips -join ", ")
        }
        else {
            # Some records (like CNAME chains) may not return IPs in the first pass
            Write-Result -Check $t.Display -Status "PASS" -Details ("Resolved (no A/AAAA shown)")
        }
    }
    catch {
        Write-Result -Check $t.Display -Status "FAIL" -Details ($_.Exception.Message)
    }
}

# ============================================================
# CHECK 8: Active Directory Replication Health (repadmin)
# ============================================================

# 8A) replsummary (high-level)
try {
    $out = & repadmin /replsummary 2>&1 | Out-String

    if ($LASTEXITCODE -ne 0) {
        Write-Result -Check "AD Replication: replsummary" -Status "FAIL" -Details ($out.Trim() -split "`r?`n")[0]
    }
    elseif ($out -match '(?i)\b0\s+fails\b') {
        Write-Result -Check "AD Replication: replsummary" -Status "PASS" -Details "0 fails reported"
    }
    elseif ($out -match '(?i)no\s+replication\s+partners|no\s+inbound\s+neighbors|no\s+outbound\s+neighbors') {
        Write-Result -Check "AD Replication: replsummary" -Status "WARN" -Details "Single-DC environment (no replication partners)"
    }
    else {
        # If repadmin ran but output isn't clearly "0 fails", treat as WARN and log first line for context
        Write-Result -Check "AD Replication: replsummary" -Status "WARN" -Details ($out.Trim() -split "`r?`n")[0]
    }
}
catch {
    Write-Result -Check "AD Replication: replsummary" -Status "FAIL" -Details ($_.Exception.Message)
}

# 8B) showrepl (detail-level) - only meaningful if 2+ DCs exist
try {
    $dcCount = (Get-ADDomainController -Filter * | Measure-Object).Count

    if ($dcCount -lt 2) {
        Write-Result -Check "AD Replication: showrepl" -Status "WARN" -Details "Single-DC environment (showrepl not applicable)"
    }
    else {
        $out = & repadmin /showrepl 2>&1 | Out-String

        if ($LASTEXITCODE -ne 0) {
            Write-Result -Check "AD Replication: showrepl" -Status "FAIL" -Details ($out.Trim() -split "`r?`n")[0]
        }
        elseif ($out -match '(?i)Last\s+error:\s*(?!0\s+\(0x0\))') {
            # Any "Last error" that is NOT "0 (0x0)" is a real replication problem
            $bad = ($out -split "`r?`n") |
                Where-Object { $_ -match '(?i)Last\s+error:' -and $_ -notmatch '0\s+\(0x0\)' } |
                Select-Object -First 1
            Write-Result -Check "AD Replication: showrepl" -Status "FAIL" -Details ($bad.Trim())
        }
        else {
            Write-Result -Check "AD Replication: showrepl" -Status "PASS" -Details "No replication errors detected"
        }
    }
}
catch {
    Write-Result -Check "AD Replication: showrepl" -Status "FAIL" -Details ($_.Exception.Message)
}

# ============================================================
# CHECK 9: Time Sync / Kerberos Health
# ============================================================

# 9A) Windows Time service status
try {
    $svc = Get-Service -Name w32time -ErrorAction Stop
    if ($svc.Status -eq "Running") {
        Write-Result -Check "Time: w32time service" -Status "PASS" -Details "Running"
    }
    else {
        Write-Result -Check "Time: w32time service" -Status "FAIL" -Details ("Status = {0}" -f $svc.Status)
    }
}
catch {
    Write-Result -Check "Time: w32time service" -Status "FAIL" -Details ($_.Exception.Message)
}

# 9B) Time sync status (w32tm /query /status)
try {
    $statusOut = (& w32tm /query /status 2>&1) | Out-String

    if ($LASTEXITCODE -ne 0) {
        Write-Result -Check "Time: w32tm status" -Status "FAIL" -Details (($statusOut.Trim() -split "`r?`n")[0])
    }
    else {
        # Pull a few useful lines for the log/details
        $sourceLine = ($statusOut -split "`r?`n" | Where-Object { $_ -match '^Source:' } | Select-Object -First 1).Trim()
        $stratumLine = ($statusOut -split "`r?`n" | Where-Object { $_ -match '^Stratum:' } | Select-Object -First 1).Trim()
        $lastSyncLine = ($statusOut -split "`r?`n" | Where-Object { $_ -match '^Last Successful Sync Time:' } | Select-Object -First 1).Trim()

        $detail = @($sourceLine, $stratumLine, $lastSyncLine) -ne "" -join " | "
        if (-not $detail) { $detail = "Status queried successfully" }

        Write-Result -Check "Time: w32tm status" -Status "PASS" -Details $detail
    }
}
catch {
    Write-Result -Check "Time: w32tm status" -Status "FAIL" -Details ($_.Exception.Message)
}

# 9C) Time offset sanity (Kerberos is sensitive to drift)
# Default thresholds:
#   PASS: <= 60s
#   WARN: 61-300s
#   FAIL: > 300s
try {
    $tmOut = (& w32tm /stripchart /computer:localhost /samples:1 /dataonly 2>&1) | Out-String

    # Example line contains something like: " -00.0001234s"
    $m = [regex]::Match($tmOut, '([+-]\d+(\.\d+)?)s')
    if ($m.Success) {
        $offsetSec = [math]::Abs([double]$m.Groups[1].Value)

        if ($offsetSec -le 60) {
            Write-Result -Check "Time: offset" -Status "PASS" -Details ("Offset ≈ {0} sec" -f $offsetSec)
        }
        elseif ($offsetSec -le 300) {
            Write-Result -Check "Time: offset" -Status "WARN" -Details ("Offset ≈ {0} sec (Kerberos risk if drift grows)" -f $offsetSec)
        }
        else {
            Write-Result -Check "Time: offset" -Status "FAIL" -Details ("Offset ≈ {0} sec (Kerberos likely to fail)" -f $offsetSec)
        }
    }
    else {
        Write-Result -Check "Time: offset" -Status "WARN" -Details "Could not parse offset from w32tm stripchart output"
    }
}
catch {
    Write-Result -Check "Time: offset" -Status "FAIL" -Details ($_.Exception.Message)
}


# ============================================================
# SUMMARY
# ============================================================

$pass = ($script:Results | Where-Object Status -eq "PASS" | Measure-Object).Count
$warn = ($script:Results | Where-Object Status -eq "WARN" | Measure-Object).Count
$fail = ($script:Results | Where-Object Status -eq "FAIL" | Measure-Object).Count
$total = ($script:Results | Measure-Object).Count

Write-Host ""
Write-Host ("Summary: Total={0}  PASS={1}  WARN={2}  FAIL={3}" -f $total, $pass, $warn, $fail)
Add-Content -Path $LogFile -Value ""
Add-Content -Path $LogFile -Value ("Summary: Total={0}  PASS={1}  WARN={2}  FAIL={3}" -f $total, $pass, $warn, $fail)

# ============================================================
# CHECK 10: GPO Health (Inventory + SYSVOL-backed GPO folders)
# ============================================================

# 10A) Can we query GPO inventory?
try {
    Import-Module GroupPolicy -ErrorAction Stop

    $allGpos = Get-GPO -All -ErrorAction Stop
    $gpoCount = ($allGpos | Measure-Object).Count

    if ($gpoCount -gt 0) {
        Write-Result -Check "GPO: Inventory" -Status "PASS" -Details ("Found {0} GPO(s)" -f $gpoCount)
    }
    else {
        Write-Result -Check "GPO: Inventory" -Status "WARN" -Details "No GPOs returned (unexpected in most domains)"
    }
}
catch {
    Write-Result -Check "GPO: Inventory" -Status "FAIL" -Details ($_.Exception.Message)
    $allGpos = @()  # prevent follow-on errors
}

# 10B) Default GPOs present?
try {
    if ($allGpos.Count -gt 0) {
        $names = $allGpos.DisplayName
        $missing = @()

        if ($names -notcontains "Default Domain Policy") { $missing += "Default Domain Policy" }
        if ($names -notcontains "Default Domain Controllers Policy") { $missing += "Default Domain Controllers Policy" }

        if ($missing.Count -eq 0) {
            Write-Result -Check "GPO: Default policies present" -Status "PASS" -Details "Default Domain Policy + Default Domain Controllers Policy found"
        }
        else {
            Write-Result -Check "GPO: Default policies present" -Status "WARN" -Details ("Missing: {0}" -f ($missing -join ", "))
        }
    }
    else {
        Write-Result -Check "GPO: Default policies present" -Status "WARN" -Details "Skipped (GPO inventory unavailable)"
    }
}
catch {
    Write-Result -Check "GPO: Default policies present" -Status "FAIL" -Details ($_.Exception.Message)
}

# 10C) SYSVOL-backed GPO folder + GPT.INI exists for each GPO
try {
    if ($allGpos.Count -gt 0) {
        $domain = $env:USERDNSDOMAIN
        $sysvolRoot = "\\$domain\SYSVOL\$domain\Policies"

        foreach ($gpo in $allGpos) {
            $guid = $gpo.Id.ToString("B")  # {GUID}
            $gpoPath = Join-Path $sysvolRoot $guid
            $gptIni = Join-Path $gpoPath "GPT.INI"

            if (-not (Test-Path -Path $gpoPath)) {
                Write-Result -Check ("GPO SYSVOL: {0}" -f $gpo.DisplayName) -Status "FAIL" -Details ("Missing folder: {0}" -f $gpoPath)
                continue
            }

            if (-not (Test-Path -Path $gptIni)) {
                Write-Result -Check ("GPO SYSVOL: {0}" -f $gpo.DisplayName) -Status "FAIL" -Details ("Missing GPT.INI: {0}" -f $gptIni)
                continue
            }

            Write-Result -Check ("GPO SYSVOL: {0}" -f $gpo.DisplayName) -Status "PASS" -Details $gpoPath
        }
    }
    else {
        Write-Result -Check "GPO SYSVOL: Policies folder" -Status "WARN" -Details "Skipped (GPO inventory unavailable)"
    }
}
catch {
    Write-Result -Check "GPO SYSVOL: Policies folder" -Status "FAIL" -Details ($_.Exception.Message)
}


# =========================================================
# SUMMARY FOOTER
# =========================================================

$total = $script:PassCount + $script:WarnCount + $script:FailCount
$summaryLine = "Summary: Total=$total PASS=$($script:PassCount) WARN=$($script:WarnCount) FAIL=$($script:FailCount)"

# Always log summary
Add-Content -Path $LogFile -Value $summaryLine

# Console output (respect flags)
if (-not $SummaryOnly) {
    Write-Host ""
    Write-Host $summaryLine
}

Write-Host ""
Write-Host "Done. Log: $LogFile"

