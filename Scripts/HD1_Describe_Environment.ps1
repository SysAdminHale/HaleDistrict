<#
.SYNOPSIS
  HaleDistrict (HD1.0) - Environment inventory report (read-only)

.DESCRIPTION
  Collects system, AD DS, DNS, DHCP, storage, services, and key-path presence.
  Writes timestamped evidence artifacts to C:\HaleDistrict\Logs\HD1_Describe_Environment\.

  Authoring/Versioning: SurfaceBook (Source of Truth)
  Execution/Evidence:    HALE-DC01

.NOTES
  Safe: no destructive actions. Read-only collection only.
#>

[CmdletBinding()]
param(
  [string]$ExpectedDomain = "HALEDISTRICT.local",
  [string]$ExpectedDC     = "HALE-DC01",
  [string]$LogRoot        = "C:\HaleDistrict\Logs\HD1_Describe_Environment",
  [string]$RepoRootOnDC    = "C:\HaleDistrict",
  [string]$ScriptVersion  = "0.1.1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-TimestampFolder {
  param([Parameter(Mandatory)] [string]$Root)
  $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
  $outDir = Join-Path $Root $ts
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null
  return $outDir
}

function Safe-ModuleImport {
  param([Parameter(Mandatory)] [string]$Name)
  try {
    if (Get-Module -ListAvailable -Name $Name) {
      Import-Module $Name -ErrorAction Stop | Out-Null
      return $true
    }
  } catch {}
  return $false
}

function Safe-Command {
  param(
    [Parameter(Mandatory)] [scriptblock]$Block,
    [string]$Label = "Command"
  )
  try {
    return & $Block
  } catch {
    return [pscustomobject]@{
      error   = $true
      label   = $Label
      message = $_.Exception.Message
    }
  }
}

function Test-Paths {
  param([Parameter(Mandatory)] [string[]]$Paths)
  foreach ($p in $Paths) {
    [pscustomobject]@{
      path   = $p
      exists = (Test-Path -LiteralPath $p)
    }
  }
}

# --- Begin run
$OutputDir = New-TimestampFolder -Root $LogRoot
$TranscriptPath = Join-Path $OutputDir "transcript.txt"
Start-Transcript -Path $TranscriptPath -Force | Out-Null

$report = [ordered]@{
  meta = [ordered]@{
    project        = "HaleDistrict (HD1.0)"
    script         = "HD1_Describe_Environment.ps1"
    version        = $ScriptVersion
    run_utc        = (Get-Date).ToUniversalTime().ToString("o")
    run_local      = (Get-Date).ToString("o")
    expected       = [ordered]@{
      domain = $ExpectedDomain
      dc     = $ExpectedDC
    }
    execution_host = $env:COMPUTERNAME
    user           = "$env:USERDOMAIN\$env:USERNAME"
  }

  system         = [ordered]@{}
  network        = [ordered]@{}
  roles_features = [ordered]@{}
  ad             = [ordered]@{}
  dns            = [ordered]@{}
  dhcp           = [ordered]@{}
  storage        = [ordered]@{}
  services       = [ordered]@{}
  paths          = [ordered]@{}
  repo           = [ordered]@{}
  health_summary = [ordered]@{}
}

# --- System
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

$report.system.os = [ordered]@{
  caption      = $os.Caption
  version      = $os.Version
  build_number = $os.BuildNumber
  install_date = ($os.InstallDate).ToString("o")
  last_boot    = ($os.LastBootUpTime).ToString("o")
}
$report.system.hardware = [ordered]@{
  manufacturer = $cs.Manufacturer
  model        = $cs.Model
  cpu_count    = $cs.NumberOfProcessors
  logical_cpu  = $cs.NumberOfLogicalProcessors
  ram_gb       = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
  bios_serial  = $bios.SerialNumber
}

# --- Network
$netCfg     = Get-NetIPConfiguration
$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4

$report.network.ip_configuration = $netCfg | ForEach-Object {
  $dnsSuffix = $null
  if ($_.PSObject.Properties.Name -contains "DnsSuffix") {
    $dnsSuffix = $_.DnsSuffix
  }

  [pscustomobject]@{
    interface_alias = $_.InterfaceAlias
    ipv4_address    = (($_.IPv4Address | ForEach-Object { $_.IPv4Address }) -join ", ")
    ipv4_gateway    = (($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ", ")
    dns_suffix      = $dnsSuffix
  }
}

$report.network.dns_servers = $dnsServers | ForEach-Object {
  [pscustomobject]@{
    interfacenamee        = $_.InterfaceAlias
    server_addresses = ($_.ServerAddresses -join ", ")
  }
}

# --- Roles / Features
$report.roles_features.installed_features = Safe-Command -Label "Get-WindowsFeature" -Block {
  if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Get-WindowsFeature | Where-Object { $_.Installed } |
      Select-Object Name, DisplayName, InstallState
  } else {
    [pscustomobject]@{ note = "Get-WindowsFeature not available in this shell." }
  }
}

# --- AD
$adOk = Safe-ModuleImport -Name "ActiveDirectory"
$report.ad.module_present = $adOk

if ($adOk) {
  $report.ad.domain = Safe-Command -Label "Get-ADDomain" -Block { Get-ADDomain | Select-Object * }
  $report.ad.forest = Safe-Command -Label "Get-ADForest" -Block { Get-ADForest | Select-Object * }

  $report.ad.domain_controllers = Safe-Command -Label "Get-ADDomainController" -Block {
    Get-ADDomainController -Filter * |
      Select-Object HostName, Site, IPv4Address, OperatingSystem, IsGlobalCatalog
  }
} else {
  $report.ad.note = "ActiveDirectory module not available."
}

# --- DNS (Server)
$dnsOk = Safe-ModuleImport -Name "DnsServer"
$report.dns.module_present = $dnsOk

if ($dnsOk) {
  $report.dns.forwarders = Safe-Command -Label "Get-DnsServerForwarder" -Block {
    Get-DnsServerForwarder | Select-Object IPAddress, Timeout, UseRootHint
  }
  $report.dns.zones = Safe-Command -Label "Get-DnsServerZone" -Block {
    Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone
  }
} else {
  $report.dns.note = "DnsServer module not available."
}

# --- DHCP (Server)
$dhcpOk = Safe-ModuleImport -Name "DhcpServer"
$report.dhcp.module_present = $dhcpOk

$report.dhcp.service = Safe-Command -Label "DHCP Service" -Block {
  Get-Service -Name "dhcpserver" -ErrorAction Stop | Select-Object Name, Status, StartType
}

if ($dhcpOk) {
  $report.dhcp.scopes_v4 = Safe-Command -Label "Get-DhcpServerv4Scope" -Block {
    Get-DhcpServerv4Scope | Select-Object ScopeId, Name, State, StartRange, EndRange, SubnetMask
  }
  $report.dhcp.options_v4 = Safe-Command -Label "Get-DhcpServerv4OptionValue" -Block {
    Get-DhcpServerv4OptionValue | Select-Object OptionId, Name, Value
  }
} else {
  $report.dhcp.note = "DhcpServer module not available."
}

# --- Storage
$report.storage.volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size
$report.storage.disks   = Get-Disk   | Select-Object Number, FriendlyName, SerialNumber, PartitionStyle, Size, HealthStatus, OperationalStatus

# --- Services (key ones)
$keyServices = @("NTDS","DNS","Netlogon","KDC","W32Time","LanmanServer","LanmanWorkstation","dhcpserver")
$report.services.key = foreach ($svc in $keyServices) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($null -ne $s) {
    [pscustomobject]@{ name=$s.Name; status=$s.Status; start_type=$s.StartType }
  } else {
    [pscustomobject]@{ name=$svc; status="NOT_FOUND"; start_type=$null }
  }
}

# --- Paths (evidence of expected structure)
$expectedPaths = @(
  "C:\HaleDistrict",
  "C:\HaleDistrict\Scripts",
  "C:\HaleDistrict\Logs",
  "C:\Shares",
  "C:\Shares\Students",
  "C:\Shares\Teachers"
)
$report.paths.expected = Test-Paths -Paths $expectedPaths

# --- Repo status on DC (optional evidence)
if (Test-Path -LiteralPath (Join-Path $RepoRootOnDC ".git")) {
  Push-Location $RepoRootOnDC
  $report.repo.present = $true
  $report.repo.branch  = Safe-Command -Label "git branch" -Block { (git rev-parse --abbrev-ref HEAD) }
  $report.repo.commit  = Safe-Command -Label "git rev-parse" -Block { (git rev-parse HEAD) }
  $report.repo.status  = Safe-Command -Label "git status" -Block { (git status --porcelain) }
  Pop-Location
} else {
  $report.repo.present = $false
  $report.repo.note    = "No .git folder found at RepoRootOnDC; skipping git evidence."
}

# --- Health summary
$domainDetected = $null
if ($adOk -and $report.ad.domain -and -not $report.ad.domain.error) {
  $domainDetected = $report.ad.domain.DNSRoot
}

$report.health_summary = [ordered]@{
  dc_name_matches_expected = ($env:COMPUTERNAME -ieq $ExpectedDC)
  domain_matches_expected  = ($null -ne $domainDetected -and $domainDetected -ieq $ExpectedDomain)
  key_services_all_running = (@($report.services.key | Where-Object { $_.status -ne "Running" -and $_.status -ne "NOT_FOUND" }).Count -eq 0)
  hale_paths_present       = (@($report.paths.expected | Where-Object { $_.exists -eq $false }).Count -eq 0)
}

# --- Write artifacts
$jsonPath = Join-Path $OutputDir "report.json"
$txtPath  = Join-Path $OutputDir "report.txt"
$mdPath   = Join-Path $OutputDir "report.md"

($report | ConvertTo-Json -Depth 8) | Out-File -FilePath $jsonPath -Encoding utf8

@"
HaleDistrict (HD1.0) - Environment Report
========================================
Run (local): $($report.meta.run_local)
Run (UTC):   $($report.meta.run_utc)

Expected:
- Domain: $ExpectedDomain
- DC:     $ExpectedDC

Detected:
- Host:   $($report.meta.execution_host)
- User:   $($report.meta.user)

OS:
- $($report.system.os.caption)
- Version: $($report.system.os.version)  Build: $($report.system.os.build_number)
- Last boot: $($report.system.os.last_boot)

Health Summary:
- DC name matches expected: $($report.health_summary.dc_name_matches_expected)
- Domain matches expected:  $($report.health_summary.domain_matches_expected)
- Key services running:     $($report.health_summary.key_services_all_running)
- Hale paths present:       $($report.health_summary.hale_paths_present)

Artifacts:
- $jsonPath
- $mdPath
- $TranscriptPath
"@ | Out-File -FilePath $txtPath -Encoding utf8

@"
# HaleDistrict (HD1.0) — Environment Report

**Run (local):** $($report.meta.run_local)  
**Run (UTC):** $($report.meta.run_utc)

## Expected
- **Domain:** $ExpectedDomain
- **DC:** $ExpectedDC

## Detected
- **Host:** $($report.meta.execution_host)
- **User:** $($report.meta.user)

## OS
- **Caption:** $($report.system.os.caption)
- **Version:** $($report.system.os.version)
- **Build:** $($report.system.os.build_number)
- **Last boot:** $($report.system.os.last_boot)

## Health summary
- DC name matches expected: **$($report.health_summary.dc_name_matches_expected)**
- Domain matches expected: **$($report.health_summary.domain_matches_expected)**
- Key services running: **$($report.health_summary.key_services_all_running)**
- Hale paths present: **$($report.health_summary.hale_paths_present)**

## Evidence artifacts
- `report.json`
- `report.txt`
- `transcript.txt`
"@ | Out-File -FilePath $mdPath -Encoding utf8

Stop-Transcript | Out-Null

Write-Host "DONE. Evidence folder:" -ForegroundColor Green
Write-Host "  $OutputDir" -ForegroundColor Green
Write-Host "Artifacts:" -ForegroundColor Green
Write-Host "  $jsonPath" -ForegroundColor Green
Write-Host "  $txtPath"  -ForegroundColor Green
Write-Host "  $mdPath"   -ForegroundColor Green
Write-Host "  $TranscriptPath" -ForegroundColor Green
