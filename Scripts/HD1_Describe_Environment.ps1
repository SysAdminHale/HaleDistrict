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
  [string]$ScriptVersion  = "0.1.0"
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
      error = $true
      label = $Label
      message = $_.Exception.Message
    }
  }
}

function Test-Paths {
  param([Parameter(Mandatory)] [string[]]$Paths)
  $results = foreach ($p in $Paths) {
    [pscustomobject]@{
      path   = $p
      exists = (Test-Path -LiteralPath $p)
    }
  }
  return $results
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

  system = [ordered]@{}
  network = [ordered]@{}
  roles_features = [ordered]@{}
  ad = [ordered]@{}
  dns = [ordered]@{}
  dhcp = [ordered]@{}
  storage = [ordered]@{}
  services = [ordered]@{}
  paths = [ordered]@{}
  repo = [ordered]@{}
  health_summary = [ordered]@{}
}

# --- System
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

$report.system.os = [ordered]@{
  caption        = $os.Caption
  version        = $os.Version
  build_number   = $os.BuildNumber
  install_date   = ($os.InstallDate).ToString("o")
  last_boot      = ($os.LastBootUpTime).ToString("o")
}
$report.system.hardware = [ordered]@{
  manufacturer   = $cs.Manufacturer
  model          = $cs.Model
  cpu_count      = $cs.NumberOfProcessors
  logical_cpu    = $cs.NumberOfLogicalProcessors
  ram_gb         = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
  bios_serial    = $bios.SerialNumber
}

# --- Network
$netCfg = Get-NetIPConfiguration
$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4

$report.network.ip_configuration = $netCfg | ForEach-Object {
  [pscustomobject]@{
    interface_alias = $_.InterfaceAlias
    ipv4_address    = ($_.IPv4Address | ForEach-Object { $_.IPv4Address }) -join ", "
    ipv4_gateway    = ($_.IPv4DefaultGateway | ForEa
