<#
.SYNOPSIS
    Bulk-creates Entra Private Access (Global Secure Access) application segments
    for a list of RD Session Hosts read from a text/CSV file.

.DESCRIPTION
    Creates one ipApplicationSegment per host and protocol (TCP + UDP) on port 3389
    against an existing Global Secure Access enterprise application.

    The script is idempotent: existing segments are detected and skipped, so it can
    be re-run safely after adding hosts to the source file.

    API reference:
      POST /beta/applications/{appObjectId}/onPremisesPublishing/segmentsConfiguration/
           microsoft.graph.ipSegmentConfiguration/applicationSegments
      Body: destinationHost, destinationType (fqdn), ports (["3389-3389"]), protocol (tcp|udp)

.PARAMETER AppObjectId
    Object ID of the APP REGISTRATION behind the Global Secure Access application.
    Entra admin center > Identity > Applications > App registrations > <app> > Overview.
    NOTE: this is not the enterprise application's object ID.

.PARAMETER Path
    Path to the file containing one FQDN per line. A header line is optional and is
    ignored, as are blank lines, surrounding quotes and duplicates. Names are
    lower-cased before use. Anything that is not a valid FQDN is skipped and counted
    in a warning, so short names must be qualified before running.

    Example file content:

        rdsh01.contoso.com
        rdsh02.contoso.com
        rdsh03.contoso.com

    The host list can be generated from the deployment itself:

        (Get-RDServer -ConnectionBroker cb01.contoso.com |
            Where-Object { $_.Roles -contains 'RDS-RD-SERVER' }).Server |
            Set-Content .\RDP-hosts.csv

.PARAMETER ExtraHost
    Additional FQDNs to include, e.g. the RD Connection Broker client access name.

.PARAMETER Port
    TCP/UDP port to publish. Defaults to 3389.

.PARAMETER Protocol
    Protocols to create segments for. Defaults to both tcp and udp.

.PARAMETER ConnectionBroker
    Optional. FQDN of an RD Connection Broker. When supplied, the script compares the
    file contents against the session hosts actually registered in the RDS deployment
    and reports differences before making any change. Requires the RemoteDesktop module
    and is normally run from a management server, not from the machine running Graph.

.PARAMETER BackupPath
    Folder for the before/after segment exports. Defaults to the current directory.

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\RDP-hosts.csv' `
        -WhatIf

    Dry run. Shows which segments would be created without changing anything.
    Always start here.

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\RDP-hosts.csv' `
        -ExtraHost   'rdcb.contoso.com'

    Standard run. Creates TCP and UDP segments on port 3389 for every host in the
    file, plus the RD Connection Broker client access name.

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\RDP-hosts.csv' `
        -ExtraHost   'rdcb.contoso.com' `
        -ConnectionBroker 'cb01.contoso.com' `
        -WhatIf

    Dry run with a cross-check against the live RDS deployment. Reports session
    hosts present in the deployment but missing from the file, and entries in the
    file that are not session hosts. Requires the RemoteDesktop module (RSAT).

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\RDP-hosts.csv' `
        -Protocol    tcp

    TCP only. Use when UDP transport is disabled in the deployment or blocked on
    the path to the connector.

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\fileservers.txt' `
        -Port        445 `
        -Protocol    tcp `
        -BackupPath  'C:\Change\CHG0012345'

    Re-use for a different workload. Publishes SMB instead of RDP and writes the
    before/after snapshots into a change-record folder.

.EXAMPLE
    .\New-GsaRdsAppSegments.ps1 `
        -AppObjectId '00000000-0000-0000-0000-000000000000' `
        -Path        '.\RDP-hosts.csv' `
        -Verbose

    Adds per-host detail, including which segments were skipped because they
    already exist. The script is idempotent, so this is the normal way to
    re-run it after new session hosts have been added to the file.

.NOTES
    Required Entra role : Application Administrator or Global Secure Access Administrator
    Required scopes     : Application.ReadWrite.All, NetworkAccess.ReadWrite.All
    Required module     : Microsoft.Graph.Authentication
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]   $AppObjectId,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]   $Path,

    [string[]] $ExtraHost   = @(),

    [ValidateRange(1, 65535)]
    [int]      $Port        = 3389,

    [ValidateSet('tcp', 'udp')]
    [string[]] $Protocol    = @('tcp', 'udp'),

    [string]   $ConnectionBroker,

    [string]   $BackupPath  = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SegmentUri = "https://graph.microsoft.com/beta/applications/$AppObjectId" +
              '/onPremisesPublishing/segmentsConfiguration' +
              '/microsoft.graph.ipSegmentConfiguration/applicationSegments'

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

#region helpers -----------------------------------------------------------------

function Invoke-GraphWithRetry {
    <#  Wraps Invoke-MgGraphRequest with handling for HTTP 429 / 503.
        Graph throttles bulk writes; without this a 100+ segment run will
        fail part way through and leave the app half configured. #>
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Uri,
        [string] $Body,
        [int]    $MaxAttempts = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType 'application/json'
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        }
        catch {
            $status = $null
            try { $status = $_.Exception.Response.StatusCode.value__ } catch { }

            if ($status -in 429, 503, 504 -and $attempt -lt $MaxAttempts) {
                $wait = [math]::Pow(2, $attempt)
                Write-Verbose "HTTP $status - retry $attempt/$MaxAttempts in $wait s"
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Get-ExistingSegment {
    $all  = @()
    $uri  = $SegmentUri
    do {
        $page = Invoke-GraphWithRetry -Method GET -Uri $uri
        if ($page.value) { $all += $page.value }
        $uri = if ($page.PSObject.Properties.Name -contains '@odata.nextLink') { $page.'@odata.nextLink' } else { $null }
    } while ($uri)
    return $all
}

#endregion ----------------------------------------------------------------------

#region 1 - connect -------------------------------------------------------------

Write-Host "`n=== Entra Private Access - RDS application segments ===`n" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}

$ctx = $null
try { $ctx = Get-MgContext } catch { }

if (-not $ctx) {
    Write-Host 'Connecting to Microsoft Graph ...' -ForegroundColor Gray
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'NetworkAccess.ReadWrite.All' | Out-Null
    $ctx = Get-MgContext
}

$missingScope = @('Application.ReadWrite.All', 'NetworkAccess.ReadWrite.All') |
                Where-Object { $_ -notin $ctx.Scopes }
if ($missingScope) {
    throw "Current Graph session is missing scope(s): $($missingScope -join ', '). Run Disconnect-MgGraph and start again."
}

Write-Host "Connected as : $($ctx.Account)"
Write-Host "Tenant       : $($ctx.TenantId)`n"

#endregion ----------------------------------------------------------------------

#region 2 - read and normalise the host list ------------------------------------

$hosts = Get-Content -Path $Path |
         ForEach-Object { $_.Trim().Trim('"').ToLowerInvariant() } |
         Where-Object   { $_ -match '^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$' } |   # FQDN only, drops header and blanks
         Sort-Object -Unique

if ($ExtraHost) {
    $hosts += ($ExtraHost | ForEach-Object { $_.Trim().ToLowerInvariant() })
    $hosts  = $hosts | Sort-Object -Unique
}

if (-not $hosts) { throw "No valid FQDNs found in '$Path'." }

$skipped = (Get-Content -Path $Path | Where-Object { $_.Trim() }).Count - ($hosts.Count - $ExtraHost.Count)
if ($skipped -gt 0) {
    Write-Warning "$skipped line(s) in the source file were ignored (header, duplicates or not an FQDN)."
}

Write-Host "Hosts in scope : $($hosts.Count)"
Write-Host "Protocols      : $($Protocol -join ', ')"
Write-Host "Port           : $Port"
Write-Host "Target segments: $($hosts.Count * $Protocol.Count)`n"

$hosts | ForEach-Object { Write-Verbose "  $_" }

#endregion ----------------------------------------------------------------------

#region 3 - optional cross-check against the RDS deployment ---------------------

if ($ConnectionBroker) {
    Write-Host 'Comparing file against the RDS deployment ...' -ForegroundColor Gray
    try {
        Import-Module RemoteDesktop -ErrorAction Stop

        $live = (Get-RDServer -ConnectionBroker $ConnectionBroker |
                 Where-Object { $_.Roles -contains 'RDS-RD-SERVER' }).Server |
                ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique

        $diff = Compare-Object -ReferenceObject $live -DifferenceObject $hosts

        if (-not $diff) {
            Write-Host "  File matches the deployment exactly ($($live.Count) session hosts).`n" -ForegroundColor Green
        }
        else {
            $missing = ($diff | Where-Object SideIndicator -eq '<=').InputObject
            $extra   = ($diff | Where-Object SideIndicator -eq '=>').InputObject

            if ($missing) {
                Write-Warning "In the deployment but NOT in the file - redirection will fail for these:"
                $missing | ForEach-Object { Write-Warning "    $_" }
            }
            if ($extra) {
                Write-Warning "In the file but not a session host - RDP would be published to these:"
                $extra | ForEach-Object { Write-Warning "    $_" }
            }
            Write-Host ''
            if (-not $PSCmdlet.ShouldContinue('Continue anyway?', 'Host list differs from the RDS deployment')) {
                Write-Host 'Aborted by user.' -ForegroundColor Yellow
                return
            }
        }
    }
    catch {
        Write-Warning "Cross-check skipped: $($_.Exception.Message)"
    }
}

#endregion ----------------------------------------------------------------------

#region 4 - snapshot current state ----------------------------------------------

Write-Host 'Reading existing application segments ...' -ForegroundColor Gray
$before = Get-ExistingSegment
Write-Host "  $($before.Count) segment(s) currently configured."

$backupFile = Join-Path $BackupPath "GsaSegments-BEFORE-$Stamp.json"
$before | ConvertTo-Json -Depth 6 | Out-File -FilePath $backupFile -Encoding utf8
Write-Host "  Snapshot written to $backupFile`n"

# index of what already exists: host|protocol|ports
$existingKey = @{}
foreach ($s in $before) {
    $key = '{0}|{1}|{2}' -f $s.destinationHost.ToLowerInvariant(), $s.protocol, ($s.ports -join ',')
    $existingKey[$key] = $s.id
}

#endregion ----------------------------------------------------------------------

#region 5 - create the segments -------------------------------------------------

$portRange = '{0}-{0}' -f $Port
$created = 0; $skippedExisting = 0; $failed = @()
$total   = $hosts.Count * $Protocol.Count
$i       = 0

foreach ($h in $hosts) {
    foreach ($p in $Protocol) {
        $i++
        $key = '{0}|{1}|{2}' -f $h, $p, $portRange

        if ($existingKey.ContainsKey($key)) {
            $skippedExisting++
            Write-Verbose "SKIP  $h/$p (already present)"
            continue
        }

        Write-Progress -Activity 'Creating application segments' `
                       -Status  "$h ($p)" `
                       -PercentComplete ([int](100 * $i / $total))

        if (-not $PSCmdlet.ShouldProcess("$h : $Port/$p", 'Create application segment')) { continue }

        $body = @{
            destinationHost = $h
            destinationType = 'fqdn'
            ports           = @($portRange)
            protocol        = $p
        } | ConvertTo-Json -Compress

        try {
            Invoke-GraphWithRetry -Method POST -Uri $SegmentUri -Body $body | Out-Null
            $created++
            Write-Host ("  OK    {0,-32} {1}" -f $h, $p) -ForegroundColor Green
        }
        catch {
            $msg = $_.Exception.Message
            $failed += [pscustomobject]@{ Host = $h; Protocol = $p; Error = $msg }
            Write-Host ("  FAIL  {0,-32} {1}  {2}" -f $h, $p, $msg) -ForegroundColor Red
        }
    }
}

Write-Progress -Activity 'Creating application segments' -Completed

#endregion ----------------------------------------------------------------------

#region 6 - verify and report ---------------------------------------------------

Write-Host "`n=== Result ===" -ForegroundColor Cyan
Write-Host "Created         : $created"
Write-Host "Already present : $skippedExisting"
Write-Host "Failed          : $($failed.Count)"

if ($failed) {
    Write-Host "`nFailures:" -ForegroundColor Red
    $failed | Format-Table -AutoSize
    $failFile = Join-Path $BackupPath "GsaSegments-FAILED-$Stamp.csv"
    $failed | Export-Csv -Path $failFile -NoTypeInformation -Encoding utf8
    Write-Host "Failure list written to $failFile"
}

if (-not $WhatIfPreference) {
    $after = Get-ExistingSegment
    Write-Host "`nSegments now configured: $($after.Count)`n"

    $afterFile = Join-Path $BackupPath "GsaSegments-AFTER-$Stamp.json"
    $after | ConvertTo-Json -Depth 6 | Out-File -FilePath $afterFile -Encoding utf8
    Write-Host "Snapshot written to $afterFile"

    $after |
        Select-Object destinationHost, destinationType, protocol,
                      @{ n = 'ports'; e = { $_.ports -join ',' } }, id |
        Sort-Object destinationHost, protocol |
        Format-Table -AutoSize

    # flag anything that is not part of the intended host list -------------------
    $stale = $after | Where-Object {
        $_.destinationType -ne 'fqdn' -or
        $_.destinationHost -like '*`**' -or
        $_.destinationHost.ToLowerInvariant() -notin $hosts
    }

    if ($stale) {
        Write-Host "`nSegments NOT covered by the host list - review and remove if obsolete:" -ForegroundColor Yellow
        $stale |
            Select-Object destinationHost, destinationType, protocol,
                          @{ n = 'ports'; e = { $_.ports -join ',' } }, id |
            Format-Table -AutoSize

        Write-Host 'Remove one with:' -ForegroundColor Gray
        Write-Host "  Invoke-MgGraphRequest -Method DELETE -Uri `"$SegmentUri/<id>`"" -ForegroundColor Gray
        Write-Host 'Do this only AFTER confirming the new segments work.' -ForegroundColor Gray
    }
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host '  1. Remove the wildcard and CIDR segments listed above (after testing).'
Write-Host '  2. Connect repeatedly via the broker client access name until several'
Write-Host '     different session hosts have been reached, and confirm each works.'
Write-Host '  3. Add "create GSA segments" to the session host build checklist.'
Write-Host ''

#endregion ----------------------------------------------------------------------
