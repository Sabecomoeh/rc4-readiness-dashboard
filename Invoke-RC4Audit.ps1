#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    RC4 Deprecation Readiness Audit - Best Practices Refactor (PS 5.1)
.DESCRIPTION
    Key best-practice fixes:
      - Uses correct AD cmdlets per object type (Get-ADUser/Get-ADComputer/Get-ADServiceAccount)
      - Fixes DC selection bug (HostName[0] -> HostName)
      - Uses Write-Verbose instead of Write-Host for progress
      - Treats msDS-SupportedEncryptionTypes 0/null as "KDC Default (domain policy)" (no speculative AES label)
      - Streams CSV output efficiently (single file handle; avoids Export-Csv per row)
      - Produces stable column order using [ordered] and explicit column lists
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\RC4_Audit",

    # Optional: if empty, will use current forest root
    [string]$ForestRootDomain = "",

    [switch]$SkipEventLog,

    [ValidateRange(1, 720)]
    [int]$EventLogHours = 72
)

Set-StrictMode -Version 2.0
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# -------------------------------
# Helper: CSV streaming writer
# -------------------------------
function New-CsvWriter {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string[]]$Columns
    )

    $dir = Split-Path -Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $utf8 = New-Object System.Text.UTF8Encoding($true) # UTF8 with BOM (Excel-friendly in PS 5.1)
    $sw = New-Object System.IO.StreamWriter($Path, $false, $utf8)

    # Write header with proper CSV quoting
    $header = ($Columns | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ','
    $sw.WriteLine($header)

    return [PSCustomObject]@{
        Path    = $Path
        Columns = $Columns
        Writer  = $sw
    }
}

function Write-CsvRow {
    param(
        [Parameter(Mandatory)] $CsvWriter,
        [Parameter(Mandatory)] [psobject]$Row
    )
    # ConvertTo-Csv returns header+row; we only want the row
    $line = ($Row | ConvertTo-Csv -NoTypeInformation)[1]
    $CsvWriter.Writer.WriteLine($line)
}

function Close-CsvWriter {
    param([Parameter(Mandatory)] $CsvWriter)
    $CsvWriter.Writer.Flush()
    $CsvWriter.Writer.Dispose()
}

# -------------------------------
# Kerberos enctype helpers
# -------------------------------
function Get-EncryptionTypes {
    param([Nullable[int]]$Mask)

    # 0 or null means "inherit KDC default/domain policy", not a guaranteed AES semantic.
    if ($null -eq $Mask -or $Mask.Value -eq 0) { return "KDC-Default (Domain Policy)" }

    $m = $Mask.Value
    $types = New-Object System.Collections.Generic.List[string]

    if ($m -band 0x1)  { $types.Add("DES-CRC") }
    if ($m -band 0x2)  { $types.Add("DES-MD5") }
    if ($m -band 0x4)  { $types.Add("RC4-HMAC") }
    if ($m -band 0x8)  { $types.Add("AES128") }
    if ($m -band 0x10) { $types.Add("AES256") }

    return ($types -join "|")
}

function Test-RC4ExplicitlyEnabled {
    param([Nullable[int]]$Mask)
    if ($null -eq $Mask) { return $false }
    return [bool]($Mask.Value -band 0x4)
}

function Test-AES256Only {
    param([Nullable[int]]$Mask)
    # "AES256 only" should be exactly 0x10 (no DES/RC4/AES128 bits)
    if ($null -eq $Mask) { return $false }
    return ($Mask.Value -eq 0x10)
}

function Get-HasSpn {
    param($Spn)
    return ($null -ne $Spn -and @($Spn).Count -gt 0)
}

# -------------------------------
# Output paths + schemas
# -------------------------------
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Timestamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$AccountsCSV    = Join-Path $OutputPath "RC4_Accounts_$Timestamp.csv"
$MasterCSV      = Join-Path $OutputPath "RC4_Master_$Timestamp.csv"

$AccountsColumns = @(
    "RecordType","Domain","SamAccountName","DisplayName","ObjectType",
    "EncryptionTypeMask","EncryptionTypes","RC4Enabled","AES256Only",
    "Enabled","PasswordLastSet","LastLogonDate","AdminCount",
    "HasSPN","SPNs","DistinguishedName","WhenCreated","Description",
    "RiskLevel","AuditTimestamp","Notes"
)

# Keep your original master schema, but only populate what we have.
$MasterColumns = @(
"RecordType","Domain","SamAccountName","DisplayName","ObjectType","EncryptionTypeMask","EncryptionTypes","RC4Enabled","AES256Only","Enabled","PasswordLastSet","LastLogonDate","AdminCount","SPNs","HasSPN","DistinguishedName","WhenCreated","Description","RiskLevel","PDCEmulator","TimeCreated","ServiceName","ClientAddress","AccountName","TicketEncType","FailureCode","GPOName","GPOId","GPOStatus","LinkedTo","HasKerberosSettings","ReferencesRC4","ReferencesAES256","WMIFilter","ModificationTime","Notes","TotalObjects","RC4ExposedObjects","AES256OnlyObjects","RC4Percent","CriticalRiskCount","HighRiskCount","UsersWithRC4","ComputersWithRC4","ServiceAccountsRC4","SPNsWithRC4","KDCEventCount","GPOsWithKerbSettings","AuditTimestamp"
)

$AccountsWriter = New-CsvWriter -Path $AccountsCSV -Columns $AccountsColumns
$MasterWriter   = New-CsvWriter -Path $MasterCSV   -Columns $MasterColumns

# -------------------------------
# Resolve forest + domains
# -------------------------------
Import-Module ActiveDirectory

if ([string]::IsNullOrWhiteSpace($ForestRootDomain)) {
    $ForestRootDomain = (Get-ADForest).RootDomain
}

$forest  = Get-ADForest -Identity $ForestRootDomain
$domains = @($forest.Domains)  # already includes root; no need to re-add

foreach ($domain in $domains) {
    try {
        Write-Verbose "Processing domain: $domain"

        # Discover the PDC (or a suitable DC). Using -Discover is the supported pattern. ll/module/activedirectory/get-addomaincontroller?view=windowsserver2025-ps)
        $dcObj = Get-ADDomainController -Discover -DomainName $domain -Service PrimaryDC
        $dc    = $dcObj.HostName  # IMPORTANT: not HostName[0]

        # Used for informational output; actual ticket behavior is KDC-driven and changes with policy. [1](https://hamptonroadstransit-my.sharepoint.com/personal/atouzov_hrtransit_org/Documents/Microsoft%20Teams%20Chat%20Files/RC4%202026%20Changes.pdf?web=1)[2](https://hamptonroadstransit.sharepoint.com/sites/Infrastructure/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={e65cc390-a853-40d2-a5df-559e4204d71c}&wd=target(/Active Directory.one/)&wdpartid={6f7e3f4e-259e-05c5-0243-ea95a2b136a1}{1}&wdsectionfileid={fc807ae8-2fdf-44dd-9362-6685ef21b29f})
        $domainInfo = Get-ADDomain -Server $dc
        $pdcEmu = $domainInfo.PDCEmulator

        # --- Users ---
        Get-ADUser -LDAPFilter "(objectCategory=person)(objectClass=user)" -Server $dc `
            -ResultPageSize 2000 -ResultSetSize $null `
            -Properties DisplayName,Enabled,PasswordLastSet,LastLogonDate,adminCount,Description,WhenCreated,DistinguishedName,ServicePrincipalName,"msDS-SupportedEncryptionTypes" |
        ForEach-Object {
            $rawEnc = $_."msDS-SupportedEncryptionTypes"
            $mask   = if ($null -eq $rawEnc) { $null } else { [int]$rawEnc }

            $rc4    = Test-RC4ExplicitlyEnabled -Mask $mask
            $spn    = $_.ServicePrincipalName
            $hasSpn = Get-HasSpn -Spn $spn

            $risk = "Low"
            if ($_.Enabled) {
                if ($rc4 -and $hasSpn) { $risk = "Critical" }
                elseif ($rc4 -and ($_.adminCount -ge 1)) { $risk = "High" }
                elseif ($rc4) { $risk = "Medium" }
            } else {
                $risk = "Disabled"
            }

            $row = [pscustomobject][ordered]@{
                RecordType         = "Account"
                Domain             = $domain
                SamAccountName     = $_.SamAccountName
                DisplayName        = $_.DisplayName
                ObjectType         = "User"
                EncryptionTypeMask = if ($null -eq $mask) { "" } else { $mask }
                EncryptionTypes    = Get-EncryptionTypes -Mask $mask
                RC4Enabled         = $rc4
                AES256Only         = Test-AES256Only -Mask $mask
                Enabled            = $_.Enabled
                PasswordLastSet    = $_.PasswordLastSet
                LastLogonDate      = $_.LastLogonDate
                AdminCount         = $_.adminCount
                HasSPN             = $hasSpn
                SPNs               = if ($hasSpn) { ($spn -join ";") } else { "" }
                DistinguishedName  = $_.DistinguishedName
                WhenCreated        = $_.WhenCreated
                Description        = $_.Description
                RiskLevel          = $risk
                AuditTimestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Notes              = "KDC policy determines defaults when mask is null/0"
            }

            Write-CsvRow -CsvWriter $AccountsWriter -Row $row

            # Master row: populate known columns; leave rest blank
            $master = [pscustomobject][ordered]@{
                RecordType         = $row.RecordType
                Domain             = $row.Domain
                SamAccountName     = $row.SamAccountName
                DisplayName        = $row.DisplayName
                ObjectType         = $row.ObjectType
                EncryptionTypeMask = $row.EncryptionTypeMask
                EncryptionTypes    = $row.EncryptionTypes
                RC4Enabled         = $row.RC4Enabled
                AES256Only         = $row.AES256Only
                Enabled            = $row.Enabled
                PasswordLastSet    = $row.PasswordLastSet
                LastLogonDate      = $row.LastLogonDate
                AdminCount         = $row.AdminCount
                SPNs               = $row.SPNs
                HasSPN             = $row.HasSPN
                DistinguishedName  = $row.DistinguishedName
                WhenCreated        = $row.WhenCreated
                Description        = $row.Description
                RiskLevel          = $row.RiskLevel
                PDCEmulator        = $pdcEmu
                Notes              = $row.Notes
                AuditTimestamp     = $row.AuditTimestamp
            }

            # Expand to full master schema in stable order
            $full = [ordered]@{}
            foreach ($c in $MasterColumns) {
                $prop = $master.PSObject.Properties[$c]
                $full[$c] = if ($null -ne $prop) { $prop.Value } else { "" }
            }
            Write-CsvRow -CsvWriter $MasterWriter -Row ([pscustomobject]$full)
        }

        # --- Computers ---
        Get-ADComputer -LDAPFilter "(objectClass=computer)" -Server $dc `
            -ResultPageSize 2000 -ResultSetSize $null `
            -Properties Enabled,PasswordLastSet,LastLogonDate,Description,WhenCreated,DistinguishedName,ServicePrincipalName,"msDS-SupportedEncryptionTypes" |
        ForEach-Object {
            $rawEnc = $_."msDS-SupportedEncryptionTypes"
            $mask   = if ($null -eq $rawEnc) { $null } else { [int]$rawEnc }

            $rc4    = Test-RC4ExplicitlyEnabled -Mask $mask
            $spn    = $_.ServicePrincipalName
            $hasSpn = Get-HasSpn -Spn $spn

            $risk = "Low"
            if ($_.Enabled) {
                if ($rc4 -and $hasSpn) { $risk = "Critical" }
                elseif ($rc4) { $risk = "Medium" }
            } else {
                $risk = "Disabled"
            }

            $row = [pscustomobject][ordered]@{
                RecordType         = "Account"
                Domain             = $domain
                SamAccountName     = $_.SamAccountName
                DisplayName        = $_.Name
                ObjectType         = "Computer"
                EncryptionTypeMask = if ($null -eq $mask) { "" } else { $mask }
                EncryptionTypes    = Get-EncryptionTypes -Mask $mask
                RC4Enabled         = $rc4
                AES256Only         = Test-AES256Only -Mask $mask
                Enabled            = $_.Enabled
                PasswordLastSet    = $_.PasswordLastSet
                LastLogonDate      = $_.LastLogonDate
                AdminCount         = ""
                HasSPN             = $hasSpn
                SPNs               = if ($hasSpn) { ($spn -join ";") } else { "" }
                DistinguishedName  = $_.DistinguishedName
                WhenCreated        = $_.WhenCreated
                Description        = $_.Description
                RiskLevel          = $risk
                AuditTimestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Notes              = "KDC policy determines defaults when mask is null/0"
            }

            Write-CsvRow -CsvWriter $AccountsWriter -Row $row

            $master = [pscustomobject][ordered]@{
                RecordType         = $row.RecordType
                Domain             = $row.Domain
