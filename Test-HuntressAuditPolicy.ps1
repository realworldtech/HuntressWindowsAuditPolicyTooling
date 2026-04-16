<#
.SYNOPSIS
    Validates local Advanced Audit Policy settings against the Huntress baseline.

.DESCRIPTION
    Compares the output of AuditPol with the Huntress Managed SIEM audit policy
    baseline defined in this repository. The script can either run AuditPol
    locally or parse previously-saved AuditPol output from a file.

    When run live on a Windows host, the script also attempts lightweight
    policy source analysis by:
    - Comparing effective AuditPol results with the Local Group Policy
      advanced audit policy file, if present
    - Collecting gpresult computer-scope context to show applied computer GPOs

    This helps distinguish likely Local Group Policy drift from settings that
    are more likely being delivered by a domain GPO or manual auditpol changes.

    Supported input formats:
    - Standard table output from: auditpol /get /category:*
    - CSV output from:            auditpol /get /category:* /r

    Conditional settings:
    - Process Creation defaults to No Auditing unless -NoHuntressEDR is used
    - Certification Services defaults to No Auditing unless -HasADCS is used

.PARAMETER Path
    Optional path to a saved AuditPol output file. If omitted, the script runs
    "auditpol /get /category:*" locally.

.PARAMETER InputFormat
    Explicitly set the input format. Default: Auto

.PARAMETER NoHuntressEDR
    Validates against the no-EDR baseline, where Process Creation is Success.

.PARAMETER HasADCS
    Validates against the AD CS baseline, where Certification Services is
    Success and Failure.

.PARAMETER PassThru
    Returns the comparison object in addition to the human-readable summary.

.PARAMETER FailOnExtra
    Treat additional parsed AuditPol subcategories not present in the Huntress
    baseline as a failure. By default they are reported informationally only.

.EXAMPLE
    .\Test-HuntressAuditPolicy.ps1

.EXAMPLE
    .\Test-HuntressAuditPolicy.ps1 -Path .\auditpol.txt

.EXAMPLE
    auditpol /get /category:* /r > .\auditpol.csv
    .\Test-HuntressAuditPolicy.ps1 -Path .\auditpol.csv -InputFormat Csv

.NOTES
    Reference:
      https://support.huntress.io/hc/en-us/articles/49363914702867

    Author:  Andrew Yager / RWTS
    Version: 1.0
    Date:    2026-04-16
#>

[CmdletBinding()]
param(
    [string]$Path,
    [ValidateSet('Auto', 'Table', 'Csv')]
    [string]$InputFormat = 'Auto',
    [switch]$NoHuntressEDR,
    [switch]$HasADCS,
    [switch]$PassThru,
    [switch]$FailOnExtra
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$processCreationValue = if ($NoHuntressEDR) { 1 } else { 0 }
$certServicesValue    = if ($HasADCS) { 3 } else { 0 }

$auditSettings = @(
    @{ Name = "Credential Validation";              Value = 3 }
    @{ Name = "Kerberos Authentication Service";    Value = 3 }
    @{ Name = "Kerberos Service Ticket Operations"; Value = 3 }
    @{ Name = "Other Account Logon Events";         Value = 0 }

    @{ Name = "Application Group Management";       Value = 0 }
    @{ Name = "Computer Account Management";        Value = 3 }
    @{ Name = "Distribution Group Management";      Value = 3 }
    @{ Name = "Other Account Management Events";    Value = 1 }
    @{ Name = "Security Group Management";          Value = 3 }
    @{ Name = "User Account Management";            Value = 3 }

    @{ Name = "DPAPI Activity";                     Value = 0 }
    @{ Name = "Plug and Play Events";               Value = 1 }
    @{ Name = "Process Creation";                   Value = $processCreationValue }
    @{ Name = "Process Termination";                Value = 0 }
    @{ Name = "RPC Events";                         Value = 0 }
    @{ Name = "Token Right Adjusted Events";        Value = 0 }

    @{ Name = "Detailed Directory Service Replication"; Value = 0 }
    @{ Name = "Directory Service Access";           Value = 3 }
    @{ Name = "Directory Service Changes";          Value = 1 }
    @{ Name = "Directory Service Replication";      Value = 0 }

    @{ Name = "Account Lockout";                    Value = 2 }
    @{ Name = "User / Device Claims";               Value = 0 }
    @{ Name = "Group Membership";                   Value = 0 }
    @{ Name = "IPsec Extended Mode";                Value = 0 }
    @{ Name = "IPsec Main Mode";                    Value = 0 }
    @{ Name = "IPsec Quick Mode";                   Value = 0 }
    @{ Name = "Logoff";                             Value = 1 }
    @{ Name = "Logon";                              Value = 3 }
    @{ Name = "Network Policy Server";              Value = 3 }
    @{ Name = "Other Logon/Logoff Events";          Value = 3 }
    @{ Name = "Special Logon";                      Value = 1 }

    @{ Name = "Application Generated";              Value = 0 }
    @{ Name = "Certification Services";             Value = $certServicesValue }
    @{ Name = "Detailed File Share";                Value = 3 }
    @{ Name = "File Share";                         Value = 3 }
    @{ Name = "File System";                        Value = 0 }
    @{ Name = "Filtering Platform Connection";      Value = 2 }
    @{ Name = "Filtering Platform Packet Drop";     Value = 0 }
    @{ Name = "Handle Manipulation";                Value = 0 }
    @{ Name = "Kernel Object";                      Value = 3 }
    @{ Name = "Other Object Access Events";         Value = 3 }
    @{ Name = "Registry";                           Value = 0 }
    @{ Name = "Removable Storage";                  Value = 3 }
    @{ Name = "SAM";                                Value = 0 }
    @{ Name = "Central Policy Staging";             Value = 0 }

    @{ Name = "Audit Policy Change";                Value = 1 }
    @{ Name = "Authentication Policy Change";       Value = 1 }
    @{ Name = "Authorization Policy Change";        Value = 1 }
    @{ Name = "Filtering Platform Policy Change";   Value = 1 }
    @{ Name = "MPSSVC Rule-Level Policy Change";    Value = 3 }
    @{ Name = "Other Policy Change Events";         Value = 3 }

    @{ Name = "Non Sensitive Privilege Use";        Value = 0 }
    @{ Name = "Other Privilege Use Events";         Value = 0 }
    @{ Name = "Sensitive Privilege Use";            Value = 3 }

    @{ Name = "IPsec Driver";                       Value = 0 }
    @{ Name = "Other System Events";                Value = 3 }
    @{ Name = "Security State Change";              Value = 1 }
    @{ Name = "Security System Extension";          Value = 1 }
    @{ Name = "System Integrity";                   Value = 3 }
)

function Convert-AuditValueToText {
    param([int]$Value)

    switch ($Value) {
        0 { "No Auditing" }
        1 { "Success" }
        2 { "Failure" }
        3 { "Success and Failure" }
        default { throw "Unsupported audit value: $Value" }
    }
}

function Convert-AuditTextToValue {
    param([string]$Text)

    $normalized = if ($null -eq $Text) { '' } else { $Text.Trim() }

    switch -Regex ($normalized) {
        '^No Auditing$'          { return 0 }
        '^Success$'              { return 1 }
        '^Failure$'              { return 2 }
        '^Success and Failure$'  { return 3 }
        default { throw "Unsupported audit setting text: '$Text'" }
    }
}

function Get-NormalizedSubcategoryName {
    param([string]$Subcategory)

    if ([string]::IsNullOrWhiteSpace($Subcategory)) {
        return ''
    }

    return (($Subcategory -replace '^Audit\s+', '').Trim())
}

function Get-ExpectedAuditMap {
    $map = @{}
    foreach ($setting in $script:auditSettings) {
        $map[(Get-NormalizedSubcategoryName -Subcategory $setting.Name)] = [pscustomobject]@{
            Name      = $setting.Name
            Value     = [int]$setting.Value
            ValueText = Convert-AuditValueToText -Value ([int]$setting.Value)
        }
    }

    return $map
}

function Resolve-InputFormat {
    param(
        [string]$Content,
        [string]$DeclaredFormat
    )

    if ($DeclaredFormat -ne 'Auto') {
        return $DeclaredFormat
    }

    $trimmed = if ($null -eq $Content) { '' } else { $Content.TrimStart([char[]]@([char]0xFEFF, [char]0xFFFE, [char]32, [char]9, [char]13, [char]10)) }
    if ($trimmed -match '^(Machine Name|\"Machine Name\")\s*,') {
        return 'Csv'
    }

    return 'Table'
}

function Get-AuditRowsFromCsv {
    param([string]$Content)

    $rows = $Content | ConvertFrom-Csv
    $parsedRows = [System.Collections.Generic.List[object]]::new()

    foreach ($row in $rows) {
        $name = Get-NormalizedSubcategoryName -Subcategory $row.Subcategory
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $settingText = if (-not [string]::IsNullOrWhiteSpace($row.'Inclusion Setting')) {
            $row.'Inclusion Setting'
        } elseif (-not [string]::IsNullOrWhiteSpace($row.'Setting Value')) {
            Convert-AuditValueToText -Value ([int]$row.'Setting Value')
        } else {
            throw "Unable to determine audit setting for subcategory '$name' from CSV input."
        }

        $parsedRows.Add([pscustomobject]@{
            Name      = $name
            Value     = Convert-AuditTextToValue -Text $settingText
            ValueText = Convert-AuditValueToText -Value (Convert-AuditTextToValue -Text $settingText)
        })
    }

    return @($parsedRows)
}

function Get-AuditRowsFromTable {
    param([string]$Content)

    $parsedRows = [System.Collections.Generic.List[object]]::new()
    $lines = $Content -split "`r?`n"

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        if ($trimmed -match '^(System audit policy|Category/Subcategory|Machine Name|Policy Target)\b') {
            continue
        }

        if ($trimmed -match '^(Account Logon|Account Management|Detailed Tracking|DS Access|Logon/Logoff|Object Access|Policy Change|Privilege Use|System)$') {
            continue
        }

        if ($trimmed -match '^(No Auditing|Success|Failure|Success and Failure)$') {
            continue
        }

        $match = [regex]::Match(
            $line,
            '^\s*(?<Subcategory>.+?)\s{2,}(?<Setting>No Auditing|Success and Failure|Success|Failure)\s*$'
        )

        if (-not $match.Success) {
            continue
        }

        $name = Get-NormalizedSubcategoryName -Subcategory $match.Groups['Subcategory'].Value
        $value = Convert-AuditTextToValue -Text $match.Groups['Setting'].Value

        $parsedRows.Add([pscustomobject]@{
            Name      = $name
            Value     = $value
            ValueText = Convert-AuditValueToText -Value $value
        })
    }

    return @($parsedRows)
}

function Get-AuditRows {
    param(
        [string]$Content,
        [string]$Format
    )

    switch ($Format) {
        'Csv'   { return @(Get-AuditRowsFromCsv -Content $Content) }
        'Table' { return @(Get-AuditRowsFromTable -Content $Content) }
        default { throw "Unsupported input format: $Format" }
    }
}

function Get-AuditPolContent {
    param([string]$InputPath)

    if ($InputPath) {
        if (-not (Test-Path -LiteralPath $InputPath)) {
            throw "Input file not found: $InputPath"
        }

        return Get-Content -LiteralPath $InputPath -Raw
    }

    $commandOutput = & auditpol /get /category:*
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol exited with code $LASTEXITCODE."
    }

    return ($commandOutput -join [Environment]::NewLine)
}

function Get-LocalAuditPolicyRows {
    $localAuditPath = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'
    if (-not (Test-Path -LiteralPath $localAuditPath)) {
        return [pscustomobject]@{
            Available = $false
            Path      = $localAuditPath
            Rows      = @()
            Error     = $null
        }
    }

    try {
        $content = Get-Content -LiteralPath $localAuditPath -Raw
        return [pscustomobject]@{
            Available = $true
            Path      = $localAuditPath
            Rows      = @(Get-AuditRows -Content $content -Format 'Csv')
            Error     = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Available = $true
            Path      = $localAuditPath
            Rows      = @()
            Error     = $_.Exception.Message
        }
    }
}

function Get-GpResultComputerSummary {
    if ($Path) {
        return [pscustomobject]@{
            Collected       = $false
            AppliedGpos     = @()
            DomainGpos      = @()
            RawOutput       = $null
            Error           = 'gpresult analysis is only available during live local execution.'
        }
    }

    try {
        $output = & gpresult /scope computer /r
        if ($LASTEXITCODE -ne 0) {
            throw "gpresult exited with code $LASTEXITCODE."
        }

        $lines = @($output)
        $appliedGpos = [System.Collections.Generic.List[string]]::new()
        $captureApplied = $false

        foreach ($line in $lines) {
            $trimmed = $line.Trim()

            if ($trimmed -match '^Applied Group Policy Objects\b') {
                $captureApplied = $true
                continue
            }

            if ($captureApplied) {
                if ([string]::IsNullOrWhiteSpace($trimmed)) {
                    if ($appliedGpos.Count -gt 0) {
                        break
                    }

                    continue
                }

                if ($line -notmatch '^\s{2,}') {
                    break
                }

                if ($trimmed -ne 'N/A' -and $trimmed -notmatch '^-+$') {
                    $appliedGpos.Add($trimmed)
                }
            }
        }

        $domainGpos = @(
            $appliedGpos | Where-Object {
                $_ -ne 'Local Group Policy'
            }
        )

        return [pscustomobject]@{
            Collected       = $true
            AppliedGpos     = @($appliedGpos)
            DomainGpos      = @($domainGpos)
            RawOutput       = ($lines -join [Environment]::NewLine)
            Error           = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Collected       = $false
            AppliedGpos     = @()
            DomainGpos      = @()
            RawOutput       = $null
            Error           = $_.Exception.Message
        }
    }
}

function Get-LdapEscapedValue {
    param([string]$Value)

    if ($null -eq $Value) {
        return ''
    }

    return ($Value `
        -replace '\\', '\5c' `
        -replace '\*', '\2a' `
        -replace '\(', '\28' `
        -replace '\)', '\29' `
        -replace [char]0, '\00')
}

function Get-CurrentDomainContext {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.Name)/RootDSE")
        $domainDn = [string]$rootDse.Properties['defaultNamingContext'][0]

        return [pscustomobject]@{
            Available  = $true
            DomainName = $domain.Name
            DomainDN   = $domainDn
            Error      = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Available  = $false
            DomainName = $null
            DomainDN   = $null
            Error      = $_.Exception.Message
        }
    }
}

function Get-AppliedGpoAuditDefinitions {
    param([string[]]$AppliedGpoNames)

    $domainContext = Get-CurrentDomainContext
    if (-not $domainContext.Available) {
        return [pscustomobject]@{
            Available = $false
            Domain    = $domainContext
            Gpos      = @()
            Error     = $domainContext.Error
        }
    }

    $gpos = [System.Collections.Generic.List[object]]::new()
    $policyBaseDn = "CN=Policies,CN=System,$($domainContext.DomainDN)"

    foreach ($gpoName in $AppliedGpoNames) {
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domainContext.DomainName)/$policyBaseDn")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=$(Get-LdapEscapedValue -Value $gpoName)))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        [void]$searcher.PropertiesToLoad.Add('name')

        $match = $searcher.FindOne()
        if ($null -eq $match) {
            $gpos.Add([pscustomobject]@{
                Name          = $gpoName
                Guid          = $null
                AuditFilePath = $null
                Available     = $false
                Definitions   = @()
                Error         = 'Unable to resolve GPO in Active Directory.'
            })
            continue
        }

        $guid = [string]$match.Properties['name'][0]
        $auditFilePath = "\\$($domainContext.DomainName)\SYSVOL\$($domainContext.DomainName)\Policies\$guid\Machine\Microsoft\Windows NT\Audit\audit.csv"

        if (-not (Test-Path -LiteralPath $auditFilePath)) {
            $gpos.Add([pscustomobject]@{
                Name          = $gpoName
                Guid          = $guid
                AuditFilePath = $auditFilePath
                Available     = $false
                Definitions   = @()
                Error         = 'No advanced audit policy file found in SYSVOL for this GPO.'
            })
            continue
        }

        try {
            $content = Get-Content -LiteralPath $auditFilePath -Raw
            $gpos.Add([pscustomobject]@{
                Name          = $gpoName
                Guid          = $guid
                AuditFilePath = $auditFilePath
                Available     = $true
                Definitions   = @(Get-AuditRows -Content $content -Format 'Csv')
                Error         = $null
            })
        }
        catch {
            $gpos.Add([pscustomobject]@{
                Name          = $gpoName
                Guid          = $guid
                AuditFilePath = $auditFilePath
                Available     = $false
                Definitions   = @()
                Error         = $_.Exception.Message
            })
        }
    }

    return [pscustomobject]@{
        Available = $true
        Domain    = $domainContext
        Gpos      = @($gpos)
        Error     = $null
    }
}

function New-AuditPolicyRowMap {
    param([object[]]$Rows)

    $map = @{}
    foreach ($row in $Rows) {
        $map[$row.Name] = $row
    }

    return $map
}

function Get-PolicySourceAnalysis {
    param(
        [pscustomobject]$ComparisonResult,
        [object[]]$ActualRows
    )

    if ($Path) {
        return [pscustomobject]@{
            Available          = $false
            LocalPolicy        = $null
            GpResult           = $null
            Findings           = @()
            Summary            = 'Policy source analysis is skipped when parsing saved AuditPol output from a file.'
        }
    }

    $localPolicy = Get-LocalAuditPolicyRows
    $gpResult = Get-GpResultComputerSummary
    $domainGpoAuditDefinitions = if ($gpResult.DomainGpos.Count -gt 0) {
        Get-AppliedGpoAuditDefinitions -AppliedGpoNames $gpResult.DomainGpos
    } else {
        [pscustomobject]@{
            Available = $false
            Domain    = $null
            Gpos      = @()
            Error     = 'No applied domain computer GPOs were parsed from gpresult output.'
        }
    }
    $actualMap = New-AuditPolicyRowMap -Rows $ActualRows
    $localMap = if ($localPolicy.Rows.Count -gt 0) { New-AuditPolicyRowMap -Rows $localPolicy.Rows } else { @{} }
    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $ComparisonResult.Mismatches) {
        $localRow = if ($localMap.ContainsKey($item.Name)) { $localMap[$item.Name] } else { $null }
        $assessment = ''
        $definingGpos = [System.Collections.Generic.List[object]]::new()

        foreach ($gpo in $domainGpoAuditDefinitions.Gpos) {
            if (-not $gpo.Available) {
                continue
            }

            $matchingDefinition = @($gpo.Definitions | Where-Object { $_.Name -eq $item.Name } | Select-Object -First 1)
            if ($matchingDefinition.Count -gt 0) {
                $definingGpos.Add([pscustomobject]@{
                    Name      = $gpo.Name
                    Guid      = $gpo.Guid
                    Value     = $matchingDefinition[0].Value
                    ValueText = $matchingDefinition[0].ValueText
                    Path      = $gpo.AuditFilePath
                })
            }
        }

        $gposMatchingEffective = @($definingGpos | Where-Object { $_.Value -eq $item.ActualValue })
        $gposMatchingExpected = @($definingGpos | Where-Object { $_.Value -eq $item.ExpectedValue })

        if ($gposMatchingEffective.Count -eq 1 -and $definingGpos.Count -gt 0) {
            $assessment = "The applied GPO '$($gposMatchingEffective[0].Name)' is the only inspected domain GPO defining the effective value, so it is the most likely source of this mismatch."
        } elseif ($gposMatchingEffective.Count -gt 1) {
            $assessment = "Multiple applied GPOs define the effective value ($($gposMatchingEffective.Name -join ', ')), so precedence between those GPOs is determining the final result."
        } elseif ($definingGpos.Count -gt 0 -and $gposMatchingExpected.Count -gt 0) {
            $assessment = "Applied GPOs define both the expected and effective values, so a conflicting higher-precedence GPO is likely overriding the Huntress baseline."
        } elseif ($null -ne $localRow -and $localRow.Value -eq $item.ActualValue) {
            $assessment = 'Local Group Policy matches the effective setting for this subcategory.'
        } elseif ($null -ne $localRow -and $localRow.Value -ne $item.ActualValue) {
            $assessment = 'Local Group Policy differs from the effective setting, so a higher-precedence domain GPO or manual auditpol change is likely winning.'
        } elseif ($definingGpos.Count -eq 0 -and $domainGpoAuditDefinitions.Gpos.Count -gt 0) {
            $assessment = 'None of the inspected applied GPO audit.csv files define this subcategory, so the mismatch may come from legacy audit policy, a manual auditpol change, or a GPO that could not be inspected.'
        } elseif ($gpResult.DomainGpos.Count -gt 0) {
            $assessment = 'Local Group Policy does not define this subcategory; a domain GPO or manual auditpol change is more likely.'
        } else {
            $assessment = 'No applied domain computer GPOs were detected and Local Group Policy does not define this subcategory, so manual/local configuration is more likely.'
        }

        $findings.Add([pscustomobject]@{
            Name            = $item.Name
            Expected        = $item.Expected
            Effective       = $item.Actual
            LocalPolicy     = $(if ($null -ne $localRow) { $localRow.ValueText } else { 'Not defined in Local Group Policy' })
            DefiningGpos    = @($definingGpos)
            Assessment      = $assessment
        })
    }

    return [pscustomobject]@{
        Available          = $true
        LocalPolicy        = $localPolicy
        GpResult           = $gpResult
        DomainGpoAudit     = $domainGpoAuditDefinitions
        Findings           = @($findings)
        Summary            = 'Policy source analysis is heuristic: AuditPol shows effective settings, while Local Group Policy plus gpresult helps narrow down whether drift is local or likely domain GPO-driven.'
    }
}

function Compare-AuditPolicy {
    param([object[]]$ActualRows)

    $expectedMap = Get-ExpectedAuditMap
    $actualMap = @{}

    foreach ($row in $ActualRows) {
        $actualMap[$row.Name] = $row
    }

    $matches    = [System.Collections.Generic.List[object]]::new()
    $mismatches = [System.Collections.Generic.List[object]]::new()
    $missing    = [System.Collections.Generic.List[object]]::new()
    $extra      = [System.Collections.Generic.List[object]]::new()

    foreach ($name in ($expectedMap.Keys | Sort-Object)) {
        $expected = $expectedMap[$name]
        if (-not $actualMap.ContainsKey($name)) {
            $missing.Add([pscustomobject]@{
                Name         = $expected.Name
                Expected     = $expected.ValueText
                ExpectedValue = $expected.Value
            })
            continue
        }

        $actual = $actualMap[$name]
        if ($actual.Value -eq $expected.Value) {
            $matches.Add([pscustomobject]@{
                Name     = $expected.Name
                Expected = $expected.ValueText
                Actual   = $actual.ValueText
            })
        } else {
            $mismatches.Add([pscustomobject]@{
                Name          = $expected.Name
                Expected      = $expected.ValueText
                ExpectedValue = $expected.Value
                Actual        = $actual.ValueText
                ActualValue   = $actual.Value
            })
        }
    }

    foreach ($name in ($actualMap.Keys | Sort-Object)) {
        if (-not $expectedMap.ContainsKey($name)) {
            $extra.Add([pscustomobject]@{
                Name        = $actualMap[$name].Name
                Actual      = $actualMap[$name].ValueText
                ActualValue = $actualMap[$name].Value
            })
        }
    }

    return [pscustomobject]@{
        Passed        = ($mismatches.Count -eq 0 -and $missing.Count -eq 0 -and ((-not $script:FailOnExtra) -or $extra.Count -eq 0))
        ExpectedCount = $expectedMap.Count
        ActualCount   = $actualMap.Count
        MatchCount    = $matches.Count
        MismatchCount = $mismatches.Count
        MissingCount  = $missing.Count
        ExtraCount    = $extra.Count
        Matches       = @($matches)
        Mismatches    = @($mismatches)
        Missing       = @($missing)
        Extra         = @($extra)
    }
}

$content = Get-AuditPolContent -InputPath $Path
$resolvedFormat = Resolve-InputFormat -Content $content -DeclaredFormat $InputFormat
$rows = Get-AuditRows -Content $content -Format $resolvedFormat

if ($rows.Count -eq 0) {
    throw "No Advanced Audit Policy rows were parsed from the provided AuditPol output."
}

$result = Compare-AuditPolicy -ActualRows $rows
$policySource = Get-PolicySourceAnalysis -ComparisonResult $result -ActualRows $rows

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " HUNTRESS AUDIT POLICY VALIDATION" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host (" Input source:  {0}" -f $(if ($Path) { $Path } else { 'Live auditpol /get /category:*' }))
Write-Host (" Input format:  {0}" -f $resolvedFormat)
Write-Host (" Expected rows: {0}" -f $result.ExpectedCount)
Write-Host (" Parsed rows:   {0}" -f $result.ActualCount)
Write-Host (" Baseline mode: Process Creation={0}; Certification Services={1}" -f `
    (Convert-AuditValueToText -Value $processCreationValue),
    (Convert-AuditValueToText -Value $certServicesValue))
Write-Host ""

if ($result.Passed) {
    Write-Host "Result: PASS - AuditPol output matches the Huntress baseline." -ForegroundColor Green
} else {
    Write-Host "Result: FAIL - Differences from the Huntress baseline were found." -ForegroundColor Red
}

if ($result.MismatchCount -gt 0) {
    Write-Host ""
    Write-Host "Mismatched subcategories:" -ForegroundColor Yellow
    foreach ($item in $result.Mismatches) {
        Write-Host ("  - {0}: expected '{1}', found '{2}'" -f $item.Name, $item.Expected, $item.Actual)
    }
}

if ($result.MissingCount -gt 0) {
    Write-Host ""
    Write-Host "Missing subcategories:" -ForegroundColor Yellow
    foreach ($item in $result.Missing) {
        Write-Host ("  - {0}: expected '{1}'" -f $item.Name, $item.Expected)
    }
}

if ($result.ExtraCount -gt 0) {
    Write-Host ""
    Write-Host ("Additional parsed subcategories not in baseline{0}:" -f $(if ($FailOnExtra) { ' (treated as failure)' } else { ' (informational only)' })) -ForegroundColor Yellow
    foreach ($item in $result.Extra) {
        Write-Host ("  - {0}: found '{1}'" -f $item.Name, $item.Actual)
    }
}

Write-Host ""
Write-Host ("Summary: {0} matched, {1} mismatched, {2} missing, {3} extra" -f `
    $result.MatchCount, $result.MismatchCount, $result.MissingCount, $result.ExtraCount)
Write-Host ""

if ($policySource.Available) {
    Write-Host "Policy source analysis:" -ForegroundColor Cyan
    Write-Host ("  - {0}" -f $policySource.Summary)

    if ($null -ne $policySource.LocalPolicy) {
        if ($policySource.LocalPolicy.Error) {
            Write-Host ("  - Local Group Policy audit file: {0} (parse error: {1})" -f $policySource.LocalPolicy.Path, $policySource.LocalPolicy.Error) -ForegroundColor Yellow
        } elseif ($policySource.LocalPolicy.Available) {
            Write-Host ("  - Local Group Policy audit file: {0} ({1} parsed row(s))" -f $policySource.LocalPolicy.Path, $policySource.LocalPolicy.Rows.Count)
        } else {
            Write-Host ("  - Local Group Policy audit file not present: {0}" -f $policySource.LocalPolicy.Path)
        }
    }

    if ($null -ne $policySource.GpResult) {
        if ($policySource.GpResult.Error) {
            Write-Host ("  - gpresult: {0}" -f $policySource.GpResult.Error) -ForegroundColor Yellow
        } elseif ($policySource.GpResult.Collected) {
            if ($policySource.GpResult.AppliedGpos.Count -gt 0) {
                Write-Host ("  - Applied computer GPOs: {0}" -f ($policySource.GpResult.AppliedGpos -join ', '))
            } else {
                Write-Host "  - Applied computer GPOs: none parsed from gpresult output"
            }
        }
    }

    if ($null -ne $policySource.DomainGpoAudit) {
        if ($policySource.DomainGpoAudit.Error) {
            Write-Host ("  - Applied GPO audit inspection: {0}" -f $policySource.DomainGpoAudit.Error) -ForegroundColor Yellow
        } elseif ($policySource.DomainGpoAudit.Gpos.Count -gt 0) {
            $inspectableCount = @($policySource.DomainGpoAudit.Gpos | Where-Object { $_.Available }).Count
            Write-Host ("  - Applied GPO audit files inspected: {0} of {1}" -f $inspectableCount, $policySource.DomainGpoAudit.Gpos.Count)
        }
    }

    if ($policySource.Findings.Count -gt 0) {
        Write-Host ""
        Write-Host "Likely source of mismatches:" -ForegroundColor Yellow
        foreach ($finding in $policySource.Findings) {
            Write-Host ("  - {0}: effective='{1}', local policy='{2}'. {3}" -f `
                $finding.Name, $finding.Effective, $finding.LocalPolicy, $finding.Assessment)

            if ($finding.DefiningGpos.Count -gt 0) {
                foreach ($gpo in $finding.DefiningGpos) {
                    Write-Host ("      GPO '{0}' defines '{1}'" -f $gpo.Name, $gpo.ValueText)
                }
            }
        }
    }

    Write-Host ""
} else {
    Write-Host "Policy source analysis: skipped for file-based input." -ForegroundColor DarkYellow
    Write-Host ""
}

if ($PassThru) {
    [pscustomobject]@{
        Comparison   = $result
        PolicySource = $policySource
    }
}

if ($result.Passed) {
    exit 0
}

exit 1

# SIG # Begin signature block
# MIIyhQYJKoZIhvcNAQcCoIIydjCCMnICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARJ6Keb3bFhkBg
# xBboZMSr8479ydlOtrarX9o5WiCB9aCCK7QwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYUMIID/KADAgECAhB6I67a
# U2mWD5HIPlz0x+M/MA0GCSqGSIb3DQEBDAUAMFcxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRp
# bWUgU3RhbXBpbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1
# OTU5WjBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSww
# KgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjCCAaIw
# DQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2Y2ENBq26CK+z2M34mNOSJjNPv
# IhKAVD7vJq+MDoGD46IiM+b83+3ecLvBhStSVjeYXIjfa3ajoW3cS3ElcJzkyZlB
# nwDEJuHlzpbN4kMH2qRBVrjrGJgSlzzUqcGQBaCxpectRGhhnOSwcjPMI3G0hedv
# 2eNmGiUbD12OeORN0ADzdpsQ4dDi6M4YhoGE9cbY11XxM2AVZn0GiOUC9+XE0wI7
# CQKfOUfigLDn7i/WeyxZ43XLj5GVo7LDBExSLnh+va8WxTlA+uBvq1KO8RSHUQLg
# zb1gbL9Ihgzxmkdp2ZWNuLc+XyEmJNbD2OIIq/fWlwBp6KNL19zpHsODLIsgZ+WZ
# 1AzCs1HEK6VWrxmnKyJJg2Lv23DlEdZlQSGdF+z+Gyn9/CRezKe7WNyxRf4e4bwU
# trYE2F5Q+05yDD68clwnweckKtxRaF0VzN/w76kOLIaFVhf5sMM/caEZLtOYqYad
# tn034ykSFaZuIBU9uCSrKRKTPJhWvXk4CllgrwIDAQABo4IBXDCCAVgwHwYDVR0j
# BBgwFoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFF9Y7UwxeqJhQo1S
# gLqzYZcZojKbMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBMBgNVHR8ERTBD
# MEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1l
# U3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRwMG4wRwYIKwYBBQUHMAKG
# O2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGlu
# Z1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNv
# bTANBgkqhkiG9w0BAQwFAAOCAgEAEtd7IK0ONVgMnoEdJVj9TC1ndK/HYiYh9lVU
# acahRoZ2W2hfiEOyQExnHk1jkvpIJzAMxmEc6ZvIyHI5UkPCbXKspioYMdbOnBWQ
# Un733qMooBfIghpR/klUqNxx6/fDXqY0hSU1OSkkSivt51UlmJElUICZYBodzD3M
# /SFjeCP59anwxs6hwj1mfvzG+b1coYGnqsSz2wSKr+nDO+Db8qNcTbJZRAiSazr7
# KyUJGo1c+MScGfG5QHV+bps8BX5Oyv9Ct36Y4Il6ajTqV2ifikkVtB3RNBUgwu/m
# SiSUice/Jp/q8BMk/gN8+0rNIE+QqU63JoVMCMPY2752LmESsRVVoypJVt8/N3qQ
# 1c6FibbcRabo3azZkcIdWGVSAdoLgAIxEKBeNh9AQO1gQrnh1TA8ldXuJzPSuALO
# z1Ujb0PCyNVkWk7hkhVHfcvBfI8NtgWQupiaAeNHe0pWSGH2opXZYKYG4Lbukg7H
# pNi/KqJhue2Keak6qH9A8CeEOB7Eob0Zf+fU+CCQaL0cJqlmnx9HCDxF+3BLbUuf
# rV64EbTI40zqegPZdA+sXCmbcZy6okx/SjwsusWRItFA3DE8MORZeFb6BmzBtqKJ
# 7l939bbKBy2jvxcJI98Va95Q5JnlKor3m0E7xpMeYRriWklUPsetMSf2NvUQa/E5
# vVyefQIwggYaMIIEAqADAgECAhBiHW0MUgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEB
# DAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLTAr
# BgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBSb290IFI0NjAeFw0y
# MTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
# gQCbK51T+jU/jmAGQ2rAz/V/9shTUxjIztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgC
# sJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NVDgFigOMYzB2OKhdqfWGVoYW3haT29PST
# ahYkwmMv0b/83nbeECbiMXhSOtbam+/36F09fy1tsB8je/RV0mIk8XL/tfCK6cPu
# YHE215wzrK0h1SWHTxPbPuYkRdkP05ZwmRmTnAO5/arnY83jeNzhP06ShdnRqtZl
# V59+8yv+KIhE5ILMqgOZYAENHNX9SJDm+qxp4VqpB3MV/h53yl41aHU5pledi9lC
# BbH9JeIkNFICiVHNkRmq4TpxtwfvjsUedyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7
# TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz44MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ
# /ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBMdlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZ
# b1sCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaAFDLrkpr/NZZILyhAQnAgNpFcF4Xm
# MB0GA1UdDgQWBBQPKssghyi47G9IritUpimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYw
# EgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNVHSAE
# FDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsGA1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9j
# cmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5j
# cmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUFBzAChjpodHRwOi8vY3J0LnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsG
# AQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AgEABv+C4XdjNm57oRUgmxP/BP6YdURhw1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5
# jUug2oeunbYAowbFC2AKK+cMcXIBD0ZdOaWTsyNyBBsMLHqafvIhrCymlaS98+Qp
# oBCyKppP0OcxYEdU0hpsaqBBIZOtBajjcw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd
# 099iChnyIMvY5HexjO2AmtsbpVn0OhNcWbWDRF/3sBp6fWXhz7DcML4iTAWS+MVX
# eNLj1lJziVKEoroGs9Mlizg0bUMbOalOhOfCipnx8CaLZeVme5yELg09Jlo8BMe8
# 0jO37PU8ejfkP9/uPak7VLwELKxAMcJszkyeiaerlphwoKx1uHRzNyE6bxuSKcut
# isqmKL5OTunAvtONEoteSiabkPVSZ2z76mKnzAfZxCl/3dq3dUNw4rg3sTCggkHS
# RqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5JKdGvspbOrTfOXyXvmPL6E52z1NZJ6ctu
# MFBQZH3pwWvqURR8AgQdULUvrxjUYbHHj95Ejza63zdrEcxWLDX6xWls/GDnVNue
# KjWUH3fTv1Y8Wdho698YADR7TNx8X8z2Bev6SivBBOHY+uqiirZtg0y9ShQoPzmC
# cn63Syatatvx157YK9hlcPmVoa1oDE5/L9Uo2bC5a4CH2RwwggZiMIIEyqADAgEC
# AhEApCk7bh7d16c0CIetek63JDANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJH
# QjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1
# YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjAeFw0yNTAzMjcwMDAwMDBaFw0zNjAz
# MjEyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRcwFQYDVQQIEw5XZXN0IFlvcmtzaGly
# ZTEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1
# YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDThJX0bqRTePI9EEt4Egc83JSBU2dhrJ+wY7JgReuff5KQ
# NhMuzVytzD+iXazATVPMHZpH/kkiMo1/vlAGFrYN2P7g0Q8oPEcR3h0SftFNYxxM
# h+bj3ZNbbYjwt8f4DsSHPT+xp9zoFuw0HOMdO3sWeA1+F8mhg6uS6BJpPwXQjNSH
# pVTCgd1gOmKWf12HSfSbnjl3kDm0kP3aIUAhsodBYZsJA1imWqkAVqwcGfvs6pbf
# s/0GE4BJ2aOnciKNiIV1wDRZAh7rS/O+uTQcb6JVzBVmPP63k5xcZNzGo4DOTV+s
# M1nVrDycWEYS8bSS0lCSeclkTcPjQah9Xs7xbOBoCdmahSfg8Km8ffq8PhdoAXYK
# OI+wlaJj+PbEuwm6rHcm24jhqQfQyYbOUFTKWFe901VdyMC4gRwRAq04FH2VTjBd
# CkhKts5Py7H73obMGrxN1uGgVyZho4FkqXA8/uk6nkzPH9QyHIED3c9CGIJ098hU
# 4Ig2xRjhTbengoncXUeo/cfpKXDeUcAKcuKUYRNdGDlf8WnwbyqUblj4zj1kQZSn
# Zud5EtmjIdPLKce8UhKl5+EEJXQp1Fkc9y5Ivk4AZacGMCVG0e+wwGsjcAADRO7W
# ga89r/jJ56IDK773LdIsL3yANVvJKdeeS6OOEiH6hpq2yT+jJ/lHa9zEdqFqMwID
# AQABo4IBjjCCAYowHwYDVR0jBBgwFoAUX1jtTDF6omFCjVKAurNhlxmiMpswHQYD
# VR0OBBYEFIhhjKEqN2SBKGChmzHQjP0sAs5PMA4GA1UdDwEB/wQEAwIGwDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwNQYM
# KwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20v
# Q1BTMAgGBmeBDAEEAjBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcmwwegYIKwYB
# BQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRwOi8vY3J0LnNlY3RpZ28uY29tL1Nl
# Y3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4IBgQACgT6khnJR
# IfllqS49Uorh5ZvMSxNEk4SNsi7qvu+bNdcuknHgXIaZyqcVmhrV3PHcmtQKt0bl
# v/8t8DE4bL0+H0m2tgKElpUeu6wOH02BjCIYM6HLInbNHLf6R2qHC1SUsJ02MWNq
# RNIT6GQL0Xm3LW7E6hDZmR8jlYzhZcDdkdw0cHhXjbOLsmTeS0SeRJ1WJXEzqt25
# dbSOaaK7vVmkEVkOHsp16ez49Bc+Ayq/Oh2BAkSTFog43ldEKgHEDBbCIyba2E8O
# 5lPNan+BQXOLuLMKYS3ikTcp/Qw63dxyDCfgqXYUhxBpXnmeSO/WA4NwdwP35lWN
# hmjIpNVZvhWoxDL+PxDdpph3+M5DroWGTc1ZuDa1iXmOFAK4iwTnlWDg3QNRsRa9
# cnG3FBBpVHnHOEQj4GMkrOHdNDTbonEeGvZ+4nSZXrwCW4Wv2qyGDBLlKk3kUW1p
# IScDCpm/chL6aUbnSsrtbepdtbCLiGanKVR/KC1gsR0tC6Q0RfWOI4owggaBMIIE
# aaADAgECAhACfDkBDKdawzq17g1UDvnlMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENp
# dHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNF
# UlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAw
# MDBaFw0zODAxMTgyMzU5NTlaMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2lnbmlu
# ZyBSb290IFI0NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAI3nlBIi
# BCR0Lv8WIwKSirauNoWsR9QjkSs+3H3iMaBRb6yEkeNSirXilt7Qh2MkiYr/7xKT
# O327toq9vQV/J5trZdOlDGmxvEk5mvFtbqrkoIMn2poNK1DpS1uzuGQ2pH5KPalx
# q2Gzc7M8Cwzv2zNX5b40N+OXG139HxI9ggN25vs/ZtKUMWn6bbM0rMF6eNySUPJk
# x6otBKvDaurgL6en3G7X6P/aIatAv7nuDZ7G2Z6Z78beH6kMdrMnIKHWuv2A5wHS
# 7+uCKZVwjf+7Fc/+0Q82oi5PMpB0RmtHNRN3BTNPYy64LeG/ZacEaxjYcfrMCPJt
# iZkQsa3bPizkqhiwxgcBdWfebeljYx42f2mJvqpFPm5aX4+hW8udMIYw6AOzQMYN
# DzjNZ6hTiPq4MGX6b8fnHbGDdGk+rMRoO7HmZzOatgjggAVIQO72gmRGqPVzsAaV
# 8mxln79VWxycVxrHeEZ8cKqUG4IXrIfptskOgRxA1hYXKfxcnBgr6kX1773VZ08o
# XgXukEx658b00Pz6zT4yRhMgNooE6reqB0acDZM6CWaZWFwpo7kMpjA4PNBGNjV8
# nLruw9X5Cnb6fgUbQMqSNenVetG1fwCuqZCqxX8BnBCxFvzMbhjcb2L+plCnuHu4
# nRU//iAMdcgiWhOVGZAA6RrVwobx447sX/TlAgMBAAGjggEWMIIBEjAfBgNVHSME
# GDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUMuuSmv81lkgvKEBC
# cCA2kVwXheYwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBD
# oEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZp
# Y2F0aW9uQXV0aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGG
# GWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAF8d
# gc5S+2H7jdJx4S0jhiqCeUq4+hoT7W5w6yS+qe9r/IsIPgFlPh1gsS3Thgbeb6F5
# /5ld0Qp4WxwBml7gR6yqw8H5fsh8eFONLbI7XlXAW0Z0HnpZfseAXIsyZoSAn00q
# MVVo4VlviYhK1x1qaVLmINsVcVQYa0iUh22DL6eF2k9dHhMv7PXpBjg8cPv5pnkn
# r/Py4P3CmfMjWMXt4X7sj96S8IKIvDm8VhVyq+U5WIj1Vmadi0ODUcB1MI6o9s+F
# WrNL4pF+3Hz5UaYkJOlVPE6aRbu5dt0MM5IbnvZk8NZRTiVwdzCd9pHXMqhvm7i6
# 9uCKCp76mn5uaJbrbxarHXvvkb0uqJbbp+gEKZ4cursBiWu3fcoBbT+ihxZXwUXT
# 8FJFjmSKr0geH8JO360CNeMDDLREu2xfJ+8SOIrNpBbxbZBTW2UslVdWYuZ83EaU
# ksbrlG91H1ylkTXQHwpaV4ebop81Z9xiZ1MVuDVOlXwGH0WElxfE6NutmlA5Nppv
# 2BPHKo7M54PeapSYeNv76WDqT2DKnaoQ5qpj6Z8nX/BziKe27eoJEVGIRAXmaOGu
# i+F7RLY1iDCMNaOVy0g7XBnXcLCrnGPLRbu2LLeQeKDFkEXQy6oeSu0TWTeNNthl
# 23qaJ+yFDS6I//sLVSn+BkyEa9wB8rHF2cTTmhMkMIIGgjCCBGqgAwIBAgIQNsKw
# vXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
# ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0Eg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4
# MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpU
# VMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQyC0cR
# LWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE/LkY
# w3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3vcTd
# OGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4
# elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI
# 9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYynPt5
# lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsT
# Ilg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25qhso
# BIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY5SJY
# ubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEIkv7k
# RmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5v1qq
# K0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAO
# BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEF
# BQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDov
# L2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRo
# b3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29j
# c3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjlocXU
# EYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb
# 3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W6
# 1KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/
# AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mS
# IkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1
# TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/G8re
# ZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8
# CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/
# 7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG
# +ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF
# 4TeMM+zYAJzoKQnVKOLg8pZVPT8wggaWMIIE/qADAgECAhEAyu6yTXnXONjJZZfx
# EYG4QDANBgkqhkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25p
# bmcgQ0EgUjM2MB4XDTI2MDQxNTAwMDAwMFoXDTI3MDQxNTIzNTk1OVowgYsxCzAJ
# BgNVBAYTAkFVMRgwFgYDVQQIDA9OZXcgU291dGggV2FsZXMxMDAuBgNVBAoMJ1Jl
# YWwgV29ybGQgVGVjaG5vbG9neSBTb2x1dGlvbnMgUHR5IEx0ZDEwMC4GA1UEAwwn
# UmVhbCBXb3JsZCBUZWNobm9sb2d5IFNvbHV0aW9ucyBQdHkgTHRkMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAttRXQesNoNvtUqrqHdfK+1nEMTcPSNrm
# K55HqiNWAWmBPN1JCSUkgSm1E6JfAoC5XODVqu05r9XIRsCUjfhczAbcCvLjgraK
# Xv7N6xGTigyIe3e0aCYGEIXWcU0yVDL86RVK5v+5MP9iK6STebTE84EJEA/qv14/
# fVWoOFGT/VvojAT5sJLJfShYYaFFeiOwxOK6JipT2uFhu3zM+BcolkiNzfPgLSww
# 7YTelTL4Xc3nCUGKaQvDqmXZRlJrkmnX99iYnNGqxn1Tbd/QoXFE7CBZnEg7g1B+
# h/kuowPP+e6W/d0AEJ6JrJLc7zUatZGBdz3eBc0zphpUB+oi7iyKt/i/wwt1qcu8
# D0kw5qWot5Nbe26rveH0S5L4QynuVHuMiZUEFY1Fq2QVtAyHyCj3ouVqX7JlzGnY
# E08ogD1ojYeQ9swYMaUFdIgnxdi0DJqWqfyKd/ZS3w9qESTbpuPZ1iTmE/U7s8ra
# Y66KllnPyewfGOFzW/DQ4jby8l+FhBByrlb9SMROBWp/w8fD+oAQOi6kq9HSfE5C
# 5oSSxwmjBQvWhytbvUFFJO+yKMOqgv2Di1bPCTs+x+NE4MsK0kwgwAWA6G03r2FN
# W+eHY+tdH/gvy7HMipDiEPPbX7hccDOO1VKsG3AsOGorj+Vh/FSKbCAqjqLnSAMO
# 5QhOj1kLJBECAwEAAaOCAakwggGlMB8GA1UdIwQYMBaAFA8qyyCHKLjsb0iuK1Sm
# KaoXpM0MMB0GA1UdDgQWBBQYAzlE2FRmHhfN6yxZ2FCoB6UYgTAOBgNVHQ8BAf8E
# BAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzBKBgNVHSAE
# QzBBMDUGDCsGAQQBsjEBAgEDAjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3Rp
# Z28uY29tL0NQUzAIBgZngQwBBAEwSQYDVR0fBEIwQDA+oDygOoY4aHR0cDovL2Ny
# bC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcmww
# eQYIKwYBBQUHAQEEbTBrMEQGCCsGAQUFBzAChjhodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNydDAjBggrBgEFBQcw
# AYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wHgYDVR0RBBcwFYETc3VwcG9ydEBy
# d3RzLmNvbS5hdTANBgkqhkiG9w0BAQwFAAOCAYEAdJPAl3pQsNjnku2c1YI2t4dN
# qqqWjhP+nr5SRRou3p88P+Mx+CU6DnKaSNmNltVh6IdADswqm4/6Dfm5gDc9HKN3
# R8u22DTE+oIpoORfmX7ZYHimdyMHaAF1WqiDNlqbt3UHE1/9ZOFRbn0XAWQpXEpk
# sVW9a7FKVqK1PpswbH0q2JfIr8TDM8/AQRk+GE3mZVfEfvuU2XcB2S3I5qhIXfTL
# 3/kHUYK43SvMYmnZqX08iIc4BwQpvSvaQeAiJ+pM2XuPfh4x+05BMfS85MdpEN0p
# uJDKf6ymW8ekBEh7rOuvmhv27KBqZLWVmIEb739iCSHwbvk5nCpn/8mEpe+Ki5b7
# JnoMXahCP2zwllKA+RgFlWvzFgGo1Es21P8m68ckvCa1tsNo+CizLYwXzapd3TNJ
# Bsi6NrVg95gz966qdyKSpGj5BlnMoR0xyFKGqggRtWTPRwkMo6NOrYYT0bHVF13E
# FIwoH5v8W8EgL4/qw6khfiKqqPUc6sbSKrWCqKi2MYIGJzCCBiMCAQEwaTBUMQsw
# CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJT
# ZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhEAyu6yTXnXONjJZZfx
# EYG4QDANBglghkgBZQMEAgEFAKBqMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBP
# ghy98gdyLl+ls8SLo1D+8SIRXEHcdMO2g104zoUlSDANBgkqhkiG9w0BAQEFAASC
# AgB/9Xsr4qgzT3b4J8kC1Pb41XzBQ5zGJ5kH3752gXTnT5D2k1OGpaZowGO7gLxG
# GGgPdFXSPa6nrzb/7u91MaTiZTpGe6I4heHMUiUgrrEk7cJI5IuxtqEeQYV9N1Fm
# pUk79Ib7onW3oCm9yhUZYx4fJEOCKRpHZ04P59z8rbyrIjyw5onJHnR0Q1NSkz9n
# /kN4VK0IXifNTwMcYnY3j/fgfcqN36atHiWMkBz+UaLk9uuA5ExO8rOTiHUSqeBU
# kJ4tv18hdvlefx8re8v7AIFXdlAxExgDUhi+LSmmim91gu3u3347dobCjAqV9MGk
# sBUM6+x3FjNP3M3nfLPAiSnR2DR25/pD7DL+VMiH6oWKzOueJ/X3AcWjdxVXC06/
# JfnH5ewKumPfzEBsAMGBqF9Nhgm0uFEnC4jO9pu12I5LySy0WZYEQRSlpJDBO4pv
# KvpXxE/ReUbQzved0jiGiOEDkltyeeRLP9aiOl5GhLpcPbm1JsbO/+SBWVwaLY/V
# EsbNsD8BTPW0+E+ES6v6dBDCZdXLXyRRlIWZa2AtlkqMIZSEo0J+ss58qSWxY/cy
# AMjceviy873f4EHgNdMoR8Gg8c94YAUloJdeQWfWXm/e1eYu6nRyzD1WXkoNb4Yl
# bTgrxUWBPTXcqTz6m0NPddhI93l2C7hYMAB5cij5VPFtcKGCAyMwggMfBgkqhkiG
# 9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNjEz
# NTYyOVowPwYJKoZIhvcNAQkEMTIEMGDzaXJJWjQn4Q4vZo4cWJlH1uXxG8p/oNXp
# BfEH3hUzXUstC0MoCa31urBF4lazyDANBgkqhkiG9w0BAQEFAASCAgB70U1PcghY
# oiS3lSub5CR2WxqsdxD8/RLWW9X5JoPDbOKCYGLDN+1BQtBy1uLZjeZSLPozYArH
# 7Haa42wP7CyrxP5dADEApXrAteHji2rKjDXCm1T8Bju8Mvbn/Lti3riIIWL/AphT
# hZO1fjlapsL6X+AKUrYpSeUiYIguw12JKOiTSggErs7532zIZ5JjFODUjM1JHMSd
# Wk7bv8a7qpwt5TJS02G4Hi39ph0r1CpWu4IzHxsyyCeDqb8e9Mj135SFcV2SOrUb
# zt8h3uk075hJBXMoHzoniwfdKeLzBtSxLvZkqHUdb4w8dr46H8jNF2Hjr70Swkdv
# hompsP5B12cVx6BUOkL7lxrmzMHIDFn5Y8o0vQhjtzPw8n0REdAiS3OG4yfZUVKT
# pS0hgAnWqA2az2f0UAOBuxFz1Iy8PV3M4cjC5x21enqAdXG4EjNpXjc+04YR0kID
# bERJOqn+QF1nfb3he5Dokrld2umJWnWrsVicgKRG0l4I26WsMNLEA/CTHXz1EzrX
# wG4TjHQgELKexUf5Yf4JWyhNhdp9Ft0Vv4UQ1LWvCS6epXaVALWCvOKA+Nko34f3
# 0Xor7zmD+vxUmDjBD1HZnKug+dWhECr9k31ixky0sODQ2FKoZ85hyw4P18QijtAK
# RAt/jScB7k7p4OGUKh2pJfpRAQcwzuAopw==
# SIG # End signature block
