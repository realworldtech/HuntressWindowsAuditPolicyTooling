[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TargetDomain,
    [switch]$AllDomains,
    [switch]$RemoveOverAuditingConflicts,
    [string]$BackupRoot = "$env:TEMP\DDCP-AuditPolicy-Backups"
)

#Requires -Modules GroupPolicy, ActiveDirectory

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$explicitWhatIf = $PSBoundParameters.ContainsKey('WhatIf')

$ddcpName = "Default Domain Controllers Policy"

# These subcategories are the overlapping settings we observed in DDCP and
# want Huntress' dedicated audit baseline GPO to own instead.
$conflictingSubcategories = @(
    "Account Lockout",
    "Application Group Management",
    "Computer Account Management",
    "Distribution Group Management",
    "Other Logon/Logoff Events",
    "Security Group Management",
    "User Account Management",
    "Special Logon"
)

$expectedAuditValues = @{
    "Account Lockout"                = 2
    "Application Group Management"   = 0
    "Computer Account Management"    = 3
    "Distribution Group Management"  = 3
    "Other Logon/Logoff Events"      = 3
    "Security Group Management"      = 3
    "User Account Management"        = 3
    "Special Logon"                  = 1
}

function Get-UpdatedMachineVersion {
    param([int]$CurrentVersionNumber)

    $userVersion = ($CurrentVersionNumber -shr 16) -band 0xFFFF
    $machineVersion = ($CurrentVersionNumber -band 0xFFFF) + 1
    return (($userVersion -shl 16) -bor $machineVersion)
}

function Update-GptIniVersion {
    param(
        [string]$Path,
        [int]$Version
    )

    $content = if (Test-Path $Path) {
        Get-Content -Path $Path -Raw
    } else {
        "[General]`r`nVersion=0`r`n"
    }

    if ($content -match '(?im)^Version=\d+\s*$') {
        $content = [regex]::Replace($content, '(?im)^Version=\d+\s*$', "Version=$Version")
    } else {
        $content = $content.TrimEnd() + "`r`nVersion=$Version`r`n"
    }

    Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Get-TargetDomains {
    if ($AllDomains) {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        return @($forest.Domains | ForEach-Object { $_.Name })
    }

    if ($TargetDomain) {
        return @($TargetDomain)
    }

    return @((Get-ADDomain).DNSRoot)
}

function Get-AuditCsvRows {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    $rows = Import-Csv -Path $Path
    return @($rows)
}

function Get-NormalizedSubcategoryName {
    param([string]$Subcategory)

    if ([string]::IsNullOrWhiteSpace($Subcategory)) {
        return ""
    }

    return (($Subcategory -replace '^Audit\s+', '').Trim())
}

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

function Convert-AuditRowToValue {
    param($Row)

    if (-not [string]::IsNullOrWhiteSpace($Row.'Setting Value')) {
        return [int]$Row.'Setting Value'
    }

    $inclusionSetting = if ($null -eq $Row.'Inclusion Setting') { '' } else { ([string]$Row.'Inclusion Setting').Trim() }

    switch ($inclusionSetting) {
        'No Auditing'         { return 0 }
        'Success'             { return 1 }
        'Failure'             { return 2 }
        'Success and Failure' { return 3 }
        default { throw "Unsupported audit row setting for subcategory '$($Row.Subcategory)'" }
    }
}

function Get-AuditDifferenceClassification {
    param(
        [int]$ExpectedValue,
        [int]$ActualValue
    )

    if ($ExpectedValue -eq $ActualValue) {
        return 'Match'
    }

    $hasAllExpectedBits = (($ActualValue -band $ExpectedValue) -eq $ExpectedValue)
    $hasOnlyExpectedBits = (($ActualValue -band (-bnot $ExpectedValue)) -eq 0)

    if ($hasAllExpectedBits -and -not $hasOnlyExpectedBits) {
        return 'Over-auditing only'
    }

    if ($hasOnlyExpectedBits -and -not $hasAllExpectedBits) {
        return 'Under-auditing'
    }

    return 'Different mode'
}

function Set-AuditCsvRows {
    param(
        [string]$Path,
        [array]$Rows
    )

    $header = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value"
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($header)

    foreach ($row in $Rows) {
        $fields = @(
            [string]$row.'Machine Name',
            [string]$row.'Policy Target',
            [string]$row.Subcategory,
            [string]$row.'Subcategory GUID',
            [string]$row.'Inclusion Setting',
            [string]$row.'Exclusion Setting',
            [string]$row.'Setting Value'
        )
        $lines.Add([string]::Join(',', $fields))
    }

    Set-Content -Path $Path -Value ($lines -join "`r`n") -Encoding Unicode
}

function Resolve-DDCPAuditConflictsForDomain {
    param(
        [string]$DomainFQDN,
        [System.Management.Automation.PSCmdlet]$CallerCmdlet
    )

    $domainDn = (Get-ADDomain -Identity $DomainFQDN -Server $DomainFQDN).DistinguishedName
    $gpo = Get-GPO -Name $ddcpName -Domain $DomainFQDN -ErrorAction Stop
    $gpoGuid = $gpo.Id.ToString("B").ToUpper()

    $policyRoot = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$gpoGuid"
    $auditCsvPath = Join-Path $policyRoot "Machine\Microsoft\Windows NT\Audit\audit.csv"
    $gptIniPath = Join-Path $policyRoot "GPT.INI"
    $gpoDn = "CN=$gpoGuid,CN=Policies,CN=System,$domainDn"

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Domain: $DomainFQDN" -ForegroundColor Cyan
    Write-Host "  GPO:    $ddcpName" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    $rows = Get-AuditCsvRows -Path $auditCsvPath
    if ($rows.Count -eq 0) {
        Write-Host "  No audit.csv found or no Advanced Audit Policy rows defined." -ForegroundColor Yellow
        return $null
    }

    if ($explicitWhatIf) {
        Write-Host ("[WhatIf] Existing DDCP subcategories: {0}" -f (($rows.Subcategory | Sort-Object) -join ', ')) -ForegroundColor DarkYellow
    }

    $matches = @(
        $rows | Where-Object {
            (Get-NormalizedSubcategoryName -Subcategory $_.Subcategory) -in $conflictingSubcategories
        }
    )
    if ($matches.Count -eq 0) {
        Write-Host "  No overlapping DDCP audit subcategories found." -ForegroundColor Green
        return [pscustomobject]@{
            Domain = $DomainFQDN
            Removed = 0
            Remaining = $rows.Count
            Changed = $false
        }
    }

    $classifiedMatches = @(
        foreach ($row in $matches) {
            $name = Get-NormalizedSubcategoryName -Subcategory $row.Subcategory
            $actualValue = Convert-AuditRowToValue -Row $row
            $expectedValue = [int]$expectedAuditValues[$name]
            [pscustomobject]@{
                Row            = $row
                Name           = $name
                ActualValue    = $actualValue
                ExpectedValue  = $expectedValue
                Classification = Get-AuditDifferenceClassification -ExpectedValue $expectedValue -ActualValue $actualValue
            }
        }
    )

    $rowsToRemove = @(
        $classifiedMatches | Where-Object {
            $RemoveOverAuditingConflicts -or $_.Classification -ne 'Over-auditing only'
        }
    )

    Write-Host ("  Overlapping DDCP subcategories found: {0}" -f (($matches.Subcategory | Sort-Object -Unique) -join ', ')) -ForegroundColor Yellow

    foreach ($item in $classifiedMatches) {
        Write-Host ("    - {0}: DDCP='{1}', Huntress='{2}' [{3}]" -f `
            $item.Name,
            (Convert-AuditValueToText -Value $item.ActualValue),
            (Convert-AuditValueToText -Value $item.ExpectedValue),
            $item.Classification) -ForegroundColor DarkYellow
    }

    if ($rowsToRemove.Count -eq 0) {
        Write-Host "  All overlapping DDCP rows are over-auditing-only supersets; leaving them untouched by default." -ForegroundColor Green
        return [pscustomobject]@{
            Domain = $DomainFQDN
            Removed = 0
            Remaining = $rows.Count
            Changed = $false
        }
    }

    if ($explicitWhatIf) {
        Write-Host ("[WhatIf] Would remove {0} DDCP row(s) from {1}" -f $rowsToRemove.Count, $ddcpName) -ForegroundColor DarkYellow
        if (-not $RemoveOverAuditingConflicts) {
            $leftInPlace = @($classifiedMatches | Where-Object { $_.Classification -eq 'Over-auditing only' })
            if ($leftInPlace.Count -gt 0) {
                Write-Host ("[WhatIf] Over-auditing-only rows left in place: {0}" -f ($leftInPlace.Name -join ', ')) -ForegroundColor DarkYellow
            }
        }
    }

    if (-not $CallerCmdlet.ShouldProcess("$ddcpName in $DomainFQDN", "Remove overlapping Huntress audit settings")) {
        return $null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $domainBackupRoot = Join-Path $BackupRoot ($DomainFQDN -replace '[^A-Za-z0-9\.-]', '_')
    New-Item -ItemType Directory -Path $domainBackupRoot -Force | Out-Null

    if (Test-Path $auditCsvPath) {
        $backupPath = Join-Path $domainBackupRoot "audit-$timestamp.csv"
        Copy-Item -Path $auditCsvPath -Destination $backupPath -Force
        Write-Host "  Backed up current audit.csv" -ForegroundColor DarkGreen
    }

    $newRows = @(
        $rows | Where-Object {
            $_ -notin $rowsToRemove.Row
        }
    )
    Set-AuditCsvRows -Path $auditCsvPath -Rows $newRows

    $adObject = Get-ADObject -Identity $gpoDn -Server $DomainFQDN -Properties versionNumber
    $newVersion = Get-UpdatedMachineVersion -CurrentVersionNumber ([int]$adObject.versionNumber)
    Set-ADObject -Identity $gpoDn -Server $DomainFQDN -Replace @{ versionNumber = $newVersion }
    Update-GptIniVersion -Path $gptIniPath -Version $newVersion

    Write-Host ("  Removed {0} row(s) from DDCP audit.csv" -f $rowsToRemove.Count) -ForegroundColor Green
    Write-Host ("  New machine row count: {0}" -f $newRows.Count) -ForegroundColor DarkGreen

    return [pscustomobject]@{
        Domain = $DomainFQDN
        Removed = $rowsToRemove.Count
        Remaining = $newRows.Count
        Changed = $true
    }
}

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$domains = Get-TargetDomains

if ($explicitWhatIf) {
    Write-Host ""
    Write-Host "[WhatIf] Planned DDCP conflict cleanup" -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] Target domain(s): {0}" -f ($domains -join ', ')) -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] GPO: {0}" -f $ddcpName) -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] Subcategories to remove: {0}" -f ($conflictingSubcategories -join ', ')) -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] Remove over-auditing-only conflicts: {0}" -f $RemoveOverAuditingConflicts) -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] Backup root: {0}" -f $BackupRoot) -ForegroundColor DarkYellow
}

$results = @()
foreach ($domain in $domains) {
    $result = Resolve-DDCPAuditConflictsForDomain -DomainFQDN $domain -CallerCmdlet $PSCmdlet
    if ($null -ne $result) {
        $results += $result
    }
}

if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host " DDCP AUDIT CONFLICT CLEANUP COMPLETE" -ForegroundColor Green
    Write-Host "===============================================================" -ForegroundColor Cyan

    foreach ($result in $results) {
        Write-Host ""
        Write-Host ("  Domain:    {0}" -f $result.Domain)
        Write-Host ("  Changed:   {0}" -f $(if ($result.Changed) { 'Yes' } else { 'No' }))
        Write-Host ("  Removed:   {0}" -f $result.Removed)
        Write-Host ("  Remaining: {0}" -f $result.Remaining)
    }

    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. gpupdate /force on a DC in each target domain"
    Write-Host "    2. Re-run auditpol /get /category:* on a test DC"
    Write-Host "    3. Confirm Huntress baseline now owns the overlapping subcategories"
    Write-Host ""
}

# SIG # Begin signature block
# MIIyhQYJKoZIhvcNAQcCoIIydjCCMnICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBslNHONDmkE7q/
# GquWS2XS1ejA00Q7PWRrqx9JurxlnaCCK7QwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB7
# 5BCJSdW0b+Ua/5hR9Oq5RtQTFIwwwJczdYEJVDnd7zANBgkqhkiG9w0BAQEFAASC
# AgCfApm2K4dfIRPG6Xk1RfEzhDAUvccT775JD/DwnpidwymmjdrZYlB/arko/Kdt
# 1DhnAoQEBGhCCYcWT2NePqbEtxPCsbFyDnD89wZvZXlc6t3uaeysAH+biVrWnu18
# Tw15dhWUE+tpm1e7EaM7q4/I38vk+FoXMJHpqCB6QheJHswGG/LBkVO+Lc3dPEnN
# bemGnCxllpRzemjzWnPqdrEtyymUZnvNq/GuHUKfr7KFJyLisnYJCYHQkdc3hv0a
# ojq/0wK2icOlmF3mSbxyhT6BwwMj9dcv6sIIy02xF9p6eL6m8Wavp8ms5+VPwyk9
# 0MBxalxQP8mYP/N4dXY26NEwqw4E6dGY/fvJZBbzxcryrxo8aYzswddQkzABm9ZP
# MoxT0VU9HG2KqcV9lIRJ0ZH9WLwWXusP96O0VDAxPLEfSis4VNcnVbyx85Esw1GU
# Fb5kexNH8BE7JGBg/o/XJlHFHrCUKmTSRWIXG8eGrixA/j1CtSTSoXLxEu/UXgKK
# +ttu6KuWntilfya79bHJmJvOp1T+dUkllrMGmasHLfL90rj2nylhYl4uktYkEv91
# l+0TAo5hEAGQSJaSrdyM4n5jb+baiMwuCmbPzY4PqUNkFqGCAyMwggMfBgkqhkiG
# 9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNjE1
# MjcxM1owPwYJKoZIhvcNAQkEMTIEMOCnb6L9MHfRu0xCNWydjACwx/qfbCp4qCrp
# aK+c2qErzsR3RJgfCZaAA84nx7wPJDANBgkqhkiG9w0BAQEFAASCAgAJcSAUMpXH
# 08rsk0FW8TSQOEz0U1kRcLNoWOUJuYs8jG53UiFXUUCgW0zggtHXS8wCbJSjb1fc
# MkDCD1ms1g93ADPdodF8j+wN6+d8zofFfB9Fmf3PEgMryZ6dSnVWyCGxmfF4d0ly
# J9mntUtJ4IaMg9AQ10gT+tztHF2UZ2EWr/IHP6GfYXBeqPMBLl4P7DH01lh/zOI1
# UN+72etW5Fh4M23emPHD01aFJxVIkUV40JHfhJOcbbK2/tFzBo6OwsaJs+DbdSIn
# qI86fkah5m8uIupJKdxkaYphSONUxXR6Kqrd97GwbrDuZ8SSBktdrWZ/HVjJDJfy
# SwnOVo9rg6tz2bdwyqqIkRO2jjzV/8TxZans2vxLws+UYuap8JoGQ1zFwe0R2osr
# zC/hf7i76vq4z0r14UzbWF1CM2/L1Awsj11JSYqJH5e2OWc/7CR8g5Ss2zpctHAc
# MqUA1yW5In+vC+fE9SnHpJKx+t9KYGAdImN7bBEOT+NTAIuUvoCrkAYxLe+qjQem
# 3rQ/N7cJG7qWx8KDul5OLsn5ucCkVrWWpe6tZMzadCp3J88wUfP+qzujg+LaLXiM
# 4W2Z59HkSbrKj8ulns3cTChnrgjWh7IfJ2lTc3Ix3iAXfy4KqO997qDGfXZ8O1KJ
# Npuse0harM/SHVEu7UwkcP8DFhUWV5xmWw==
# SIG # End signature block
