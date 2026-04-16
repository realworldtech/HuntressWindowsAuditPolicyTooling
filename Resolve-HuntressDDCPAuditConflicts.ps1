[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TargetDomain,
    [switch]$AllDomains,
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

    Write-Host ("  Conflicting subcategories found: {0}" -f (($matches.Subcategory | Sort-Object -Unique) -join ', ')) -ForegroundColor Yellow

    if ($explicitWhatIf) {
        Write-Host ("[WhatIf] Would remove {0} overlapping row(s) from {1}" -f $matches.Count, $ddcpName) -ForegroundColor DarkYellow
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
            (Get-NormalizedSubcategoryName -Subcategory $_.Subcategory) -notin $conflictingSubcategories
        }
    )
    Set-AuditCsvRows -Path $auditCsvPath -Rows $newRows

    $adObject = Get-ADObject -Identity $gpoDn -Server $DomainFQDN -Properties versionNumber
    $newVersion = Get-UpdatedMachineVersion -CurrentVersionNumber ([int]$adObject.versionNumber)
    Set-ADObject -Identity $gpoDn -Server $DomainFQDN -Replace @{ versionNumber = $newVersion }
    Update-GptIniVersion -Path $gptIniPath -Version $newVersion

    Write-Host ("  Removed {0} row(s) from DDCP audit.csv" -f $matches.Count) -ForegroundColor Green
    Write-Host ("  New machine row count: {0}" -f $newRows.Count) -ForegroundColor DarkGreen

    return [pscustomobject]@{
        Domain = $DomainFQDN
        Removed = $matches.Count
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
# MIJlLwYJKoZIhvcNAQcCoIJlIDCCZRwCAQExHDALBglghkgBZQMEAgIwDQYJYIZI
# AWUDBAIBBQAweQYKKwYBBAGCNwIBBKBrMGkwNAYKKwYBBAGCNwIBHjAmAgMBAAAE
# EB/MO2BZSwhOtyTSxil+81ECAQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEF
# AAQg5uXpJq7YgFzpp2dNwCXxaeNfgHDg0zj4acyS8Nyi1IWggiu0MIIFbzCCBFeg
# AwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0BAQwFADB7MQswCQYDVQQG
# EwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxm
# b3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENl
# cnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAwMFoXDTI4MTIzMTIzNTk1
# OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEtMCsG
# A1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIFJvb3QgUjQ2MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIEJHQu/xYjApKKtq42haxH
# 1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7fbu2ir29BX8nm2tl06UM
# abG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGrYbNzszwLDO/bM1flvjQ3
# 45cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTHqi0Eq8Nq6uAvp6fcbtfo
# /9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv64IplXCN/7sVz/7RDzai
# Lk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2JmRCxrds+LOSqGLDGBwF1
# Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0POM1nqFOI+rgwZfpvx+cd
# sYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXybGWfv1VbHJxXGsd4Rnxw
# qpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyheBe6QTHrnxvTQ/PrNPjJG
# EyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXycuu7D1fkKdvp+BRtAypI1
# 6dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7idFT/+IAx1yCJaE5UZkADp
# GtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQYMBaAFKARCiM+lvEH7OKv
# Ke+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAOBgNVHQ8B
# Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDAzAb
# BgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3Js
# MDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2Rv
# Y2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3SamES4aUa1qyQKDKSKZ7g6
# gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+BtlcY2fUQBaHRIZyKtYy
# FfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8ZsBRNraJAlTH/Fj7bADu
# /pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx2jLsFeSmTD1sOXPUC4U5
# IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyoXZ3JHFuu2PMvdM+4fvbX
# g50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p1FiAhORFe1rYMIIGFDCC
# A/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0BAQwFADBXMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0
# aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAwMDAw
# MFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGlu
# ZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDNmNhDQatu
# givs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7wYUrUlY3mFyI32t2
# o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc81KnBkAWgsaXnLURo
# YZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ4ujOGIaBhPXG2NdV8TNg
# FWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOywwRMUi54fr2vFsU5
# QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTWw9jiCKv31pcAaeij
# S9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHWZUEhnRfs/hsp/fwk
# Xsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhdFczf8O+pDiyGhVYX
# +bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15OApZYK8CAwEAAaOC
# AVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AKPRQlMB0GA1UdDgQW
# BBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/
# BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUd
# IAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0
# aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYIKwYBBQUHAQEEcDBu
# MEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJs
# aWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29j
# c3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBABLXeyCtDjVYDJ6BHSVY
# /UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcwDMZhHOmbyMhyOVJD
# wm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16mNIUlNTkpJEor7edV
# JZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGBp6rEs9sEiq/pwzvg
# 2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/Qrd+mOCJemo06ldo
# n4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlOtyaFTAjD2Nu+di5h
# ErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4ACMRCgXjYfQEDtYEK5
# 4dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYFkLqYmgHjR3tKVkhh
# 9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9GX/n1PggkGi9HCap
# Zp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJMf0o8LLrFkSLRQNwx
# PDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK95tBO8aTHmEa4lpJ
# VD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEc
# CjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcg
# Um9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0
# aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEF
# AAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3ll
# MwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioX
# an1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0
# VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN
# 43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4e
# d8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jr
# OW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELc
# vzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIyp
# xR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWW
# SC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYD
# VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECg
# PqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2ln
# bmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0
# cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290
# UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetA
# QLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6
# mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyx
# f5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l
# 4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2Xl
# ZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCs
# dbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93a
# t3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l
# 75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHM
# Viw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prq
# ooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kc
# MIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQwDQYJKoZIhvcNAQEMBQAw
# VTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UE
# AxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYwHhcNMjUwMzI3
# MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQGEwJHQjEXMBUGA1UECBMO
# V2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UE
# AxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM2MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6kU3jyPRBLeBIHPNyUgVNn
# YayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5JIjKNf75QBha2Ddj+4NEP
# KDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc6BbsNBzjHTt7FngNfhfJ
# oYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5tJD92iFAIbKHQWGbCQNY
# plqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe60vzvrk0HG+iVcwVZjz+
# t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D40GofV7O8WzgaAnZmoUn
# 4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH0MmGzlBUylhXvdNVXcjA
# uIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcmYaOBZKlwPP7pOp5Mzx/U
# MhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw3lHACnLilGETXRg5X/Fp
# 8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0KdRZHPcuSL5OAGWnBjAl
# RtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVbySnXnkujjhIh+oaatsk/
# oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1S
# gLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx0Iz9LALOTzAOBgNVHQ8B
# Af8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBK
# BgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczov
# L3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0
# cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FS
# MzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMG
# CCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu6r7vmzXXLpJx4FyGmcqn
# FZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrusDh9NgYwiGDOhyyJ2zRy3
# +kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM4WXA3ZHcNHB4V42zi7Jk
# 3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQXPgMqvzodgQJEkxaION5X
# RCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0MOt3ccgwn4Kl2FIcQaV55
# nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jOQ66Fhk3NWbg2tYl5jhQC
# uIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ026JxHhr2fuJ0mV68AluF
# r9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWwi4hmpylUfygtYLEdLQuk
# NEX1jiOKMIIGgTCCBGmgAwIBAgIQAnw5AQynWsM6te4NVA755TANBgkqhkiG9w0B
# AQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNV
# BAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsx
# LjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
# HhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+shJHjUoq1
# 4pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCDJ9qaDStQ
# 6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7P2bSlDFp
# +m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extmeme/G3h+p
# DHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUzT2MuuC3h
# v2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6qRT5uWl+P
# oVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mczmrYI4IAF
# SEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEcQNYWFyn8
# XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2TOglmmVhc
# KaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/AZwQsRb8
# zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QIDAQABo4IB
# FjCCARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYE
# FDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8E
# BTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGA1UdIAQKMAgwBgYEVR0gADBQ
# BgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYIKwYBBQUHAQEEKTAn
# MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3
# DQEBDAUAA4ICAQBfHYHOUvth+43SceEtI4YqgnlKuPoaE+1ucOskvqnva/yLCD4B
# ZT4dYLEt04YG3m+hef+ZXdEKeFscAZpe4EesqsPB+X7IfHhTjS2yO15VwFtGdB56
# WX7HgFyLMmaEgJ9NKjFVaOFZb4mIStcdamlS5iDbFXFUGGtIlIdtgy+nhdpPXR4T
# L+z16QY4PHD7+aZ5J6/z8uD9wpnzI1jF7eF+7I/ekvCCiLw5vFYVcqvlOViI9VZm
# nYtDg1HAdTCOqPbPhVqzS+KRftx8+VGmJCTpVTxOmkW7uXbdDDOSG572ZPDWUU4l
# cHcwnfaR1zKob5u4uvbgigqe+pp+bmiW628Wqx1775G9LqiW26foBCmeHLq7AYlr
# t33KAW0/oocWV8FF0/BSRY5kiq9IHh/CTt+tAjXjAwy0RLtsXyfvEjiKzaQW8W2Q
# U1tlLJVXVmLmfNxGlJLG65RvdR9cpZE10B8KWleHm6KfNWfcYmdTFbg1TpV8Bh9F
# hJcXxOjbrZpQOTaab9gTxyqOzOeD3mqUmHjb++lg6k9gyp2qEOaqY+mfJ1/wc4in
# tu3qCRFRiEQF5mjhrovhe0S2NYgwjDWjlctIO1wZ13Cwq5xjy0W7tiy3kHigxZBF
# 0MuqHkrtE1k3jTbYZdt6mifshQ0uiP/7C1Up/gZMhGvcAfKxxdnE05oTJDCCBoIw
# ggRqoAMCAQICEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEMBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkg
# Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVV
# U0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIxMDMyMjAw
# MDAwMFoXDTM4MDExODIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFt
# cGluZyBSb290IFI0NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIid
# 2LlFZ50d3ei5JoGaVFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQkiUv
# pVdYqZ1uYoZEMgtHES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx4IBr
# Aou7hNGsKioIBPy5GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4vvyV
# DQGsd5KarLW5d73E3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6IuHJ
# orEu6EopoB1CNFp/+HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid61qmr
# lD/IbKJA6COw/8lFSPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR3ZUw
# xDKL1wCAxgL2Mpz7eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM8/6N
# nWH3T9ClmcGSF22LEyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7ALL8b
# AJyPDmubNqMtuaobKASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6tG9o
# j7liwPddXEcYGOUiWLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAHteOR
# lsSuDt5t4BBRCJL+5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjggEWMIIBEjAfBgNV
# HSMEGDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQU9ndq3T/9ARP/
# FqFsggIv0Ao9FCUwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcw
# RaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0
# aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUH
# MAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIB
# AA6+ZUHtaES45aHF1BGH5Lc7JYzrftrIF5Ht2PFDxKKFOct/awAEWgHQMVHol9ZL
# Syd/pYMbaC0IZ+XBW9xhdkkmUV/KbUOiL7g98M/yzRyqUOZ1/IY7Ay0YbMniIibJ
# rPcgFp73WDnRDKtVutShPSZQZAdtFwXnuiWl8eFARK3PmLqEm9UsVX+55DbVIz33
# Mbhba0HUTEYv3yJ1fwKGxPBsP/MgTECimh7eXomvMm0/GPxX2uhwCcs/YLxDnBdV
# VlxvDjHjO1cuwbOpkiJGHmLXXVNbsdXUC2xBrq9fLrfe8IBsA4hopwsCj8hTuwKX
# JlSTrZcPRVSccP5i9U28gZ7OMzoJGlxZ5384OKm0r568Mo9TYrqzKeKZgFo0fj2/
# 0iHbj55hc20jfxvK3mQi+H7xpbzxZOFGm/yVQkpo+ffv5gdhp+hv1GDsvJOtJinJ
# mgGbBFZIThbqI+MHvAmMmkfb3fTxmSkop2mSJL1Y2x/955S29Gu0gSJIkc3z30vU
# /iXrMpWx2tS7UVfVP+5tKuzGtgkP7d/doqDrLF1u6Ci3TpjAZdeLLlRQZm867eVe
# XED58LXd1Dk6UvaAhvmWYXoiLz4JA5gPBcz7J311uahxCweNxE+xxxR3kT0WKzAS
# o5G/PyDez6NHdIUKBeE3jDPs2ACc6CkJ1Sji4PKWVT0/MIIGljCCBP6gAwIBAgIR
# AMrusk151zjYyWWX8RGBuEAwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJs
# aWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yNjA0MTUwMDAwMDBaFw0yNzA0MTUy
# MzU5NTlaMIGLMQswCQYDVQQGEwJBVTEYMBYGA1UECAwPTmV3IFNvdXRoIFdhbGVz
# MTAwLgYDVQQKDCdSZWFsIFdvcmxkIFRlY2hub2xvZ3kgU29sdXRpb25zIFB0eSBM
# dGQxMDAuBgNVBAMMJ1JlYWwgV29ybGQgVGVjaG5vbG9neSBTb2x1dGlvbnMgUHR5
# IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbUV0HrDaDb7VKq
# 6h3XyvtZxDE3D0ja5iueR6ojVgFpgTzdSQklJIEptROiXwKAuVzg1artOa/VyEbA
# lI34XMwG3Ary44K2il7+zesRk4oMiHt3tGgmBhCF1nFNMlQy/OkVSub/uTD/Yiuk
# k3m0xPOBCRAP6r9eP31VqDhRk/1b6IwE+bCSyX0oWGGhRXojsMTiuiYqU9rhYbt8
# zPgXKJZIjc3z4C0sMO2E3pUy+F3N5wlBimkLw6pl2UZSa5Jp1/fYmJzRqsZ9U23f
# 0KFxROwgWZxIO4NQfof5LqMDz/nulv3dABCeiayS3O81GrWRgXc93gXNM6YaVAfq
# Iu4sirf4v8MLdanLvA9JMOalqLeTW3tuq73h9EuS+EMp7lR7jImVBBWNRatkFbQM
# h8go96Llal+yZcxp2BNPKIA9aI2HkPbMGDGlBXSIJ8XYtAyalqn8inf2Ut8PahEk
# 26bj2dYk5hP1O7PK2mOuipZZz8nsHxjhc1vw0OI28vJfhYQQcq5W/UjETgVqf8PH
# w/qAEDoupKvR0nxOQuaEkscJowUL1ocrW71BRSTvsijDqoL9g4tWzwk7PsfjRODL
# CtJMIMAFgOhtN69hTVvnh2PrXR/4L8uxzIqQ4hDz21+4XHAzjtVSrBtwLDhqK4/l
# YfxUimwgKo6i50gDDuUITo9ZCyQRAgMBAAGjggGpMIIBpTAfBgNVHSMEGDAWgBQP
# Kssghyi47G9IritUpimqF6TNDDAdBgNVHQ4EFgQUGAM5RNhUZh4XzessWdhQqAel
# GIEwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYX
# aHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8
# oDqGOGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWdu
# aW5nQ0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDov
# L2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5j
# cnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMB4GA1UdEQQX
# MBWBE3N1cHBvcnRAcnd0cy5jb20uYXUwDQYJKoZIhvcNAQEMBQADggGBAHSTwJd6
# ULDY55LtnNWCNreHTaqqlo4T/p6+UkUaLt6fPD/jMfglOg5ymkjZjZbVYeiHQA7M
# KpuP+g35uYA3PRyjd0fLttg0xPqCKaDkX5l+2WB4pncjB2gBdVqogzZam7d1BxNf
# /WThUW59FwFkKVxKZLFVvWuxSlaitT6bMGx9KtiXyK/EwzPPwEEZPhhN5mVXxH77
# lNl3AdktyOaoSF30y9/5B1GCuN0rzGJp2al9PIiHOAcEKb0r2kHgIifqTNl7j34e
# MftOQTH0vOTHaRDdKbiQyn+splvHpARIe6zrr5ob9uygamS1lZiBG+9/Ygkh8G75
# OZwqZ//JhKXviouW+yZ6DF2oQj9s8JZSgPkYBZVr8xYBqNRLNtT/JuvHJLwmtbbD
# aPgosy2MF82qXd0zSQbIuja1YPeYM/euqncikqRo+QZZzKEdMchShqoIEbVkz0cJ
# DKOjTq2GE9Gx1RddxBSMKB+b/FvBIC+P6sOpIX4iqqj1HOrG0iq1gqiotjGCOMQw
# gjjAAgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIR
# AMrusk151zjYyWWX8RGBuEAwDQYJYIZIAWUDBAIBBQCgajAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkq
# hkiG9w0BCQQxIgQgfCnyM4kx8I6tAkfyXOltM4yXoCX/zE6uzCxd9Xu3xUkwDQYJ
# KoZIhvcNAQEBBQAEggIAFz/6lHSDCcnkY7pWhyknmhxcv/igNsS85pof38aHu+3V
# hExWWM5QlotQsLCckuXSznES7S+8qYmovjJ+S2v9bNsD2rrX2gs2djo65LLLkvYz
# +d0NpHZC0af+4r2Zv58QRkSLs7VV2ANxa1Kl4OLpu81PoB+Y0+WwTOL+HkODr9Fw
# g/YcNmu8n5VpA69/nsS9Li6Sh/dDUGVre5WVphx33k0VtoOjjzMGW5Vp41odMSV8
# Bsp2NAgH0WynJHjBc9NXovW9f8KDzYEwhuMSVnZNtr5PO/mkXr4G+BfTGPqzaej+
# JV9Wn6Noc5ODBVtGB/Ax16xEzJj+r9Mc/mpny7gQ3CSsj6cTchAZ/Nw5wV+CzzkY
# b+j9E5dWoUL+hCMvRyqmvYeL9SeJD8iA2S7SPVZSi/SUyiJrlCynecFfT+3PlMQd
# dBE6kpX4uuIEYND3JanJXT3t3Io8HYpiSx1zgyGJpyVyeh/3xSCvQarxjH9JsXF6
# 39upXTqhb+Y7PXChwSTb/eK3Vt/3u7uP4y6qO9PmC5zwCvqlT25zQ5MEkIuilloj
# 9LB9XF/hzkiZtQ2ydyEeEHJW6AX7iR7iSIj2c5X2BptCTZ1s+VOxW4Fi6aN+EJZA
# KyT518SIp0TX1SMZAg0vLK5izCGJIBtK5Pnsh4k33fD62GlKZ2NjZk6G/TlRid+h
# gjXAMIIDHwYJKoZIhvcNAQkGMYIDEDCCAwwCAQEwajBVMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1Ymxp
# YyBUaW1lIFN0YW1waW5nIENBIFIzNgIRAKQpO24e3denNAiHrXpOtyQwDQYJYIZI
# AWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MTYxMzU2MjVaMD8GCSqGSIb3DQEJBDEyBDD98S4+zps/WrLDj1T+
# AY1XmmNbu2Fjdk6ETA33IvR7YcfcQ6SyTT4BKoHwcfJEnP8wDQYJKoZIhvcNAQEB
# BQAEggIAJyGRbOf5JDRQwJ/MVrJGMRlnhibFQYSk1ojrSlx4rnLqET+amdeN/4xM
# sv2o8plHc/FiNVGq3C6KxlL0MzViW3kbGkJ/uDbqLZXTru+27TvKExDsZdJ9bixh
# sGnaAmhKo9rcRU/Wx9H+ICkdY9k98997Pwc3szsncaSGDgxWFMViNTa9goKsiHUE
# gfmrdld06OmcyzJVtJpMHPYWKT/2jv5mNmAKqkoPPns4JGP48Q/fc+QV6jDGsBRS
# 0on1TRrLCbwXyUMceQ6N+PYc/Ganq7z+j2w4C+BCR484EObjeE41LxEvxQQrZ3fF
# kVE8RITX8Fww4uDGH36Y7valnBymYfJq+015rDsuGwbqR1BXskaec5dPK33UAJiG
# W33L+t/TgtvybhLaX6d2tJpi1fqKQCyvnUT5W9qMJVNPhT/stK+unZ4bqaJi+Psy
# TQHZ7o14FZQbXToNMZt8zGQCzwOAHUfOW0BTb8IBC0KQdIPUbGuEya+Ksi3YfWQZ
# NQiaDoM9Edn3VmsKA8uWLMjjCjAiVIskn/J9YVH0suqAyk95mRojTEmId83IpNhY
# VB7QYZqzvSsDqooAtXI9j//M97LXScqNtb206ERkNn/60w7Pmj/26Y0v3BWffg8P
# dG5GRKZltxvFWBXBsxv5TbQ16QwFWt/ww5JmxjwnS6Tem8KBG+cwgjKZBgorBgEE
# AYI3AgQBMYIyiTCCMoUGCSqGSIb3DQEHAqCCMnYwgjJyAgEBMQ8wDQYJYIZIAWUD
# BAIBBQAweQYKKwYBBAGCNwIBBKBrMGkwNAYKKwYBBAGCNwIBHjAmAgMBAAAEEB/M
# O2BZSwhOtyTSxil+81ECAQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
# FA1T8xOCG+my+YUyhs9bTLi2dHvv3g+4FxMbUV86Aneggiu0MIIFbzCCBFegAwIB
# AgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0BAQwFADB7MQswCQYDVQQGEwJH
# QjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3Jk
# MRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRp
# ZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAwMFoXDTI4MTIzMTIzNTk1OVow
# VjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEtMCsGA1UE
# AxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIFJvb3QgUjQ2MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIEJHQu/xYjApKKtq42haxH1COR
# Kz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7fbu2ir29BX8nm2tl06UMabG8
# STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGrYbNzszwLDO/bM1flvjQ345cb
# Xf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTHqi0Eq8Nq6uAvp6fcbtfo/9oh
# q0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv64IplXCN/7sVz/7RDzaiLk8y
# kHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2JmRCxrds+LOSqGLDGBwF1Z95t
# 6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0POM1nqFOI+rgwZfpvx+cdsYN0
# aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXybGWfv1VbHJxXGsd4RnxwqpQb
# ghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyheBe6QTHrnxvTQ/PrNPjJGEyA2
# igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXycuu7D1fkKdvp+BRtAypI16dV6
# 0bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7idFT/+IAx1yCJaE5UZkADpGtXC
# hvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQYMBaAFKARCiM+lvEH7OKvKe+C
# pX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAOBgNVHQ8BAf8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNV
# HSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQG
# CCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2Eu
# Y29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3SamES4aUa1qyQKDKSKZ7g6gb9F
# in1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+BtlcY2fUQBaHRIZyKtYyFfUS
# g8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8ZsBRNraJAlTH/Fj7bADu/pim
# LpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx2jLsFeSmTD1sOXPUC4U5IOCF
# Gmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyoXZ3JHFuu2PMvdM+4fvbXg50R
# lmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p1FiAhORFe1rYMIIGFDCCA/yg
# AwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0BAQwFADBXMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdv
# IFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAwMDAwMFoX
# DTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDNmNhDQatugivs
# 9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7wYUrUlY3mFyI32t2o6Ft
# 3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc81KnBkAWgsaXnLURoYZzk
# sHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ4ujOGIaBhPXG2NdV8TNgFWZ9
# BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOywwRMUi54fr2vFsU5QPrg
# b6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTWw9jiCKv31pcAaeijS9fc
# 6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHWZUEhnRfs/hsp/fwkXsyn
# u1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhdFczf8O+pDiyGhVYX+bDD
# P3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15OApZYK8CAwEAAaOCAVww
# ggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AKPRQlMB0GA1UdDgQWBBRf
# WO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgw
# BgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAw
# TAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYIKwYBBQUHAQEEcDBuMEcG
# CCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNU
# aW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBABLXeyCtDjVYDJ6BHSVY/Uwt
# Z3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcwDMZhHOmbyMhyOVJDwm1y
# rKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16mNIUlNTkpJEor7edVJZiR
# JVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGBp6rEs9sEiq/pwzvg2/Kj
# XE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/Qrd+mOCJemo06ldon4pJ
# FbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlOtyaFTAjD2Nu+di5hErEV
# VaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4ACMRCgXjYfQEDtYEK54dUw
# PJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYFkLqYmgHjR3tKVkhh9qKV
# 2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9GX/n1PggkGi9HCapZp8f
# Rwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJMf0o8LLrFkSLRQNwxPDDk
# WXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK95tBO8aTHmEa4lpJVD7H
# rTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjAN
# BgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9v
# dCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOC
# AY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsR
# HgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1h
# laGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJi
# JPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc
# 4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8pe
# NWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+L
# PmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUH
# f9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//
# YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8o
# QEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0P
# AQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8
# hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmlu
# Z1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDov
# L2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2
# LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZI
# hvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI
# 1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7y
# IawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XW
# KZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w
# 3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuc
# hC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0
# czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VD
# cOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy
# +hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1
# +sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2
# bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIG
# YjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQwDQYJKoZIhvcNAQEMBQAwVTEL
# MAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMj
# U2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYwHhcNMjUwMzI3MDAw
# MDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQGEwJHQjEXMBUGA1UECBMOV2Vz
# dCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMn
# U2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM2MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6kU3jyPRBLeBIHPNyUgVNnYayf
# sGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5JIjKNf75QBha2Ddj+4NEPKDxH
# Ed4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc6BbsNBzjHTt7FngNfhfJoYOr
# kugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5tJD92iFAIbKHQWGbCQNYplqp
# AFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe60vzvrk0HG+iVcwVZjz+t5Oc
# XGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D40GofV7O8WzgaAnZmoUn4PCp
# vH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH0MmGzlBUylhXvdNVXcjAuIEc
# EQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcmYaOBZKlwPP7pOp5Mzx/UMhyB
# A93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw3lHACnLilGETXRg5X/Fp8G8q
# lG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0KdRZHPcuSL5OAGWnBjAlRtHv
# sMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVbySnXnkujjhIh+oaatsk/oyf5
# R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1SgLqz
# YZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx0Iz9LALOTzAOBgNVHQ8BAf8E
# BAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNV
# HSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3Nl
# Y3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDov
# L2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYu
# Y3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMGCCsG
# AQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu6r7vmzXXLpJx4FyGmcqnFZoa
# 1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrusDh9NgYwiGDOhyyJ2zRy3+kdq
# hwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM4WXA3ZHcNHB4V42zi7Jk3ktE
# nkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQXPgMqvzodgQJEkxaION5XRCoB
# xAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0MOt3ccgwn4Kl2FIcQaV55nkjv
# 1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jOQ66Fhk3NWbg2tYl5jhQCuIsE
# 55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ026JxHhr2fuJ0mV68AluFr9qs
# hgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWwi4hmpylUfygtYLEdLQukNEX1
# jiOKMIIGgTCCBGmgAwIBAgIQAnw5AQynWsM6te4NVA755TANBgkqhkiG9w0BAQwF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcN
# MjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBWMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBD
# b2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+shJHjUoq14pbe
# 0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCDJ9qaDStQ6Utb
# s7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7P2bSlDFp+m2z
# NKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extmeme/G3h+pDHaz
# JyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUzT2MuuC3hv2Wn
# BGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6qRT5uWl+PoVvL
# nTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mczmrYI4IAFSEDu
# 9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEcQNYWFyn8XJwY
# K+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2TOglmmVhcKaO5
# DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/AZwQsRb8zG4Y
# 3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QIDAQABo4IBFjCC
# ARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFDLr
# kpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNV
# HR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0
# UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYIKwYBBQUHAQEEKTAnMCUG
# CCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEB
# DAUAA4ICAQBfHYHOUvth+43SceEtI4YqgnlKuPoaE+1ucOskvqnva/yLCD4BZT4d
# YLEt04YG3m+hef+ZXdEKeFscAZpe4EesqsPB+X7IfHhTjS2yO15VwFtGdB56WX7H
# gFyLMmaEgJ9NKjFVaOFZb4mIStcdamlS5iDbFXFUGGtIlIdtgy+nhdpPXR4TL+z1
# 6QY4PHD7+aZ5J6/z8uD9wpnzI1jF7eF+7I/ekvCCiLw5vFYVcqvlOViI9VZmnYtD
# g1HAdTCOqPbPhVqzS+KRftx8+VGmJCTpVTxOmkW7uXbdDDOSG572ZPDWUU4lcHcw
# nfaR1zKob5u4uvbgigqe+pp+bmiW628Wqx1775G9LqiW26foBCmeHLq7AYlrt33K
# AW0/oocWV8FF0/BSRY5kiq9IHh/CTt+tAjXjAwy0RLtsXyfvEjiKzaQW8W2QU1tl
# LJVXVmLmfNxGlJLG65RvdR9cpZE10B8KWleHm6KfNWfcYmdTFbg1TpV8Bh9FhJcX
# xOjbrZpQOTaab9gTxyqOzOeD3mqUmHjb++lg6k9gyp2qEOaqY+mfJ1/wc4intu3q
# CRFRiEQF5mjhrovhe0S2NYgwjDWjlctIO1wZ13Cwq5xjy0W7tiy3kHigxZBF0Muq
# HkrtE1k3jTbYZdt6mifshQ0uiP/7C1Up/gZMhGvcAfKxxdnE05oTJDCCBoIwggRq
# oAMCAQICEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0
# eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VS
# VHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIxMDMyMjAwMDAw
# MFoXDTM4MDExODIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGlu
# ZyBSb290IFI0NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIid2LlF
# Z50d3ei5JoGaVFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQkiUvpVdY
# qZ1uYoZEMgtHES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx4IBrAou7
# hNGsKioIBPy5GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4vvyVDQGs
# d5KarLW5d73E3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6IuHJorEu
# 6EopoB1CNFp/+HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid61qmrlD/I
# bKJA6COw/8lFSPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR3ZUwxDKL
# 1wCAxgL2Mpz7eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM8/6NnWH3
# T9ClmcGSF22LEyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7ALL8bAJyP
# DmubNqMtuaobKASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6tG9oj7li
# wPddXEcYGOUiWLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAHteORlsSu
# Dt5t4BBRCJL+5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjggEWMIIBEjAfBgNVHSME
# GDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQU9ndq3T/9ARP/FqFs
# ggIv0Ao9FCUwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBD
# oEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZp
# Y2F0aW9uQXV0aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGG
# GWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAA6+
# ZUHtaES45aHF1BGH5Lc7JYzrftrIF5Ht2PFDxKKFOct/awAEWgHQMVHol9ZLSyd/
# pYMbaC0IZ+XBW9xhdkkmUV/KbUOiL7g98M/yzRyqUOZ1/IY7Ay0YbMniIibJrPcg
# Fp73WDnRDKtVutShPSZQZAdtFwXnuiWl8eFARK3PmLqEm9UsVX+55DbVIz33Mbhb
# a0HUTEYv3yJ1fwKGxPBsP/MgTECimh7eXomvMm0/GPxX2uhwCcs/YLxDnBdVVlxv
# DjHjO1cuwbOpkiJGHmLXXVNbsdXUC2xBrq9fLrfe8IBsA4hopwsCj8hTuwKXJlST
# rZcPRVSccP5i9U28gZ7OMzoJGlxZ5384OKm0r568Mo9TYrqzKeKZgFo0fj2/0iHb
# j55hc20jfxvK3mQi+H7xpbzxZOFGm/yVQkpo+ffv5gdhp+hv1GDsvJOtJinJmgGb
# BFZIThbqI+MHvAmMmkfb3fTxmSkop2mSJL1Y2x/955S29Gu0gSJIkc3z30vU/iXr
# MpWx2tS7UVfVP+5tKuzGtgkP7d/doqDrLF1u6Ci3TpjAZdeLLlRQZm867eVeXED5
# 8LXd1Dk6UvaAhvmWYXoiLz4JA5gPBcz7J311uahxCweNxE+xxxR3kT0WKzASo5G/
# PyDez6NHdIUKBeE3jDPs2ACc6CkJ1Sji4PKWVT0/MIIGljCCBP6gAwIBAgIRAMru
# sk151zjYyWWX8RGBuEAwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMCR0IxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMg
# Q29kZSBTaWduaW5nIENBIFIzNjAeFw0yNjA0MTUwMDAwMDBaFw0yNzA0MTUyMzU5
# NTlaMIGLMQswCQYDVQQGEwJBVTEYMBYGA1UECAwPTmV3IFNvdXRoIFdhbGVzMTAw
# LgYDVQQKDCdSZWFsIFdvcmxkIFRlY2hub2xvZ3kgU29sdXRpb25zIFB0eSBMdGQx
# MDAuBgNVBAMMJ1JlYWwgV29ybGQgVGVjaG5vbG9neSBTb2x1dGlvbnMgUHR5IEx0
# ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbUV0HrDaDb7VKq6h3X
# yvtZxDE3D0ja5iueR6ojVgFpgTzdSQklJIEptROiXwKAuVzg1artOa/VyEbAlI34
# XMwG3Ary44K2il7+zesRk4oMiHt3tGgmBhCF1nFNMlQy/OkVSub/uTD/Yiukk3m0
# xPOBCRAP6r9eP31VqDhRk/1b6IwE+bCSyX0oWGGhRXojsMTiuiYqU9rhYbt8zPgX
# KJZIjc3z4C0sMO2E3pUy+F3N5wlBimkLw6pl2UZSa5Jp1/fYmJzRqsZ9U23f0KFx
# ROwgWZxIO4NQfof5LqMDz/nulv3dABCeiayS3O81GrWRgXc93gXNM6YaVAfqIu4s
# irf4v8MLdanLvA9JMOalqLeTW3tuq73h9EuS+EMp7lR7jImVBBWNRatkFbQMh8go
# 96Llal+yZcxp2BNPKIA9aI2HkPbMGDGlBXSIJ8XYtAyalqn8inf2Ut8PahEk26bj
# 2dYk5hP1O7PK2mOuipZZz8nsHxjhc1vw0OI28vJfhYQQcq5W/UjETgVqf8PHw/qA
# EDoupKvR0nxOQuaEkscJowUL1ocrW71BRSTvsijDqoL9g4tWzwk7PsfjRODLCtJM
# IMAFgOhtN69hTVvnh2PrXR/4L8uxzIqQ4hDz21+4XHAzjtVSrBtwLDhqK4/lYfxU
# imwgKo6i50gDDuUITo9ZCyQRAgMBAAGjggGpMIIBpTAfBgNVHSMEGDAWgBQPKssg
# hyi47G9IritUpimqF6TNDDAdBgNVHQ4EFgQUGAM5RNhUZh4XzessWdhQqAelGIEw
# DgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqG
# OGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5n
# Q0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2Ny
# dC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQw
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMB4GA1UdEQQXMBWB
# E3N1cHBvcnRAcnd0cy5jb20uYXUwDQYJKoZIhvcNAQEMBQADggGBAHSTwJd6ULDY
# 55LtnNWCNreHTaqqlo4T/p6+UkUaLt6fPD/jMfglOg5ymkjZjZbVYeiHQA7MKpuP
# +g35uYA3PRyjd0fLttg0xPqCKaDkX5l+2WB4pncjB2gBdVqogzZam7d1BxNf/WTh
# UW59FwFkKVxKZLFVvWuxSlaitT6bMGx9KtiXyK/EwzPPwEEZPhhN5mVXxH77lNl3
# AdktyOaoSF30y9/5B1GCuN0rzGJp2al9PIiHOAcEKb0r2kHgIifqTNl7j34eMftO
# QTH0vOTHaRDdKbiQyn+splvHpARIe6zrr5ob9uygamS1lZiBG+9/Ygkh8G75OZwq
# Z//JhKXviouW+yZ6DF2oQj9s8JZSgPkYBZVr8xYBqNRLNtT/JuvHJLwmtbbDaPgo
# sy2MF82qXd0zSQbIuja1YPeYM/euqncikqRo+QZZzKEdMchShqoIEbVkz0cJDKOj
# Tq2GE9Gx1RddxBSMKB+b/FvBIC+P6sOpIX4iqqj1HOrG0iq1gqiotjGCBicwggYj
# AgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEr
# MCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIRAMru
# sk151zjYyWWX8RGBuEAwDQYJYIZIAWUDBAIBBQCgajAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgEmgfT+EV5GsEfEVCkGgNLqeuEtEUMhAe2yew53Qu4B4wDQYJKoZI
# hvcNAQEBBQAEggIAhWON0vXzotBa87kcw6RhfNNjfGZcVLVJPxQAjhqP4lxteVyR
# o1PFZGrtAKny12F4r0uJtCkWXAY1SJr7nZ4DA2blGlpF6zzFPtftU4cRbElXVHDo
# nRbQ6nwgXfKdT4jVb1ZkZGulEekfRiqDNkKIOdDyS8olwQwAQG9NbrB+AEKnD6RJ
# kTT5H//b0EW1IrnHTpeR5FhqRITPLXTGUK1WpCeLv4ZCEyFS+XGGYr2UXkCJFqHs
# petzkdSKWHzIVkiDzmWqZxfAmhamKYnVpm47UHs1uw7ZaqWOu5QuwjHoH/p0lYtm
# RweUhFlFeNNpMUnt4PwlHWvOPR8lOz7GtOuLeqYPbTBSMF/sVKJ0k7aZ/4lNzNmi
# eea4uvCcErwPO4bZdaEBL73SMt7qQ4eBdnQ9thUsnGOcZKATAewKuH7Xbbojh9J4
# /v/AAC+K6LaBvr0S2oApjy68b1mBKR+byOLZuA5pmEFC8yQzffu/AsY8JgwAfDl5
# CK8J87Uhkc4K9WULbmsGlZ0L+NUCnOuJzr32EvwY4U64Prm6y4jNEPcr/u/8Zsmj
# J8Ebuz4tezOVwcim46RcmBTSvjTzl3vgypFvUZ5nlvc1/Q2400Lmt6VXI9RZy1DH
# yCXbKZNl9zADPAw7f0k/slt1GBFKgS0HcBJMaXPAotYMiI46CddYUCjr576hggMj
# MIIDHwYJKoZIhvcNAQkGMYIDEDCCAwwCAQEwajBVMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIENBIFIzNgIRAKQpO24e3denNAiHrXpOtyQwDQYJYIZIAWUD
# BAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA0MTYxNDAwMjVaMD8GCSqGSIb3DQEJBDEyBDCBddNWwN8l8knCHuUGM3nL
# tynciBnvyJC1K0NgQ32k0frxnWERWOxm10SXgVztLwMwDQYJKoZIhvcNAQEBBQAE
# ggIAYcaWINcWTGM4Cl3b9xLqZN+c5J0UKgiWdi+qNjbJe6NVoRBTv+O9/gPDknAm
# Dq78+y7fknDf/YRHla3+U8PcGpIwWTY7F4k225dRnGDdEDybnw7yAQkV/WORlxrE
# DIXQNCYG1cYvIswdHPvkNnylYZZpecw0BFglWBPU/rr8sQV/9I5X2PEWOq0E1pRj
# HxTUvP5VJm7tMvDgQ/6EkEVuxKwLHNIsvGDnw2qnC19CG0t9WJ/huSy1VXfgV7tI
# 3lhE1RiApqXQS5fOV2QM0ZPnaf7dINa6qfewzz74WFPVIwn1oL5ICUKzLNFOdnXm
# 1y3BM+FUn9x4RALR91pQ94Hy7m+PWMBfFlhVFbO9Pw3xmO3hPITE+xpe8zadoOfH
# zfyTs3vYvWa1y+CDnY0zXsOdIt6LGdmKa8GoS+u84VmjxXk1OnjnwILRlcPV3GqZ
# cmF3llzi0sEUq1BKdJ2mSCJpPpX0kWnTkNpZF7n+nwFsDwGlhbLsJxQBrJzK941c
# OzttT5tI4zyvYjYarAOyEjoYoTXjm44PF2jxQhTwY20xyKd8NZgFilD9aqORerLc
# 6I5yjLs5uBXk3VeV9haNgKpNzNRQd6U68DZTcrkD3MPx0zEVSBqPfDhljSeeNexI
# ULl9z4wzno7yUsaUKRv0Cv77oGHmaSX4afkudBpOS/twGCk=
# SIG # End signature block
