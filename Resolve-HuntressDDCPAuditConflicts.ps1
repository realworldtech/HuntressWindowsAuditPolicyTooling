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
# MIIyhQYJKoZIhvcNAQcCoIIydjCCMnICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrN0F2u6IPArSm
# eYSPBsDSQzO/QyEyvQLwxyVIoZogpKCCK7QwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB+
# /6RCBJW84mVrbmZ7kWIyFvPZ3M9czT3KRHmeY5U16zANBgkqhkiG9w0BAQEFAASC
# AgBMJr2/iK3XrhBl6s/XQThlMCxewKCZobStPb8sf7OKxQYIufT3YkshWPbL4WFl
# qgI0NYupmOUXK9nsi2Nk5jJjihSUCxaxjbVINXS6DVa36c1r3n6spnP8MT8XC228
# oL7TTyVjBcRfRHhqAhDhg86NvJLUR3wYf9b1+uRoIF82CLinXlPcdSOADiCbXAxE
# l9imTFa9gBppL4r2oB0lPod+kiQaYqySnphAAY8lii3toIfUeFhYm6BqCUwUKQT/
# FsYiDkaxbUDo6Y7TeRvxJwH5ypxS4NSNawobYPjhPRlUn2TsbghUJapRXWZkIh2J
# Snospl5681BV6vOHfDRT/mmJVhQC3BLzJ6tHct6/iQurWxxE6LStUZGuDhY3kc78
# G2Dre6Ou5W1I/kIklRJsiCaSdCYcpdhKG9nriYD8low/8X93JkFeW9cn1V8tDFLD
# +TI54NkJPP6kc7nUf7D08t/htWryTc4GnlD/K+yCdowYbCxympeR37PQDN4d3zN8
# ITqiEmqjfUj1L/uLiu1xXfN+0Vg9unnv2yu20xlh3sLwvLnDVNbljpAVIcQhIe2R
# aGnAhZbZU1sLQDL+tWylsGnVa7SGHhE1nBK3wWh5Xm11V1RSSZ6x5Wi+CMLSpYpY
# 5nHSUkmxA2Q1gOew5IcTw19FHmsuayDuei3c1OEt3DFz4qGCAyMwggMfBgkqhkiG
# 9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNjE0
# MTMwNFowPwYJKoZIhvcNAQkEMTIEMP1i5RMrexQ3/junBGjpVxiyNj7/VnaoGjhY
# PLPkC9i3oWdJqX7/2C086KjLeXozpTANBgkqhkiG9w0BAQEFAASCAgB6Bq32q9hN
# q9UatlEKrGLT3e7l+nCCLmlf9rO4BPTALKiVANf7Rp6jZdRdXdFWGuhbAvCq5SCa
# Y7U3ArlCJOb+eJQxMf58RSzkw8/zRBV2REFB3RscL+pxiwsJkgz5a9+B+aBHrGMN
# THbC4Cun5qhvYS4KGh8jnCjCriOvwS8fEFnDgCd38dqs/2/rQw3nO5CyuT1pCHGL
# aM0hgoqqoRFUrTIjeeC6M+lNVvk+RuE2gEEbdIcqCXG1lKIzNippDjz5Z6A0OWap
# 1FAARJ6teVZ/IvxFqxdCCrAdOes1Q9hjkdo+aEv57YiMuWLwvKZWibZQgnbqS4fM
# i2dqnDYVy+fYDtZ2a/TDs1a/qHSB+Q9cRtrwzsd3UiZ6ZO+7lHSlAgVqBjIWs+1I
# 3VUjqHeqDYw31xiOuqrw6gl8ZtL6wTkv/PGQrWcjdKKUGjOf8IOig21aYJOXOcfN
# Sd/IraGlTAyQeM+Xt8WSFpS6mqAVN0D5VBZS+vTZN0stCj1JKopVnNC6RFzHbb9M
# Np5dtT/k3uhrFbW9dZ27FqpMElJw7lOEQYCWQljnwm0uaB7B1gVC97EspAQs5ofo
# xxF9KSH70yQ2O0ABK2WdH5sZ7qDbQanoEJRpPBjQrL7HHTVdBxiDMu+rcqgyohv6
# Vbz5k9ZwLqAaRhl5RCQJpVxCyCp5R7ffmw==
# SIG # End signature block
