<#
.SYNOPSIS
    Performs a lightweight AD and SYSVOL replication healthcheck for a domain.

.DESCRIPTION
    Checks core signals that commonly explain Group Policy creation/read
    inconsistencies:
    - Domain controller discovery and role visibility
    - AD replication summary via repadmin /replsummary
    - DFS Replication state for SYSVOL via dfsrdiag
    - Presence of the SYSVOL Policies path on each discovered DC

    This script is intended as a troubleshooting companion for
    New-HuntressAuditGPO.ps1 when GPO creation succeeds but follow-up reads of
    the corresponding AD or SYSVOL objects behave inconsistently.

.PARAMETER TargetDomain
    Domain FQDN to inspect. Defaults to the current computer's domain.

.PARAMETER Server
    Preferred domain controller for discovery and AD queries. If omitted, the
    script uses the target domain's PDC emulator.

.PARAMETER PassThru
    Returns the collected health objects in addition to the console summary.

.EXAMPLE
    .\Test-HuntressADReplicationHealth.ps1

.EXAMPLE
    .\Test-HuntressADReplicationHealth.ps1 -TargetDomain child.corp.example.com

.NOTES
    Requirements:
      - ActiveDirectory module
      - repadmin available
      - dfsrdiag available for DFSR/SYSVOL state checks

    Author:  Andrew Yager / RWTS
    Version: 1.0
    Date:    2026-04-17
#>

[CmdletBinding()]
param(
    [string]$TargetDomain,
    [string]$Server,
    [switch]$PassThru
)

#Requires -Modules ActiveDirectory

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-PreferredDomainController {
    param(
        [string]$DomainFQDN,
        [string]$PreferredServer
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredServer)) {
        return $PreferredServer
    }

    $domain = Get-ADDomain -Identity $DomainFQDN -Server $DomainFQDN
    if (-not [string]::IsNullOrWhiteSpace($domain.PDCEmulator)) {
        return $domain.PDCEmulator
    }

    return $DomainFQDN
}

function Get-TargetDomainName {
    param([string]$RequestedDomain)

    if (-not [string]::IsNullOrWhiteSpace($RequestedDomain)) {
        return $RequestedDomain
    }

    return (Get-ADDomain).DNSRoot
}

function Get-ReplSummary {
    try {
        $output = & repadmin /replsummary
        return [pscustomobject]@{
            Available = $true
            Success   = ($LASTEXITCODE -eq 0)
            Output    = ($output -join [Environment]::NewLine)
            Error     = $(if ($LASTEXITCODE -eq 0) { $null } else { "repadmin exited with code $LASTEXITCODE." })
        }
    }
    catch {
        return [pscustomobject]@{
            Available = $false
            Success   = $false
            Output    = $null
            Error     = $_.Exception.Message
        }
    }
}

function Get-DfsrSysvolState {
    try {
        $output = & dfsrdiag ReplicationState
        return [pscustomobject]@{
            Available = $true
            Success   = ($LASTEXITCODE -eq 0)
            Output    = ($output -join [Environment]::NewLine)
            Error     = $(if ($LASTEXITCODE -eq 0) { $null } else { "dfsrdiag exited with code $LASTEXITCODE." })
        }
    }
    catch {
        return [pscustomobject]@{
            Available = $false
            Success   = $false
            Output    = $null
            Error     = $_.Exception.Message
        }
    }
}

function Get-SysvolPathChecks {
    param(
        [string]$DomainFQDN,
        [string[]]$DomainControllers
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $DomainControllers) {
        $policiesPath = "\\$dc\SYSVOL\$DomainFQDN\Policies"
        $exists = $false
        $error = $null

        try {
            $exists = Test-Path -LiteralPath $policiesPath
        }
        catch {
            $error = $_.Exception.Message
        }

        $results.Add([pscustomobject]@{
            Server = $dc
            Path   = $policiesPath
            Exists = $exists
            Error  = $error
        })
    }

    return @($results)
}

Import-Module ActiveDirectory -ErrorAction Stop

$domainFQDN = Get-TargetDomainName -RequestedDomain $TargetDomain
$serverName = Resolve-PreferredDomainController -DomainFQDN $domainFQDN -PreferredServer $Server
$domainInfo = Get-ADDomain -Identity $domainFQDN -Server $serverName
$dcs = @(Get-ADDomainController -Filter * -Server $serverName | Sort-Object HostName)
$sysvolChecks = Get-SysvolPathChecks -DomainFQDN $domainFQDN -DomainControllers $dcs.HostName
$replSummary = Get-ReplSummary
$dfsrState = Get-DfsrSysvolState

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " HUNTRESS AD / SYSVOL REPLICATION HEALTHCHECK" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host (" Domain:          {0}" -f $domainFQDN)
Write-Host (" Preferred server:{0}" -f $serverName)
Write-Host (" PDC emulator:    {0}" -f $domainInfo.PDCEmulator)
Write-Host (" RID master:      {0}" -f $domainInfo.RIDMaster)
Write-Host (" Infrastructure:  {0}" -f $domainInfo.InfrastructureMaster)
Write-Host (" Domain DC count: {0}" -f $dcs.Count)
Write-Host ""

Write-Host "Domain controllers:" -ForegroundColor Yellow
foreach ($dc in $dcs) {
    Write-Host ("  - {0} ({1})" -f $dc.HostName, $dc.Site)
}

Write-Host ""
Write-Host "SYSVOL access checks:" -ForegroundColor Yellow
foreach ($item in $sysvolChecks) {
    if ($item.Error) {
        Write-Host ("  - {0}: ERROR - {1}" -f $item.Server, $item.Error) -ForegroundColor Red
    } elseif ($item.Exists) {
        Write-Host ("  - {0}: OK - {1}" -f $item.Server, $item.Path) -ForegroundColor Green
    } else {
        Write-Host ("  - {0}: MISSING - {1}" -f $item.Server, $item.Path) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "repadmin /replsummary:" -ForegroundColor Yellow
if ($replSummary.Available) {
    Write-Host ("  Status: {0}" -f $(if ($replSummary.Success) { 'OK' } else { 'FAILED' })) -ForegroundColor $(if ($replSummary.Success) { 'Green' } else { 'Red' })
    if ($replSummary.Output) {
        Write-Host ""
        Write-Host $replSummary.Output
    }
} else {
    Write-Host ("  Unavailable: {0}" -f $replSummary.Error) -ForegroundColor Yellow
}

Write-Host ""
Write-Host "dfsrdiag ReplicationState:" -ForegroundColor Yellow
if ($dfsrState.Available) {
    Write-Host ("  Status: {0}" -f $(if ($dfsrState.Success) { 'OK' } else { 'FAILED' })) -ForegroundColor $(if ($dfsrState.Success) { 'Green' } else { 'Red' })
    if ($dfsrState.Output) {
        Write-Host ""
        Write-Host $dfsrState.Output
    }
} else {
    Write-Host ("  Unavailable: {0}" -f $dfsrState.Error) -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Interpretation:" -ForegroundColor Yellow
Write-Host "  - If SYSVOL access differs between DCs, GPO file writes may not be visible everywhere yet."
Write-Host "  - If repadmin shows failures, AD object reads can race or disagree across DCs."
Write-Host "  - If dfsrdiag shows active backlog or errors, SYSVOL convergence may be delayed."
Write-Host ""

if ($PassThru) {
    [pscustomobject]@{
        DomainInfo    = $domainInfo
        DomainControllers = $dcs
        SysvolChecks  = $sysvolChecks
        ReplSummary   = $replSummary
        DfsrState     = $dfsrState
    }
}

# SIG # Begin signature block
# MIIyhQYJKoZIhvcNAQcCoIIydjCCMnICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCAknF/8amRx9+f
# 52eqn+GAZUFI2IF74Cun5THkI0lN1qCCK7QwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAm
# ZQQJx3bJRpp6qSzxbYU5OuXNlJtF36mHfIJsV2VqnTANBgkqhkiG9w0BAQEFAASC
# AgBa677XiB2vvSKxlwW2rL80roUu95JC5iYWrHTkP1AkTHZRdNDQ+VaPVW5dj9LG
# 31dIeaiTWfGUELB16Q09Kv9uFvya4LimU3dsJV7uemz0Pw2jDH3hIt1LQRnbRCk5
# tFlXet0v8bGzQRW4Rom6Biwmh5Jg7akP2ozEMepMqXCDp9Jo+TSSlp7inkrU1sVh
# LaU7SjQ1xthp6IxAVLSL8ioVqiBhcf4/j0ePlWUpKQjdYvoxiPh5wK020PWYvHQJ
# ONDXt3mzA+UythOxn3x2m7PrVwb1Ff2vu408vylWqW+I1GbbgGKV7BGh2ETrLEjy
# hV2SaUX5N69D4vvKqOBtHU5us2NFp/m6Ds4/zBLo84hfBU/ovfftG/rDnUYQawJ/
# 0bFu1ofyAWsJ4hVvjTmWemhChy7DqN5Ari3kkAksz2rwE/m8JCUnXhR8LxN/Sldz
# ZpxUH7KXAQk3b4xCL6olTz8GQUyPtAk0ArhZ6EHVrgWWgJuI/jd33y2XKLGjyJ67
# bWkrN4xrpwnIH8qGoIc8j1v9Z8ouYFHKcX4ylKZWoKXgQb7M79x4HEz1X9ZikAyS
# 07FkypWRVpYXoaJ44Y4v/fZhjONx7RfvtaR9GxNSnJ5rVlfOE2eS63Tf0X0W0qVO
# 0hGNVl4etwHqCma8TjK7ci/WbQoK0oeDHPoYjGP2v36qXaGCAyMwggMfBgkqhkiG
# 9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNjE1
# MDY1MFowPwYJKoZIhvcNAQkEMTIEMEWahYBT9N2/XtBy8C20ZImQN/moKmgMuave
# h8GEeW8yMrSvoCzUwwA2/KhfQgrEdzANBgkqhkiG9w0BAQEFAASCAgCh/e4OF0P4
# yqd++jb44CRrkZph2lyEuSXg5yI2RVq0QAhMmy/EReWffAckz2KxUqHC4MHXlTVV
# NcFl2t8p4pK7JMEE5coP1VACWEWvm/erBTdoNZuwYFqs1Js5fZJRlJWyMziZsAB5
# m1mmalIRC65w+wt9/gkf3hABAVU2KdDCcEgjPFdfMdfWEDvw95hem0Or+9fETbpl
# IAOog8rqONgHhdEo1Ze1ambzAgqOQozA07e/njxwPSCrXEaLmw/kJ8mZujEy87c3
# VSB2as14lA+NJfqtK6Aa4dN/QP/VoQxJPFTn6yLoGBH0UP5FBaVCjivanYz1ML5o
# opRpcHayBOt/yt0+ShIHKWYCtxvo5X6CipU36i2SdvYDnLvhY73ggooBRLgdAIz8
# AxH20uJQT5Ab7QNInwcFhGoYB8iXhjO/YN2+XTA63hIN97hfmgsz4hd8RDvVoixH
# FSDBQwKs6sQFyVWYJO6IGgtZnw7sM6ykEvP6ZpVlnugpfZXIZ2sLRUJWib0I6yL3
# phUFBkqpdpvXXMmggNnlxQMt9x98hpPGSOsBcoXtlACZVjJyMxRdtUtyXSYldZyS
# ixaPehZeqhQ/0rnSC2qZSdhvidj7dk6363vUTVLUHBRRJRwH3K8hNRHxTy6aDwbA
# HgtLDQTMUEQSSYKLZYiOyHOM3lcfWE6DxQ==
# SIG # End signature block
