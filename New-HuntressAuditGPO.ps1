<#
.SYNOPSIS
    Creates a GPO implementing Huntress Managed SIEM recommended audit
    policies and links it at the target domain root.

.DESCRIPTION
    Creates a new GPO, writes Advanced Audit Policy and security settings
    directly into SYSVOL, updates the GPO's AD metadata (CSE GUIDs and
    version number), then applies registry-based policies via
    Set-GPRegistryValue. If any step fails, the partially-created GPO is
    removed automatically.

    This approach avoids fabricating a GPO backup for Import-GPO, which is
    fragile due to undocumented backup XML schema requirements that vary
    across Windows Server versions.

    Settings implemented (per Huntress "Enforcing Windows Logging Audit
    Policies" article, last updated 2026-03-27):

    1. Advanced Audit Policy - all 59 subcategories explicitly defined
       (baseline: 21 S+F, 11 S, 2 F, 25 No Auditing)
    2. Force audit policy subcategory settings to override category settings
    3. Disable "Audit the access of global system objects" (prevents
       excessive Kernel Object event generation)
    4. Security Event Log: 512000 KB max, OverwriteAsNeeded
    5. PowerShell Module Logging: Enabled (all modules)
    6. PowerShell Script Block Logging: Enabled

    CONDITIONAL SETTINGS (see parameters):
    - Process Creation: Default No Auditing (Huntress EDR covers this).
      Use -NoHuntressEDR to set to Success for environments without EDR.
    - Certification Services: Default No Auditing.
      Use -HasADCS to set to Success and Failure for AD CS environments.

    MULTI-DOMAIN FORESTS:
    GPOs are domain-scoped - a GPO linked at one domain does NOT
    automatically apply to child domains. By default, this script targets
    the current user's domain. Use -TargetDomain to specify a different
    domain, or -AllDomains to deploy to every domain in the forest.

.PARAMETER GPOName
    Name for the new GPO. Default: "Huntress SIEM - Audit Policy Baseline"

.PARAMETER NoHuntressEDR
    Enables Process Creation auditing (Success). Use when the Huntress
    EDR agent is NOT deployed.

.PARAMETER HasADCS
    Enables Certification Services auditing (Success and Failure). Use
    when Active Directory Certificate Services is deployed.

.PARAMETER TargetDomain
    FQDN of the domain to create and link the GPO in. Defaults to the
    current user's domain.

.PARAMETER AllDomains
    Creates and links the GPO in every domain in the forest.

.PARAMETER LinkEnabled
    Whether to link the GPO after creation. Default: $true

.PARAMETER Server
    Preferred domain controller to use for all Group Policy and Active
    Directory operations. If omitted, the script resolves and pins the
    target domain's PDC emulator.

.PARAMETER WhatIf
    Shows what the script would do without making changes.

.EXAMPLE
    # Standard deployment (Huntress EDR present, no AD CS)
    .\New-HuntressAuditGPO.ps1

.EXAMPLE
    # No Huntress EDR, AD CS deployed, specific child domain
    .\New-HuntressAuditGPO.ps1 -NoHuntressEDR -HasADCS -TargetDomain child.corp.example.com

.EXAMPLE
    # Deploy to every domain in the forest
    .\New-HuntressAuditGPO.ps1 -AllDomains

.EXAMPLE
    # Preview without making changes
    .\New-HuntressAuditGPO.ps1 -WhatIf

.NOTES
    Requirements:
      - Domain controller or machine with RSAT (GroupPolicy + ActiveDirectory)
      - Domain Admin or equivalent permissions (per target domain)
      - PowerShell 5.1+

    Reference:
      https://support.huntress.io/hc/en-us/articles/49363914702867

    Author:  Andrew Yager / RWTS
    Version: 5.0
    Date:    2026-04-16
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$GPOName = "Huntress SIEM - Audit Policy Baseline",
    [switch]$NoHuntressEDR,
    [switch]$HasADCS,
    [string]$TargetDomain,
    [switch]$AllDomains,
    [string]$Server,
    [bool]$LinkEnabled = $true
)

#Requires -Modules GroupPolicy, ActiveDirectory

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$explicitWhatIf = $PSBoundParameters.ContainsKey('WhatIf')

# ============================================================================
# AUDIT POLICY DATA
# ============================================================================

$processCreationValue = if ($NoHuntressEDR) { 1 } else { 0 }
$certServicesValue    = if ($HasADCS) { 3 } else { 0 }

$auditSettings = @(
    # -- Account Logon --------------------------------------------------
    @{ GUID = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Name = "Credential Validation";              Value = 3 }
    @{ GUID = "{0CCE9242-69AE-11D9-BED3-505054503030}"; Name = "Kerberos Authentication Service";    Value = 3 }
    @{ GUID = "{0CCE9240-69AE-11D9-BED3-505054503030}"; Name = "Kerberos Service Ticket Operations";  Value = 3 }
    @{ GUID = "{0CCE9241-69AE-11D9-BED3-505054503030}"; Name = "Other Account Logon Events";          Value = 0 }

    # -- Account Management ---------------------------------------------
    @{ GUID = "{0CCE9239-69AE-11D9-BED3-505054503030}"; Name = "Application Group Management";       Value = 0 }
    @{ GUID = "{0CCE9236-69AE-11D9-BED3-505054503030}"; Name = "Computer Account Management";        Value = 3 }
    @{ GUID = "{0CCE9238-69AE-11D9-BED3-505054503030}"; Name = "Distribution Group Management";      Value = 3 }
    @{ GUID = "{0CCE923A-69AE-11D9-BED3-505054503030}"; Name = "Other Account Management Events";    Value = 1 }
    @{ GUID = "{0CCE9237-69AE-11D9-BED3-505054503030}"; Name = "Security Group Management";          Value = 3 }
    @{ GUID = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Name = "User Account Management";            Value = 3 }

    # -- Detailed Tracking ----------------------------------------------
    @{ GUID = "{0CCE922D-69AE-11D9-BED3-505054503030}"; Name = "DPAPI Activity";                     Value = 0 }
    @{ GUID = "{0CCE9248-69AE-11D9-BED3-505054503030}"; Name = "Plug and Play Events";               Value = 1 }
    @{ GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Name = "Process Creation";                   Value = $processCreationValue }
    @{ GUID = "{0CCE922C-69AE-11D9-BED3-505054503030}"; Name = "Process Termination";                Value = 0 }
    @{ GUID = "{0CCE922E-69AE-11D9-BED3-505054503030}"; Name = "RPC Events";                         Value = 0 }
    @{ GUID = "{0CCE924A-69AE-11D9-BED3-505054503030}"; Name = "Token Right Adjusted Events";        Value = 0 }

    # -- DS Access (events only generated on DCs, harmless elsewhere) ----
    @{ GUID = "{0CCE923E-69AE-11D9-BED3-505054503030}"; Name = "Detailed Directory Service Replication"; Value = 0 }
    @{ GUID = "{0CCE923B-69AE-11D9-BED3-505054503030}"; Name = "Directory Service Access";           Value = 3 }
    @{ GUID = "{0CCE923C-69AE-11D9-BED3-505054503030}"; Name = "Directory Service Changes";          Value = 1 }
    @{ GUID = "{0CCE923D-69AE-11D9-BED3-505054503030}"; Name = "Directory Service Replication";      Value = 0 }

    # -- Logon/Logoff ---------------------------------------------------
    @{ GUID = "{0CCE9217-69AE-11D9-BED3-505054503030}"; Name = "Account Lockout";                    Value = 2 }
    @{ GUID = "{0CCE9247-69AE-11D9-BED3-505054503030}"; Name = "User / Device Claims";               Value = 0 }
    @{ GUID = "{0CCE9249-69AE-11D9-BED3-505054503030}"; Name = "Group Membership";                   Value = 0 }
    @{ GUID = "{0CCE921A-69AE-11D9-BED3-505054503030}"; Name = "IPsec Extended Mode";                Value = 0 }
    @{ GUID = "{0CCE9218-69AE-11D9-BED3-505054503030}"; Name = "IPsec Main Mode";                    Value = 0 }
    @{ GUID = "{0CCE9219-69AE-11D9-BED3-505054503030}"; Name = "IPsec Quick Mode";                   Value = 0 }
    @{ GUID = "{0CCE9216-69AE-11D9-BED3-505054503030}"; Name = "Logoff";                             Value = 1 }
    @{ GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Name = "Logon";                              Value = 3 }
    @{ GUID = "{0CCE9243-69AE-11D9-BED3-505054503030}"; Name = "Network Policy Server";              Value = 3 }
    @{ GUID = "{0CCE921C-69AE-11D9-BED3-505054503030}"; Name = "Other Logon/Logoff Events";          Value = 3 }
    @{ GUID = "{0CCE921B-69AE-11D9-BED3-505054503030}"; Name = "Special Logon";                      Value = 1 }

    # -- Object Access --------------------------------------------------
    @{ GUID = "{0CCE9222-69AE-11D9-BED3-505054503030}"; Name = "Application Generated";              Value = 0 }
    @{ GUID = "{0CCE9221-69AE-11D9-BED3-505054503030}"; Name = "Certification Services";             Value = $certServicesValue }
    @{ GUID = "{0CCE9244-69AE-11D9-BED3-505054503030}"; Name = "Detailed File Share";                Value = 3 }
    @{ GUID = "{0CCE9224-69AE-11D9-BED3-505054503030}"; Name = "File Share";                         Value = 3 }
    @{ GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"; Name = "File System";                        Value = 0 }
    @{ GUID = "{0CCE9226-69AE-11D9-BED3-505054503030}"; Name = "Filtering Platform Connection";      Value = 2 }
    @{ GUID = "{0CCE9225-69AE-11D9-BED3-505054503030}"; Name = "Filtering Platform Packet Drop";     Value = 0 }
    @{ GUID = "{0CCE9223-69AE-11D9-BED3-505054503030}"; Name = "Handle Manipulation";                Value = 0 }
    @{ GUID = "{0CCE921F-69AE-11D9-BED3-505054503030}"; Name = "Kernel Object";                      Value = 3 }
    @{ GUID = "{0CCE9227-69AE-11D9-BED3-505054503030}"; Name = "Other Object Access Events";         Value = 3 }
    @{ GUID = "{0CCE921E-69AE-11D9-BED3-505054503030}"; Name = "Registry";                           Value = 0 }
    @{ GUID = "{0CCE9245-69AE-11D9-BED3-505054503030}"; Name = "Removable Storage";                  Value = 3 }
    @{ GUID = "{0CCE9220-69AE-11D9-BED3-505054503030}"; Name = "SAM";                                Value = 0 }
    @{ GUID = "{0CCE9246-69AE-11D9-BED3-505054503030}"; Name = "Central Policy Staging";             Value = 0 }

    # -- Policy Change --------------------------------------------------
    @{ GUID = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Name = "Audit Policy Change";                Value = 1 }
    @{ GUID = "{0CCE9230-69AE-11D9-BED3-505054503030}"; Name = "Authentication Policy Change";       Value = 1 }
    @{ GUID = "{0CCE9231-69AE-11D9-BED3-505054503030}"; Name = "Authorization Policy Change";        Value = 1 }
    @{ GUID = "{0CCE9233-69AE-11D9-BED3-505054503030}"; Name = "Filtering Platform Policy Change";   Value = 1 }
    @{ GUID = "{0CCE9232-69AE-11D9-BED3-505054503030}"; Name = "MPSSVC Rule-Level Policy Change";    Value = 3 }
    @{ GUID = "{0CCE9234-69AE-11D9-BED3-505054503030}"; Name = "Other Policy Change Events";         Value = 3 }

    # -- Privilege Use --------------------------------------------------
    @{ GUID = "{0CCE9229-69AE-11D9-BED3-505054503030}"; Name = "Non Sensitive Privilege Use";         Value = 0 }
    @{ GUID = "{0CCE922A-69AE-11D9-BED3-505054503030}"; Name = "Other Privilege Use Events";          Value = 0 }
    @{ GUID = "{0CCE9228-69AE-11D9-BED3-505054503030}"; Name = "Sensitive Privilege Use";              Value = 3 }

    # -- System ---------------------------------------------------------
    @{ GUID = "{0CCE9213-69AE-11D9-BED3-505054503030}"; Name = "IPsec Driver";                        Value = 0 }
    @{ GUID = "{0CCE9214-69AE-11D9-BED3-505054503030}"; Name = "Other System Events";                 Value = 3 }
    @{ GUID = "{0CCE9210-69AE-11D9-BED3-505054503030}"; Name = "Security State Change";               Value = 1 }
    @{ GUID = "{0CCE9211-69AE-11D9-BED3-505054503030}"; Name = "Security System Extension";           Value = 1 }
    @{ GUID = "{0CCE9212-69AE-11D9-BED3-505054503030}"; Name = "System Integrity";                    Value = 3 }
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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

function New-AuditCsvContent {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value")
    foreach ($setting in $script:auditSettings) {
        $lines.Add(",System,$($setting.Name),$($setting.GUID),$(Convert-AuditValueToText -Value $setting.Value),,$($setting.Value)")
    }
    return ($lines -join "`r`n")
}

function New-GptTmplContent {
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
"@
}

function Merge-GptTmplRegistryValues {
    param(
        [string]$ExistingContent,
        [string[]]$RequiredEntries
    )

    $content = if ([string]::IsNullOrWhiteSpace($ExistingContent)) {
        New-GptTmplContent
    } else {
        $ExistingContent
    }

    # Ensure a [Registry Values] section exists
    if ($content -notmatch '(?im)^\[Registry Values\]\s*$') {
        $content = $content.TrimEnd() + "`r`n[Registry Values]`r`n"
    }

    # Add each required entry if not already present
    foreach ($entry in $RequiredEntries) {
        if ($content -notmatch [regex]::Escape($entry)) {
            $content = $content.TrimEnd() + "`r`n$entry"
        }
    }

    return ($content.TrimEnd() + "`r`n")
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

function Get-UpdatedMachineVersion {
    param([int]$CurrentVersionNumber)

    $userVersion    = ($CurrentVersionNumber -shr 16) -band 0xFFFF
    $machineVersion = ($CurrentVersionNumber -band 0xFFFF) + 1
    return (($userVersion -shl 16) -bor $machineVersion)
}

function Get-SortedMachineExtensionNames {
    param([string]$CurrentValue)

    # CSE GUID pairs required for: Registry, Security Settings, Advanced Audit Policy
    $requiredPairs = @(
        "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957D-509E-11D1-A7CC-0000F87571E3}]",
        "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
        "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
    )

    $value = if ($null -eq $CurrentValue) { "" } else { $CurrentValue }

    foreach ($pair in $requiredPairs) {
        if ($value -notmatch [regex]::Escape($pair)) {
            $value += $pair
        }
    }

    # Sort pairs by CSE GUID - Windows expects ascending order
    $pairs = [regex]::Matches($value, '\[\{[0-9A-Fa-f-]+\}\{[0-9A-Fa-f-]+\}\]') |
        ForEach-Object { $_.Value } |
        Sort-Object

    return ($pairs -join '')
}

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

function Get-GpoAdObjectWithRetry {
    param(
        [string]$Identity,
        [string]$ServerName,
        [int]$MaxAttempts = 6,
        [int]$DelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Get-ADObject -Identity $Identity -Server $ServerName `
                -Properties gPCMachineExtensionNames, versionNumber
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($attempt -eq $MaxAttempts) {
                throw
            }

            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# ============================================================================
# CORE: Apply audit policy to a GPO via direct SYSVOL write + AD update
# ============================================================================

function Set-HuntressAdvancedAuditPolicy {
    param(
        [Guid]$GpoId,
        [string]$DomainFQDN,
        [string]$DomainDN,
        [string]$ServerName
    )

    $gpoGuid    = $GpoId.ToString("B").ToUpper()
    $machinePath = "\\$ServerName\SYSVOL\$DomainFQDN\Policies\$gpoGuid\Machine"
    $auditDir    = Join-Path $machinePath "Microsoft\Windows NT\Audit"
    $secEditDir  = Join-Path $machinePath "Microsoft\Windows NT\SecEdit"
    $auditCsvPath = Join-Path $auditDir "audit.csv"
    $gptTmplPath  = Join-Path $secEditDir "GptTmpl.inf"
    $gptIniPath   = Join-Path "\\$ServerName\SYSVOL\$DomainFQDN\Policies\$gpoGuid" "GPT.INI"

    # Create directories and write audit.csv
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    New-Item -ItemType Directory -Path $secEditDir -Force | Out-Null
    Set-Content -Path $auditCsvPath -Value (New-AuditCsvContent) -Encoding Unicode

    # Write or merge GptTmpl.inf
    $requiredInfEntries = @(
        "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1",
        "MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0"
    )
    $existingInf = if (Test-Path $gptTmplPath) { Get-Content -Path $gptTmplPath -Raw } else { "" }
    $mergedInf   = Merge-GptTmplRegistryValues -ExistingContent $existingInf -RequiredEntries $requiredInfEntries
    Set-Content -Path $gptTmplPath -Value $mergedInf -Encoding Unicode

    # Update AD object: CSE extension names and version
    $gpoDN    = "CN=$gpoGuid,CN=Policies,CN=System,$DomainDN"
    $adObject = Get-GpoAdObjectWithRetry -Identity $gpoDN -ServerName $ServerName

    $newExtensionNames = Get-SortedMachineExtensionNames -CurrentValue $adObject.gPCMachineExtensionNames
    $newVersion        = Get-UpdatedMachineVersion -CurrentVersionNumber ([int]$adObject.versionNumber)

    Set-ADObject -Identity $gpoDN -Server $ServerName -Replace @{
        gPCMachineExtensionNames = $newExtensionNames
        versionNumber            = $newVersion
    }

    Update-GptIniVersion -Path $gptIniPath -Version $newVersion
}

# ============================================================================
# CORE: Apply registry-based policies via Set-GPRegistryValue
# ============================================================================

function Set-HuntressRegistryPolicies {
    param(
        [Guid]$GpoId,
        [string]$DomainFQDN,
        [string]$ServerName
    )

    # Security Event Log: 512000 KB, OverwriteAsNeeded
    Set-GPRegistryValue -Guid $GpoId -Domain $DomainFQDN -Server $ServerName `
        -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
        -ValueName "MaxSize" -Type DWord -Value 512000 | Out-Null

    Set-GPRegistryValue -Guid $GpoId -Domain $DomainFQDN -Server $ServerName `
        -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
        -ValueName "Retention" -Type DWord -Value 0 | Out-Null

    # PowerShell logging - both 64-bit and 32-bit (Wow6432Node) paths
    foreach ($root in @(
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
    )) {
        Set-GPRegistryValue -Guid $GpoId -Domain $DomainFQDN -Server $ServerName `
            -Key "$root\ModuleLogging" `
            -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null

        Set-GPRegistryValue -Guid $GpoId -Domain $DomainFQDN -Server $ServerName `
            -Key "$root\ModuleLogging\ModuleNames" `
            -ValueName "*" -Type String -Value "*" | Out-Null

        Set-GPRegistryValue -Guid $GpoId -Domain $DomainFQDN -Server $ServerName `
            -Key "$root\ScriptBlockLogging" `
            -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
    }
}

# ============================================================================
# DEPLOY TO A SINGLE DOMAIN - with rollback on failure
# ============================================================================

function Deploy-HuntressGPOToDomain {
    param(
        [string]$DomainFQDN,
        [string]$Name,
        [bool]$Link,
        [string]$PreferredServer,
        [System.Management.Automation.PSCmdlet]$CallerCmdlet
    )

    $serverName = Resolve-PreferredDomainController -DomainFQDN $DomainFQDN -PreferredServer $PreferredServer
    $domainDN = (Get-ADDomain -Identity $DomainFQDN -Server $serverName).DistinguishedName

    Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Domain: $DomainFQDN" -ForegroundColor Cyan
    Write-Host "  DN:     $domainDN" -ForegroundColor Cyan
    Write-Host "  Server: $serverName" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    # Check for existing GPO
    $existing = Get-GPO -Name $Name -Domain $DomainFQDN -Server $serverName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warning "  GPO '$Name' already exists in $DomainFQDN (ID: $($existing.Id)). Skipping."
        return $null
    }

    # ShouldProcess gate - nothing destructive before this point
    if (-not $CallerCmdlet.ShouldProcess("$Name in $DomainFQDN", "Create GPO, apply Huntress audit baseline, and link")) {
        return $null
    }

    $gpo = $null
    try {
        # Create the GPO
        $gpo = New-GPO -Name $Name -Domain $DomainFQDN -Server $serverName `
            -Comment "Huntress SIEM audit policy baseline. Created $(Get-Date -Format 'yyyy-MM-dd')."
        Write-Host "  Created GPO: $Name (ID: $($gpo.Id))" -ForegroundColor Green

        # Apply Advanced Audit Policy via direct SYSVOL write
        Set-HuntressAdvancedAuditPolicy -GpoId $gpo.Id -DomainFQDN $DomainFQDN -DomainDN $domainDN -ServerName $serverName
        Write-Host "  Applied Advanced Audit Policy ($($script:auditSettings.Count) subcategories)" -ForegroundColor DarkGreen
        Write-Host "  Applied SCENoApplyLegacyAuditPolicy=1, AuditBaseObjects=0" -ForegroundColor DarkGreen

        # Apply registry-based policies
        Set-HuntressRegistryPolicies -GpoId $gpo.Id -DomainFQDN $DomainFQDN -ServerName $serverName
        Write-Host "  Applied Security Event Log: 512000 KB, OverwriteAsNeeded" -ForegroundColor DarkGreen
        Write-Host "  Applied PowerShell Module Logging + Script Block Logging" -ForegroundColor DarkGreen

        # Link at domain root
        if ($Link) {
            New-GPLink -Guid $gpo.Id -Target $domainDN -Domain $DomainFQDN -Server $serverName -LinkEnabled Yes | Out-Null
            Write-Host "  Linked GPO at domain root" -ForegroundColor Green
        } else {
            Write-Host "  GPO created but NOT linked (-LinkEnabled `$false)" -ForegroundColor Yellow
        }
    }
    catch {
        # Rollback: remove the partially-created GPO
        if ($null -ne $gpo) {
            Write-Warning "  Deployment failed, removing partially-created GPO..."
            Remove-GPO -Guid $gpo.Id -Domain $DomainFQDN -Server $serverName -Confirm:$false -ErrorAction SilentlyContinue
        }
        throw
    }

    return $gpo
}

# ============================================================================
# MAIN
# ============================================================================

Import-Module GroupPolicy     -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# -- Resolve target domain(s) -----------------------------------------------
if ($AllDomains) {
    $forest  = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = $forest.Domains | ForEach-Object { $_.Name }
    Write-Host "Multi-domain forest detected. Targeting $($domains.Count) domain(s):" -ForegroundColor Cyan
    $domains | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
} elseif ($TargetDomain) {
    $domains = @($TargetDomain)
} else {
    $domains = @((Get-ADDomain).DNSRoot)
}

Write-Host "GPOs are domain-scoped. Child domains require separate deployment." -ForegroundColor Yellow

# -- Report conditional settings ---------------------------------------------
if ($NoHuntressEDR) {
    Write-Host "Mode: No Huntress EDR - Process Creation set to Success" -ForegroundColor Yellow
}
if ($HasADCS) {
    Write-Host "Mode: AD CS present - Certification Services set to Success and Failure" -ForegroundColor Yellow
}

# -- WhatIf preview ----------------------------------------------------------
if ($explicitWhatIf) {
    $sf       = ($auditSettings | Where-Object { $_.Value -eq 3 }).Count
    $sOnly    = ($auditSettings | Where-Object { $_.Value -eq 1 }).Count
    $fOnly    = ($auditSettings | Where-Object { $_.Value -eq 2 }).Count
    $disabled = ($auditSettings | Where-Object { $_.Value -eq 0 }).Count

    Write-Host ""
    Write-Host "[WhatIf] Planned deployment summary" -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Target domain(s): $($domains -join ', ')" -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Preferred server: $(if ($Server) { $Server } else { 'Auto-resolve PDC emulator per domain' })" -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Link after create: $LinkEnabled" -ForegroundColor DarkYellow
    Write-Host ("[WhatIf] Subcategories: {0} total ({1} S+F / {2} S / {3} F / {4} disabled)" -f $auditSettings.Count, $sf, $sOnly, $fOnly, $disabled) -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Process Creation: $(if ($NoHuntressEDR) { 'Success (no EDR)' } else { 'No Auditing (EDR covers)' })" -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Certification Services: $(if ($HasADCS) { 'Success and Failure (AD CS present)' } else { 'No Auditing' })" -ForegroundColor DarkYellow
    Write-Host "[WhatIf] Baseline hardening: Security log 512000 KB / overwrite, PowerShell Module + Script Block logging enabled" -ForegroundColor DarkYellow
    Write-Host ""
}

# -- Deploy to each domain ---------------------------------------------------
$results = @()
foreach ($domain in $domains) {
    $gpo = Deploy-HuntressGPOToDomain `
        -DomainFQDN    $domain `
        -Name          $GPOName `
        -Link          $LinkEnabled `
        -PreferredServer $Server `
        -CallerCmdlet  $PSCmdlet

    if ($gpo) {
        $results += @{ Domain = $domain; GPO = $gpo }
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
if ($results.Count -gt 0) {
    $sf       = ($auditSettings | Where-Object { $_.Value -eq 3 }).Count
    $sOnly    = ($auditSettings | Where-Object { $_.Value -eq 1 }).Count
    $fOnly    = ($auditSettings | Where-Object { $_.Value -eq 2 }).Count
    $disabled = ($auditSettings | Where-Object { $_.Value -eq 0 }).Count

    Write-Host "`n===============================================================" -ForegroundColor Cyan
    Write-Host " HUNTRESS SIEM AUDIT POLICY - DEPLOYMENT COMPLETE" -ForegroundColor Green
    Write-Host "===============================================================" -ForegroundColor Cyan

    foreach ($r in $results) {
        Write-Host ""
        Write-Host "  Domain:  $($r.Domain)"
        Write-Host "  GPO:     $GPOName (ID: $($r.GPO.Id))"
        Write-Host "  Linked:  $(if ($LinkEnabled) { 'Yes' } else { 'No' })"
    }

    Write-Host ""
    Write-Host ("  Subcategories:  {0} total ({1} S+F / {2} S / {3} F / {4} disabled)" -f $auditSettings.Count, $sf, $sOnly, $fOnly, $disabled)
    Write-Host "  Process Creation:       $(if ($NoHuntressEDR) { 'Success (no EDR)' } else { 'No Auditing (EDR covers)' })"
    Write-Host "  Certification Services: $(if ($HasADCS) { 'S+F (AD CS present)' } else { 'No Auditing' })"
    Write-Host ""
    Write-Host "  Baseline hardening:"
    Write-Host "    Security Event Log:      512000 KB / OverwriteAsNeeded"
    Write-Host "    PowerShell Logging:      Module (all) + Script Block"
    Write-Host "    Subcategory override:    Enabled"
    Write-Host "    Global system objects:   Disabled"

    if ($domains.Count -gt 1) {
        Write-Host ""
        Write-Host "  NOTE: Deployed to $($domains.Count) domains independently." -ForegroundColor Yellow
        Write-Host "  Each has its own GPO - update each if the baseline changes." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Verification:" -ForegroundColor Yellow
    Write-Host "    1. gpmc.msc -> Edit GPO -> verify settings"
    Write-Host "    2. Test machine: gpupdate /force"
    Write-Host "    3. auditpol /get /category:*"
    Write-Host "    4. rsop.msc -> check for conflicts"
    Write-Host "    5. Huntress portal -> SIEM -> Misconfigured Policies"
    Write-Host ""
}

# SIG # Begin signature block
# MIIyhQYJKoZIhvcNAQcCoIIydjCCMnICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLzLXLi8P8MjkK
# Egc1sNijVJwo0QViF/JahmdC6yIfZqCCK7QwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBJ
# LP1wJ2IAxFxEQEKxNgRK8hZaSYTANhjg+8lGbMgmBzANBgkqhkiG9w0BAQEFAASC
# AgBG37lMxdI71FMct6dnctAQnTUAAziLW7v7AmQ+JFnGsGH0Q6GrfRDijnIBrhvH
# Zb836gMSG6ordZWhOlw311RYggXOrCKih02KVVh0ji/ywOm+wTrhim+ZCu1Serp5
# 5RNLPU4HB30QMUWkXndXdFOkdx8FMvvyQxuec4r7T5vckEm2WYonByxloB8VBnBi
# 1a4s6oS/p4DqN/hCX4O+3slqpY7BNJlBQJZKAeyrGczJLPt2n0FW5ZhC3Ag/Udt+
# 1UFYiTolCp7lauFWhitBFTXTnPrNSaVA7b/RXzlpZpTvZpNGxHJzeXvefly+4GWv
# GVw0FlRe3M0SR8tGjoFIzf7lWrAYKj23QEmeidprBtoCO2+vynGbiaFsSs53ld5O
# XjUO3ZHNUAe+/RdjfFkbpPVRPWjZxhNqYRdeOGSj0n6X0+AF2TpGMYnxj8xqqfen
# plN7mnLaN9EJsVoLwPObd8D3cMg90LnlDC7kT/R83dODSpmDIx7GAXwUaPuzH//p
# sTVQmVuD00NqMNpXvEtcajdcBOJhvd9XUpBg8UqTDdddnCp+fEmRSaeBdYcSfprK
# WaW+4lNrMUVdNFJll/ObtIT5ff21PVLjX/NeIFQJE2K8fj2f8KjF+kCu5NJ9hvA5
# IJbQvs5mw303/UhuWhivvsrinDMfsn2eVHSb+SMfIJahkaGCAyMwggMfBgkqhkiG
# 9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNjE1
# MDY0NlowPwYJKoZIhvcNAQkEMTIEMD8Xzp/MnML0LTjg/0LFmAGx7+GXWzx6Anj5
# BYCAwwO4+8m4rGc2BqQ62rhVVYMywDANBgkqhkiG9w0BAQEFAASCAgAnkSRSc838
# 3rtf7uv8yyGrOcVsp3Zz1uQSctZDsq+riFEJhoU5qNCdF1bpcl8ihwuKFn4DHNPw
# AjJz9TPbc48bmvi0lId6dkkldzlb7BYf29xkMww6RvcaHnms2bK3pASWUh6vQETu
# T+z4LpbpeSKOQHTYGiooPQsai8a6OXW65csQAF5fDl1Q8fqMSz4rgompie04fSVt
# pwLvTzoogJIeF72A5n9W4KfXwaD+epG/hP0UHWhwvpJtFyNCQJ76uLQLW7ja1YFa
# q7cTnlLCs/3wVa3hmsz2JOYSmwvC05CZMeM0fi60dLWGxzU1fN7CQVfToQMWAcZA
# 0AOzTv3zF1v41DKcv4dg+tq/W1AKRvBopJlahJNdreLN+KOavg5WOIWeQhXPdv1j
# +5PvDJdBeRXe61SGPkM3RwJIXE7buo68rxvcHiuzgkiQ/w196n3zq6UUe/hFXNtx
# RFmF5Xr7rMJZN++BdjDYWBFsoio1Flrm1ydrx1CB51XhB7NGCenZRh9jBWqYlZXU
# rbe5LVls+qqIZJVjgdivgKKGBa2s295eL5enlGyk7gbCgosiAG4M5ohidmUR4R0l
# hMMp2emNBQihx4pl+qQ9IsEtqYCPYkEkWr26XDb3SqzMvDA26MJ5B0pj9JBJaPik
# EC1AhCJY0wxbIfbXZXmVgmtuMannKV9YWw==
# SIG # End signature block
