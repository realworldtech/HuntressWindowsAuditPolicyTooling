# Huntress Windows Audit Policy Tooling

PowerShell scripts for deploying, validating, and maintaining the [Huntress Managed SIEM audit policy baseline](https://support.huntress.io/hc/en-us/articles/49363914702867) across Active Directory environments.

## Scripts

### New-HuntressAuditGPO.ps1

Creates a Group Policy Object that implements the full Huntress Managed SIEM recommended audit configuration and links it at the domain root. The GPO includes:

- **Advanced Audit Policy** -- all 59 subcategories explicitly defined
- **Force subcategory override** -- ensures Advanced Audit Policy settings take precedence over legacy category-level settings
- **Disable global system object auditing** -- prevents excessive Kernel Object event noise
- **Security Event Log sizing** -- 512 MB maximum size with overwrite-as-needed retention
- **PowerShell logging** -- Module Logging (all modules) and Script Block Logging enabled for both 64-bit and 32-bit paths

The GPO is written directly to SYSVOL rather than using `Import-GPO`, avoiding fragile undocumented backup XML schema differences across Windows Server versions. If any step fails during deployment, the partially-created GPO is automatically removed.

**Conditional settings:**

| Parameter | Effect |
|---|---|
| `-NoHuntressEDR` | Sets Process Creation auditing to Success (default is No Auditing because Huntress EDR already captures process events) |
| `-HasADCS` | Sets Certification Services auditing to Success and Failure (default is No Auditing) |

**Multi-domain support:**

GPOs are domain-scoped and do not automatically apply to child domains. Use `-TargetDomain` to specify a single domain or `-AllDomains` to deploy to every domain in the forest.

```powershell
# Standard deployment (Huntress EDR present, no AD CS)
.\New-HuntressAuditGPO.ps1

# No Huntress EDR, AD CS deployed, specific child domain
.\New-HuntressAuditGPO.ps1 -NoHuntressEDR -HasADCS -TargetDomain child.corp.example.com

# Deploy to every domain in the forest
.\New-HuntressAuditGPO.ps1 -AllDomains

# Preview without making changes
.\New-HuntressAuditGPO.ps1 -WhatIf
```

### Resolve-HuntressDDCPAuditConflicts.ps1

Removes overlapping Advanced Audit Policy subcategories from the **Default Domain Controllers Policy** (DDCP) that conflict with the Huntress baseline GPO. When both the DDCP and the Huntress GPO define the same audit subcategories, the effective result depends on GPO precedence and can produce unexpected audit settings.

The script identifies and removes these specific overlapping subcategories from the DDCP's `audit.csv`:

- Application Group Management
- Computer Account Management
- Distribution Group Management
- Security Group Management
- Special Logon

Before making changes, the existing `audit.csv` is backed up to a timestamped file. The script also increments the GPO version number in both Active Directory and the SYSVOL `GPT.INI` so that domain controllers recognise the policy change.

```powershell
# Fix DDCP conflicts in the current domain
.\Resolve-HuntressDDCPAuditConflicts.ps1

# Fix DDCP conflicts in a specific domain
.\Resolve-HuntressDDCPAuditConflicts.ps1 -TargetDomain child.corp.example.com

# Fix DDCP conflicts in every domain in the forest
.\Resolve-HuntressDDCPAuditConflicts.ps1 -AllDomains

# Preview without making changes
.\Resolve-HuntressDDCPAuditConflicts.ps1 -WhatIf
```

### Test-HuntressAuditPolicy.ps1

Validates the effective Advanced Audit Policy on a Windows host against the Huntress baseline. It can run live (executing `auditpol /get /category:*` locally) or parse previously-saved AuditPol output from a file in either table or CSV format.

When run live, the script also performs lightweight **policy source analysis**:

- Compares effective AuditPol results against the Local Group Policy `audit.csv` file
- Collects `gpresult /scope computer /r` to list applied computer GPOs
- For each mismatch, provides a heuristic assessment of whether the drift is likely caused by Local Group Policy, a domain GPO, or a manual `auditpol` change

The script exits with code 0 on pass and 1 on failure, making it suitable for use in automated compliance checks.

```powershell
# Validate the local machine against the Huntress baseline
.\Test-HuntressAuditPolicy.ps1

# Validate from a saved AuditPol output file
.\Test-HuntressAuditPolicy.ps1 -Path .\auditpol.txt

# Validate CSV-format output
auditpol /get /category:* /r > .\auditpol.csv
.\Test-HuntressAuditPolicy.ps1 -Path .\auditpol.csv -InputFormat Csv

# Validate for environments without Huntress EDR
.\Test-HuntressAuditPolicy.ps1 -NoHuntressEDR

# Validate for environments with AD CS
.\Test-HuntressAuditPolicy.ps1 -HasADCS

# Return structured comparison object for further processing
$result = .\Test-HuntressAuditPolicy.ps1 -PassThru
```

## Requirements

- **PowerShell 5.1+**
- **RSAT modules**: `GroupPolicy` and `ActiveDirectory` (required by `New-HuntressAuditGPO.ps1` and `Resolve-HuntressDDCPAuditConflicts.ps1`)
- **Domain Admin** or equivalent permissions for GPO creation, modification, and linking
- `Test-HuntressAuditPolicy.ps1` requires **local administrator** privileges when running live (for `auditpol` access)

## Typical workflow

1. **Deploy** the baseline GPO with `New-HuntressAuditGPO.ps1`
2. **Resolve conflicts** in the Default Domain Controllers Policy with `Resolve-HuntressDDCPAuditConflicts.ps1`
3. Run `gpupdate /force` on a target machine
4. **Validate** the effective policy with `Test-HuntressAuditPolicy.ps1`
5. Confirm in the Huntress portal under **SIEM > Misconfigured Policies**

## Code signing

Both `New-HuntressAuditGPO.ps1` and `Resolve-HuntressDDCPAuditConflicts.ps1` are Authenticode-signed by Real World Technology Solutions Pty Ltd.

## Licence

MIT -- see [LICENSE](LICENSE).
