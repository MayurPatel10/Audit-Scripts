# ============================================================
# Script  : Get-LocalGroupMembers.ps1
# Purpose : Query local group members on a (local or remote) server,
#           RECURSIVELY expand any nested groups -- both local nested
#           groups AND domain (Active Directory) groups -- down to the
#           underlying user accounts, and export the effective
#           membership to TXT + CSV for audit evidence.
# Author  : SysAdmin  (nested-expansion update by IT Audit)
# Date    : 2026-06-04
# ------------------------------------------------------------
# WHAT CHANGED VS. THE ORIGINAL
#   * Original listed only DIRECT members. If a member was itself a
#     group, it was printed as one line and never opened.
#   * This version recurses into every nested group so the report
#     reflects EFFECTIVE membership (who can actually use the rights).
#   * Domain groups are expanded via the ActiveDirectory module when
#     present, with an LDAP/ADSI fallback when it is not (no RSAT req'd).
#   * Circular nesting (A->B->A) is blocked via a "visited" set keyed
#     on SID / DistinguishedName.
#   * Each resolved account carries its LINEAGE (the path it came in
#     through), a Direct/Nested flag, depth, scope, SID, and a
#     best-effort Enabled status -- all of which matter for audit.
# ============================================================

# --- CONFIGURATION ---
$RemoteServer  = $env:COMPUTERNAME            # Target server (defaults to this machine)
$TargetGroups  = @("Administrators", "Power Users", "Backup Operators", "Remote Desktop Users", "Users")

$ExpandDomainGroups   = $true   # $false = local nesting only, domain groups left unexpanded but flagged
$IncludeEnabledStatus = $true   # Best-effort account enabled/disabled flag (important for risk rating)
$MaxDepth             = 25      # Hard safety ceiling on recursion depth

$Stamp        = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutputFile   = "C:\Reports\GroupMembers_${RemoteServer}_$Stamp.txt"
$CsvFile      = "C:\Reports\GroupMembers_${RemoteServer}_$Stamp.csv"

# --- ENSURE OUTPUT DIRECTORY EXISTS ---
$OutputDir = Split-Path -Path $OutputFile
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ============================================================
# RESOLVER SCRIPTBLOCK
# Runs ON THE TARGET so the local-group view and domain
# connectivity are from the target's own perspective.
# Returns a flat array of fully-resolved membership records.
# ============================================================
$ResolverScript = {
    param($TargetGroups, $MaxDepth, $ExpandDomainGroups, $IncludeEnabledStatus)

    $LocalComputer = $env:COMPUTERNAME

    # Authorities that are built-in pseudo-principals: treat as leaves, never expand.
    $BuiltinAuthorities = @(
        'NT AUTHORITY','NT SERVICE','BUILTIN','Everyone',
        'APPLICATION PACKAGE AUTHORITY','NT VIRTUAL MACHINE'
    )

    # --- Detect AD module once (preferred path for domain expansion) ---
    $AdModule = $false
    if ($ExpandDomainGroups) {
        try { Import-Module ActiveDirectory -ErrorAction Stop; $AdModule = $true } catch { $AdModule = $false }
    }

    # --- Cache the domain naming context for the LDAP fallback ---
    $DefaultNC = $null
    if ($ExpandDomainGroups -and -not $AdModule) {
        try { $DefaultNC = ([ADSI]"LDAP://RootDSE").Get("defaultNamingContext") } catch { $DefaultNC = $null }
    }

    # --- Helpers ---------------------------------------------------------
    function ConvertTo-Sddl {
        param($SidBytes)
        if ($null -eq $SidBytes) { return $null }
        try {
            $bytes = [byte[]]$SidBytes      # cast away COM/object[] wrapping the WinNT provider sometimes returns
            (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
        }
        catch { $null }
    }

    # Domain groups whose membership is defined by primaryGroupID, NOT the
    # 'member' attribute. They cannot be expanded reliably and expanding them
    # is misleading (e.g. "Domain Users" effectively = every domain user), so
    # we FLAG them rather than walk them. Matched by well-known RID or by name.
    $PrimaryGroupRids  = @(513, 514, 515)                            # Domain Users / Guests / Computers
    $PrimaryGroupNames = @('Domain Users','Domain Computers','Domain Guests')

    function Test-NonExpandableGroup {
        param([string]$Sid, [string]$Name)
        if ($Sid -and ($Sid -match '-(\d+)$') -and ([int]$Matches[1] -in $PrimaryGroupRids)) { return $true }
        if ($Name -and ($PrimaryGroupNames -contains $Name)) { return $true }
        return $false
    }

    function Get-WinNTProp {
        param($Object, [string]$Prop)
        try { $Object.GetType().InvokeMember($Prop, 'GetProperty', $null, $Object, $null) }
        catch { $null }
    }

    function Get-MemberScope {
        # Classify a WinNT ADsPath as Local / Builtin / Domain
        param([string]$AdsPath)
        $authority = ($AdsPath -replace '^WinNT://','').Split('/')[0]
        if ($authority -ieq $LocalComputer)       { return 'Local'   }
        if ($BuiltinAuthorities -contains $authority) { return 'Builtin' }
        return 'Domain'
    }

    function Get-LocalUserEnabled {
        param([string]$AdsPath)
        if (-not $IncludeEnabledStatus) { return $null }
        try {
            $u     = [ADSI]"$AdsPath,user"
            $flags = $u.psbase.InvokeGet("UserFlags")
            # 0x2 = ADS_UF_ACCOUNTDISABLE
            return (-not ([int]$flags -band 0x2))
        } catch { return $null }
    }

    function Get-DomainUserEnabled {
        param([string]$Sid)
        if (-not $IncludeEnabledStatus) { return $null }
        if ($AdModule) {
            try { return (Get-ADUser -Identity $Sid -Properties Enabled -ErrorAction Stop).Enabled }
            catch { return $null }
        }
        return $null   # LDAP path sets Enabled inline below
    }

    # ----------------------------------------------------------------
    # Recursive expander. Enumerates the DIRECT members of one group
    # (at $GroupDepth) and, for any member that is itself a group,
    # recurses (member sits at $GroupDepth + 1).
    # ----------------------------------------------------------------
    function Expand-Group {
        param(
            [string]$TopGroup,     # Name of the original target group (for grouping the report)
            [string]$Scope,        # 'Local' or 'Domain' -- how to enumerate THIS group
            [string]$AdsPath,      # WinNT path (Local) -- used for local enumeration
            [string]$Sid,          # SDDL SID  (Domain) -- used for AD/LDAP enumeration
            [string]$Lineage,      # Path taken to reach this group, e.g. "Administrators\DBA_Admins"
            [int]   $GroupDepth,   # Depth of THIS group from the target (target = 0)
            [hashtable]$Visited,   # Loop protection: SID/DN already expanded
            [System.Collections.ArrayList]$Out
        )

        if ($GroupDepth -ge $MaxDepth) {
            [void]$Out.Add([PSCustomObject]@{
                TargetGroup=$TopGroup; PrincipalName='[MAX DEPTH REACHED]'; SamAccountName=$null
                ObjectClass='Note'; Scope=$Scope; MembershipType='Nested'; Depth=$GroupDepth
                Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                Note="Recursion stopped at MaxDepth=$MaxDepth"
            })
            return
        }

        $childDepth = $GroupDepth + 1
        $memberType = if ($childDepth -le 1) { 'Direct' } else { 'Nested' }

        # ---------- LOCAL enumeration (WinNT provider) ----------
        if ($Scope -eq 'Local') {
            try {
                $grp = [ADSI]"$AdsPath"
                $members = @($grp.psbase.Invoke("Members"))
            } catch {
                [void]$Out.Add([PSCustomObject]@{
                    TargetGroup=$TopGroup; PrincipalName="[ERROR enumerating $Lineage]"; SamAccountName=$null
                    ObjectClass='Error'; Scope='Local'; MembershipType=$memberType; Depth=$childDepth
                    Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                    Note=$_.Exception.Message
                })
                return
            }

            foreach ($m in $members) {
                $mPath  = Get-WinNTProp $m 'ADsPath'
                $mName  = Get-WinNTProp $m 'Name'
                $mClass = Get-WinNTProp $m 'Class'
                $mSidB  = Get-WinNTProp $m 'objectSID'
                $mSid   = ConvertTo-Sddl $mSidB
                $mScope = Get-MemberScope $mPath
                $childLineage = "$Lineage\$mName"

                if ($mClass -ieq 'group') {
                    # --- Nested group ---
                    $key = if ($mSid) { $mSid } else { $mPath }
                    if ($Visited.ContainsKey($key)) {
                        [void]$Out.Add([PSCustomObject]@{
                            TargetGroup=$TopGroup; PrincipalName=$mName; SamAccountName=$null
                            ObjectClass='Group'; Scope=$mScope; MembershipType=$memberType; Depth=$childDepth
                            Lineage=$childLineage; SID=$mSid; Identifier=$mPath; Enabled=$null
                            Note='Circular / already-expanded group - not re-expanded'
                        })
                        continue
                    }
                    $Visited[$key] = $true

                    if ($mScope -eq 'Builtin') {
                        [void]$Out.Add([PSCustomObject]@{
                            TargetGroup=$TopGroup; PrincipalName=$mName; SamAccountName=$null
                            ObjectClass='Group'; Scope='Builtin'; MembershipType=$memberType; Depth=$childDepth
                            Lineage=$childLineage; SID=$mSid; Identifier=$mPath; Enabled=$null
                            Note='Built-in/system group - not expanded'
                        })
                    }
                    elseif ($mScope -eq 'Local') {
                        Expand-Group -TopGroup $TopGroup -Scope 'Local' -AdsPath "$mPath,group" -Sid $mSid `
                                     -Lineage $childLineage -GroupDepth $childDepth -Visited $Visited -Out $Out
                    }
                    else { # Domain nested group inside a local group
                        if ($ExpandDomainGroups) {
                            Expand-Group -TopGroup $TopGroup -Scope 'Domain' -AdsPath $mPath -Sid $mSid `
                                         -Lineage $childLineage -GroupDepth $childDepth -Visited $Visited -Out $Out
                        } else {
                            [void]$Out.Add([PSCustomObject]@{
                                TargetGroup=$TopGroup; PrincipalName=$mName; SamAccountName=$null
                                ObjectClass='Group'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                                Lineage=$childLineage; SID=$mSid; Identifier=$mPath; Enabled=$null
                                Note='Domain group - expansion disabled (ExpandDomainGroups=$false)'
                            })
                        }
                    }
                }
                else {
                    # --- Leaf account (user/computer) ---
                    $enabled = if ($mScope -eq 'Local') { Get-LocalUserEnabled $mPath } else { Get-DomainUserEnabled $mSid }
                    [void]$Out.Add([PSCustomObject]@{
                        TargetGroup=$TopGroup; PrincipalName=$mName; SamAccountName=$null
                        ObjectClass=$mClass; Scope=$mScope; MembershipType=$memberType; Depth=$childDepth
                        Lineage=$childLineage; SID=$mSid; Identifier=$mPath; Enabled=$enabled
                        Note=$null
                    })
                }
            }
            return
        }

        # ---------- DOMAIN enumeration ----------
        if ($Scope -eq 'Domain') {

            # Primary-group groups (Domain Users/Guests/Computers): do NOT expand.
            $thisName = ($Lineage -split '\\')[-1]
            $selfType = if ($GroupDepth -le 1) { 'Direct' } else { 'Nested' }
            if (Test-NonExpandableGroup -Sid $Sid -Name $thisName) {
                [void]$Out.Add([PSCustomObject]@{
                    TargetGroup=$TopGroup; PrincipalName=$thisName; SamAccountName=$thisName
                    ObjectClass='Group'; Scope='Domain'; MembershipType=$selfType; Depth=$GroupDepth
                    Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                    Note='Primary-group membership (defined by primaryGroupID, not the member attribute). Effective members = essentially all domain accounts; not expanded.'
                })
                return
            }

            # --- Preferred: ActiveDirectory module ---
            if ($AdModule) {
                $direct = $null
                $adIdentity = if ($Sid) { $Sid } else { $thisName }
                try { $direct = @(Get-ADGroupMember -Identity $adIdentity -ErrorAction Stop) } catch { $direct = $null }
                if ($null -eq $direct) {
                    [void]$Out.Add([PSCustomObject]@{
                        TargetGroup=$TopGroup; PrincipalName="[ERROR expanding $Lineage]"; SamAccountName=$null
                        ObjectClass='Error'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                        Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                        Note='Get-ADGroupMember failed (rights / connectivity / large group)'
                    })
                    return
                }
                foreach ($d in $direct) {
                    $dSid = $d.SID.Value
                    $childLineage = "$Lineage\$($d.name)"
                    if ($d.objectClass -eq 'group') {
                        if ($Visited.ContainsKey($dSid)) {
                            [void]$Out.Add([PSCustomObject]@{
                                TargetGroup=$TopGroup; PrincipalName=$d.name; SamAccountName=$d.SamAccountName
                                ObjectClass='Group'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                                Lineage=$childLineage; SID=$dSid; Identifier=$d.distinguishedName; Enabled=$null
                                Note='Circular / already-expanded group - not re-expanded'
                            })
                            continue
                        }
                        $Visited[$dSid] = $true
                        Expand-Group -TopGroup $TopGroup -Scope 'Domain' -AdsPath $d.distinguishedName -Sid $dSid `
                                     -Lineage $childLineage -GroupDepth $childDepth -Visited $Visited -Out $Out
                    }
                    else {
                        $enabled = Get-DomainUserEnabled $dSid
                        [void]$Out.Add([PSCustomObject]@{
                            TargetGroup=$TopGroup; PrincipalName=$d.name; SamAccountName=$d.SamAccountName
                            ObjectClass=$d.objectClass; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                            Lineage=$childLineage; SID=$dSid; Identifier=$d.distinguishedName; Enabled=$enabled
                            Note=$null
                        })
                    }
                }
                return
            }

            # --- Fallback: raw LDAP / ADSI (no RSAT required) ---
            if (-not $DefaultNC) {
                [void]$Out.Add([PSCustomObject]@{
                    TargetGroup=$TopGroup; PrincipalName="[UNRESOLVED $Lineage]"; SamAccountName=$null
                    ObjectClass='Group'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                    Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                    Note='No AD module and no LDAP naming context - domain group left unexpanded'
                })
                return
            }
            try {
                # Locate the group object by SID when possible, else by name.
                $filter = $null
                if ($Sid) {
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
                        $ba = New-Object byte[] $sidObj.BinaryLength
                        $sidObj.GetBinaryForm($ba, 0)
                        $hex = ($ba | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
                        $filter = "(objectSid=$hex)"
                    } catch { $filter = $null }
                }
                if (-not $filter) {
                    $safeName = $thisName -replace '([\\\*\(\)])','\$1'
                    $filter = "(&(objectClass=group)(sAMAccountName=$safeName))"
                }

                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = [ADSI]"LDAP://$DefaultNC"
                $searcher.Filter     = $filter
                [void]$searcher.PropertiesToLoad.Add("member")
                $grpResult = $searcher.FindOne()
                $memberDNs = @()
                if ($grpResult) { $memberDNs = @($grpResult.Properties["member"]) }

                foreach ($dn in $memberDNs) {
                    $obj = [ADSI]"LDAP://$dn"
                    $oClassVals = @($obj.psbase.Properties["objectClass"])
                    $oClass     = $oClassVals[-1]
                    $oName      = [string]$obj.psbase.Properties["sAMAccountName"].Value
                    $oSidBytes  = $obj.psbase.Properties["objectSid"].Value
                    $oSid       = ConvertTo-Sddl $oSidBytes
                    $childLineage = "$Lineage\$oName"

                    if ($oClass -eq 'group') {
                        $key = if ($oSid) { $oSid } else { $dn }
                        if ($Visited.ContainsKey($key)) {
                            [void]$Out.Add([PSCustomObject]@{
                                TargetGroup=$TopGroup; PrincipalName=$oName; SamAccountName=$oName
                                ObjectClass='Group'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                                Lineage=$childLineage; SID=$oSid; Identifier=$dn; Enabled=$null
                                Note='Circular / already-expanded group - not re-expanded'
                            })
                            continue
                        }
                        $Visited[$key] = $true
                        Expand-Group -TopGroup $TopGroup -Scope 'Domain' -AdsPath $dn -Sid $oSid `
                                     -Lineage $childLineage -GroupDepth $childDepth -Visited $Visited -Out $Out
                    }
                    else {
                        $enabled = $null
                        if ($IncludeEnabledStatus) {
                            try {
                                $uac = [int]$obj.psbase.Properties["userAccountControl"].Value
                                $enabled = (-not ($uac -band 0x2))
                            } catch { $enabled = $null }
                        }
                        [void]$Out.Add([PSCustomObject]@{
                            TargetGroup=$TopGroup; PrincipalName=$oName; SamAccountName=$oName
                            ObjectClass=$oClass; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                            Lineage=$childLineage; SID=$oSid; Identifier=$dn; Enabled=$enabled
                            Note=$null
                        })
                    }
                }
            }
            catch {
                [void]$Out.Add([PSCustomObject]@{
                    TargetGroup=$TopGroup; PrincipalName="[ERROR expanding $Lineage]"; SamAccountName=$null
                    ObjectClass='Error'; Scope='Domain'; MembershipType=$memberType; Depth=$childDepth
                    Lineage=$Lineage; SID=$Sid; Identifier=$AdsPath; Enabled=$null
                    Note=$_.Exception.Message
                })
            }
            return
        }
    }

    # ---------------- Drive each target group ----------------
    $Results = New-Object System.Collections.ArrayList
    foreach ($g in $TargetGroups) {
        $visited = @{}                              # fresh loop-guard per target group
        $seedPath = "WinNT://./$g,group"
        try {
            $seed    = [ADSI]$seedPath
            $seedSid = ConvertTo-Sddl (Get-WinNTProp $seed 'objectSID')
            if ($seedSid) { $visited[$seedSid] = $true }
        } catch {
            [void]$Results.Add([PSCustomObject]@{
                TargetGroup=$g; PrincipalName='[ERROR - group not found]'; SamAccountName=$null
                ObjectClass='Error'; Scope='Local'; MembershipType='Direct'; Depth=0
                Lineage=$g; SID=$null; Identifier=$seedPath; Enabled=$null; Note=$_.Exception.Message
            })
            continue
        }
        Expand-Group -TopGroup $g -Scope 'Local' -AdsPath $seedPath -Sid $seedSid `
                     -Lineage $g -GroupDepth 0 -Visited $visited -Out $Results
    }

    # Tag environment info onto the return so the caller can report it
    [PSCustomObject]@{
        Records  = $Results
        AdModule = $AdModule
        Computer = $LocalComputer
    }
}

# ============================================================
# EXECUTE (locally if target is this box, else via Invoke-Command)
# ============================================================
$IsLocal = ($RemoteServer -eq $env:COMPUTERNAME) -or ($RemoteServer -in @('localhost','127.0.0.1','.'))

try {
    if ($IsLocal) {
        $Payload = & $ResolverScript $TargetGroups $MaxDepth $ExpandDomainGroups $IncludeEnabledStatus
    } else {
        $Payload = Invoke-Command -ComputerName $RemoteServer -ScriptBlock $ResolverScript `
                       -ArgumentList $TargetGroups, $MaxDepth, $ExpandDomainGroups, $IncludeEnabledStatus -ErrorAction Stop
    }
} catch {
    Write-Host "[FATAL] Could not run resolver against '$RemoteServer': $($_.Exception.Message)" -ForegroundColor Red
    return
}

$Records  = @($Payload.Records)
$UsedAd   = $Payload.AdModule

# ============================================================
# BUILD HUMAN-READABLE TXT REPORT
# ============================================================
$Report = @()
$Report += "=" * 70
$Report += " EFFECTIVE GROUP MEMBERSHIP REPORT (nested groups expanded)"
$Report += " Server          : $RemoteServer"
$Report += " Date            : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Report += " Domain expansion: $ExpandDomainGroups   (AD module used: $UsedAd)"
$Report += "=" * 70

foreach ($g in $TargetGroups) {
    $Report += ""
    $Report += "-" * 70
    $Report += " GROUP: $g"
    $Report += "-" * 70

    $rows = $Records | Where-Object { $_.TargetGroup -eq $g }
    if (-not $rows) { $Report += "  (No members found)"; continue }

    # Show actual user/computer accounts indented by depth, with lineage.
    foreach ($r in ($rows | Sort-Object Depth, Lineage)) {
        $indent = '  ' * ($r.Depth + 1)
        $tag    = if ($r.ObjectClass -eq 'Group') { '[GROUP]' }
                  elseif ($r.ObjectClass -in @('Error','Note')) { '[!]' }
                  else { "[$($r.MembershipType)]" }
        $en     = if ($null -ne $r.Enabled) { if ($r.Enabled) { ' (Enabled)' } else { ' (DISABLED)' } } else { '' }
        $Report += "$indent$tag $($r.PrincipalName)  <$($r.ObjectClass)/$($r.Scope)>$en"
        $Report += "$indent      Lineage : $($r.Lineage)"
        if ($r.SID)  { $Report += "$indent      SID     : $($r.SID)" }
        if ($r.Note) { $Report += "$indent      Note    : $($r.Note)" }
    }

    # Per-group summary of EFFECTIVE distinct accounts (the audit headline).
    $accts = $rows | Where-Object { $_.ObjectClass -notin @('Group','Error','Note') }
    $distinct = $accts | Sort-Object SID -Unique
    $disabled = $distinct | Where-Object { $_.Enabled -eq $false }
    $Report += ""
    $Report += "  SUMMARY for ${g}:"
    $Report += "    Distinct effective accounts : $($distinct.Count)"
    $Report += "    Direct                      : $(@($accts | Where-Object {$_.MembershipType -eq 'Direct'} | Sort-Object SID -Unique).Count)"
    $Report += "    Via nested group(s)         : $(@($accts | Where-Object {$_.MembershipType -eq 'Nested'} | Sort-Object SID -Unique).Count)"
    $Report += "    Disabled accounts           : $($disabled.Count)"
}

$Report += ""
$Report += "=" * 70
$Report += " END OF REPORT"
$Report += "=" * 70

# ============================================================
# WRITE OUTPUTS
# ============================================================
$Report | Out-File -FilePath $OutputFile -Encoding UTF8
$Records | Select-Object TargetGroup, PrincipalName, SamAccountName, ObjectClass, Scope,
                         MembershipType, Depth, Lineage, Enabled, SID, Identifier, Note |
           Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

$Report | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "TXT report saved to: $OutputFile" -ForegroundColor Green
Write-Host "CSV evidence saved to: $CsvFile"  -ForegroundColor Green
