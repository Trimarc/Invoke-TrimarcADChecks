<#
.SYNOPSIS
Performs AD Scan

.DESCRIPTION
This script is designed for a single AD forest and is not designed to capture all data for a multiple domain forest.
Note that if this script is used for a single domain in a multi-domain AD forest, not all elements may be captured.

.PARAMETER DomainName
Forest Name of your AD

.PARAMETER RootDir
Location to save all output too

.EXAMPLE
PS>.\Invoke-TrimarcADChecks.ps1

This is the prefer method of running this script, all data will be store at the following location C:\TM\
.EXAMPLE
PS>.\Invoke-TrimarcADChecks.ps1 -DomainName ad.vulndomain.corp -RootDir c:\FOLDERPATH

.EXAMPLE
PS>Set-ExecutionPolicy Bypass -Scope Process -Force 
PS>.\Invoke-TrimarcADChecks.ps1

.NOTES
AUTHOR: Sean Metcalf
AUTHOR EMAIL: sean@trimarcsecurity.com
COMPANY: Trimarc Security, LLC (Trimarc)
COPYRIGHT: 2020 - 2023 Trimarc Security, LLC (Trimarc)
WEBSITE: https://www.TrimarcSecurity.com

This script requires the following:
 * PowerShell 5.0 (minimum)
 * Windows 10/2016
 * Active Directory PowerShell Module
 * Group Policy PowerShell Module
If the above requirements are not met, results will be inconsistent.
This script is provided as-is, without support.
#>

Param (
    [string]$DomainName = $env:userdnsdomain,
    [string]$RootDir = 'C:\TM\'
)

function Get-ADForestInfo {
    Param (
        $DomainName
    )

    $ADForestFunctionalLevel = (Get-ADForest).ForestMode
    $ADDomainFunctionalLevel = (Get-ADDomain $DomainName).DomainMode

    Write-Host "The AD Forest Functional Level is $ADForestFunctionalLevel"
    Write-Host "The AD Domain Functional Level ($DomainName) is $ADDomainFunctionalLevel"
}

function Get-DomainControllers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $DomainDCs = Get-ADDomainController -Filter * -Server $DomainDC
    $DomainDCs | Select HostName,OperatingSystem | Format-Table -AutoSize

    $DomainDCArray = @()
    foreach ($DomainDCItem in $DomainDCs) {
        $DomainDCItem | Add-Member -MemberType NoteProperty -Name FSMORolesList -Value ($DomainDCItem.OperationMasterRoles -join ';') -Force 
        $DomainDCItem | Add-Member -MemberType NoteProperty -Name PartitionsList -Value ($DomainDCItem.Partitions -join ';') -Force 
        [array]$DomainDCArray += $DomainDCItem
    }

    $DomainDCArray | Sort OperatingSystem | Export-CSV "$ReportDir\TrimarcADChecks-DomainDCs-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainDCs-$DomainName.csv"
}

function Get-TombstoneInfo {
    Param (
        $DomainDC
    )

    $ADRootDSE = Get-ADRootDSE -Server $DomainDC
    $ADConfigurationNamingContext = $ADRootDSE.configurationNamingContext
    
    $TombstoneObjectInfo = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ADConfigurationNamingContext" -Partition "$ADConfigurationNamingContext" -Properties * 
    [int]$TombstoneLifetime = $TombstoneObjectInfo.tombstoneLifetime

    if ($TombstoneLifetime -eq 0) { 
        $TombstoneLifetime = 60 
    }

    Write-Host "The AD Forest Tombstone lifetime is set to $TombstoneLifetime days."
}

function Get-ADBackups {
    Param (
        $DomainName,
        $DomainDC
    )

    $ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
    $Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType,(Get-ADDomain $DomainName).DNSRoot)
    $DomainController = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne($Context)
    
    [string[]]$Partitions = (Get-ADRootDSE -Server $DomainDC).namingContexts
    foreach ($Partition in $Partitions) {
        $dsaSignature = $DomainController.GetReplicationMetadata($Partition).Item("dsaSignature")
        Write-Host "$Partition was backed up $($dsaSignature.LastOriginatingChangeTime.DateTime)" 
    }
}

function Get-ADTrustInfo {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADTrusts = Get-ADTrust -Filter * -Server $DomainDC
    
    if ($ADTrusts.Count -gt 0) {
        $ADTrusts | Select Source,Target,Direction,IntraForest,SelectiveAuth,SIDFilteringForestAware,SIDFilteringQuarantined | Format-Table -AutoSize
        $ADTrusts | Export-CSV "$ReportDir\TrimarcADChecks-DomainTrustReport-$DomainName.csv" -NoTypeInformation
        Write-Host "File save to $ReportDir\TrimarcADChecks-DomainTrustReport-$DomainName.csv" 
    } else {
        Write-Host "No Trust Found"
    }
}

function Get-DomainUsers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $UserLogonAge,
        $UserPasswordAge
    )

    $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -days $UserLogonAge)  
    $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -days $UserPasswordAge)

    $ADLimitedProperties = @("Name","Enabled","SAMAccountname","DisplayName","Enabled","LastLogonDate","PasswordLastSet",
        "PasswordNeverExpires","PasswordNotRequired","PasswordExpired","SmartcardLogonRequired","AccountExpirationDate",
        "AdminCount","Created","Modified","LastBadPasswordAttempt","badpwdcount","mail","CanonicalName","DistinguishedName",
        "ServicePrincipalName","SIDHistory","PrimaryGroupID","UserAccountControl","DoesNotRequirePreAuth")

    [array]$DomainUsers = Get-ADUser -Filter * -Property $ADLimitedProperties -Server $DomainDC
    [array]$DomainEnabledUsers = $DomainUsers | Where {$_.Enabled -eq $True }
    [array]$DomainEnabledInactiveUsers = $DomainEnabledUsers | Where { ($_.LastLogonDate -le $LastLoggedOnDate) -AND ($_.PasswordLastSet -le $PasswordStaleDate) }
    [array]$DomainUsersWithReversibleEncryptionPasswordArray = $DomainUsers | Where { $_.UserAccountControl -band 0x0080 } 
    [array]$DomainUserPasswordNotRequiredArray = $DomainUsers | Where {$_.PasswordNotRequired -eq $True}
    [array]$DomainUserPasswordNeverExpiresArray = $DomainUsers | Where {$_.PasswordNeverExpires -eq $True}
    [array]$DomainKerberosDESUsersArray = $DomainUsers | Where { $_.UserAccountControl -band 0x200000 }
    [array]$DomainUserDoesNotRequirePreAuthArray = $DomainUsers | Where {$_.DoesNotRequirePreAuth -eq $True}
    [array]$DomainUsersWithSIDHistoryArray = $DomainUsers | Where {$_.SIDHistory -like "*"}

    Write-Host "Total Users: $($DomainUsers.Count)"
    Write-Host "Enabled Users: $($DomainEnabledUsers.Count)"
    Write-Host "`nEnabled Users Identified as Inactive: $($DomainEnabledInactiveUsers.Count)"
    Write-Host "Enabled Users With Reversible Encryption Password: $($DomainUsersWithReversibleEncryptionPasswordArray.Count)"
    Write-Host "Enabled Users With Password Not Required: $($DomainUserPasswordNotRequiredArray.Count)"
    Write-Host "Enabled Users With Password Never Expires: $($DomainUserPasswordNeverExpiresArray.Count)"
    Write-Host "Enabled Users With Kerberos DES: $($DomainKerberosDESUsersArray.Count)"
    Write-Host "Enabled Users That Do Not Require Kerberos Pre-Authentication: $($DomainUserDoesNotRequirePreAuthArray.Count)"
    Write-Host "Enabled Users With SID History: $($DomainUsersWithSIDHistoryArray.Count)"
    Write-Host "`nReview & clean up as appropriate"

    $DomainUsers | Export-CSV "$ReportDir\TrimarcADChecks-DomainUserReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainUserReport-$DomainName.csv" 
}

function Get-DomainPasswordPolicy {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    [array]$DomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainDC
    $DomainPasswordPolicy | Format-List
    $DomainPasswordPolicy | Export-CSV "$ReportDir\TrimarcADChecks-DomainPasswordPolicy-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainUserReport-$DomainName.csv" 
}

function Get-DomainAdminUser {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $ADDomainInfo
    )

    $ADLimitedProperties = @("Name","Enabled","Created","PasswordLastSet","LastLogonDate","ServicePrincipalName","SID")
    $DomainDefaultAdminAccount = Get-ADUser "$($ADDomainInfo.DomainSID)-500" -Server $DomainDC -Properties $ADLimitedProperties
    $DomainDefaultAdminAccount | Select $ADLimitedProperties | Format-List
    $DomainDefaultAdminAccount | Export-CSV "$ReportDir\TrimarcADChecks-DomainDefaultAdminAccount-$DomainName.csv" -NoTypeInformation 
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainDefaultAdminAccount-$DomainName.csv" 
}

function Get-KRBTGT {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $DomainKRBTGTAccount = Get-ADUser 'krbtgt' -Server $DomainDC -Properties DistinguishedName,'msds-keyversionnumber',Created,PasswordLastSet    
    $DomainKRBTGTAccount | Select DistinguishedName,Created,PasswordLastSet,'msds-keyversionnumber' | Format-Table -AutoSize
    $DomainKRBTGTAccount | Export-CSV "$ReportDir\TrimarcADChecks-DomainKRBTGTAccount-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainKRBTGTAccount-$DomainName.csv" 
}

function Get-ADAdmins {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADAdminArray = @()
    $ADAdminMembers = Get-ADGroupMember Administrators -Recursive -Server $DomainDC
    foreach ($ADAdminMemberItem in $ADAdminMembers) { 
        try {
            Switch ($ADAdminMemberItem.objectClass) {
                'User' { [array]$ADAdminArray += Get-ADUser $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet,ServicePrincipalName -Server $DomainDC }
                'Computer' { [array]$ADAdminArray += Get-ADComputer $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC }
                'msDS-GroupManagedServiceAccount' { [array]$ADAdminArray += Get-ADServiceAccount $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC}
            }
        } catch {
            Write-Warning "The security principal member ($ADAdminMemberItem) may be in another domain or is unreachable" ; $ADAdminArray += $ADAdminMemberItem
        }
    }

    $ADAdminArray | sort PasswordLastSet | Select name,DistinguishedName,PasswordLastSet,LastLogonDate,ObjectClass | Format-Table -AutoSize
    $ADAdminArray | Export-CSV "$ReportDir\TrimarcADChecks-ADAdminAccountReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-ADAdminAccountReport-$DomainName.csv" 
}

function Get-SPNs {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADAdminArray = @()
    $ADAdminMembers = Get-ADGroupMember Administrators -Recursive -Server $DomainDC
    foreach ($ADAdminMemberItem in $ADAdminMembers) { 
        try {
            Switch ($ADAdminMemberItem.objectClass) {
                'User' { [array]$ADAdminArray += Get-ADUser $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet,ServicePrincipalName -Server $DomainDC }
                'Computer' { [array]$ADAdminArray += Get-ADComputer $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC }
                'msDS-GroupManagedServiceAccount' { [array]$ADAdminArray += Get-ADServiceAccount $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC}
            }
        } catch {
            Write-Warning "The security principal member ($ADAdminMemberItem) may be in another domain or is unreachable" ; $ADAdminArray += $ADAdminMemberItem
        }
    }

    $ADAdminArray | Where {$_.ServicePrincipalName} | Select name,DistinguishedName,ServicePrincipalName | Format-Table -AutoSize
    $ADAdminArray | Where {$_.ServicePrincipalName} | Export-CSV "$ReportDir\TrimarcADChecks-ADAdminSPNReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-ADAdminSPNReport-$DomainName.csv" 
}

function Get-ProtectedUsers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ProtectedUsersGroupMembership = Get-ADGroupMember 'Protected Users' -Server $DomainDC
    $ProtectedUsersGroupMembership | Select name,DistinguishedName,objectClass | Format-Table
    $ProtectedUsersGroupMembership | Export-CSV "$ReportDir\TrimarcADChecks-ProtectedUsersGroupMembershipReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-ProtectedUsersGroupMembershipReport-$DomainName.csv" 
}

function Get-UsersFromGroup {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $GroupName
    )

    $ADPrivGroupItemGroupMembership = @()
    try { 
        Write-Host "`n$GroupName Group:" -Fore Cyan

        $ADPrivGroupItemGroupMembership = Get-ADGroupMember $GroupName -Server $DomainDC 
        if ($ADPrivGroupItemGroupMembership.count -ge 1) {
            $ADPrivGroupItemGroupMembership | Select name,DistinguishedName,objectClass | Format-Table
            $ADPrivGroupItemGroupMembership | Export-CSV "$ReportDir\TrimarcADChecks-PrivGroups-$DomainName-$GroupName.csv" -NoTypeInformation
            Write-Host "File save to $ReportDir\TrimarcADChecks-PrivGroups-$DomainName-$GroupName.csv"
         } else { 
             Write-Host "No members"
         }
     } catch { 
         Write-Warning "An error occured when attempting to enumerate group membership"
     }
}

function Get-DomainPrivilegedADGroups {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    ## Privileged AD Group Array
    $GroupNames = @(
        'Administrators',
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Server Operators',
        'Group Policy Creator Owners',
        'DNSAdmins',
        'Enterprise Key Admins',
        'Exchange Domain Servers',
        'Exchange Enterprise Servers',
        'Exchange Admins',
        'Organization Management',
        'Exchange Windows Permissions'
    )
   
    foreach ($GroupName in $GroupNames) {
        Get-UsersFromGroup -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -GroupName $GroupName
    }

    [array]$GroupNames = Get-ADGroup -filter {Name -like "*VMWare*"}  -Server $DomainDC
    foreach ($GroupName in $GroupNames) {
        Get-UsersFromGroup -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -GroupName $GroupName
    }
}

function Get-KerberosDelegation {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $DomainDN
    )

    $ADLimitedProperties = @("Name","ObjectClass","PrimaryGroupID","UserAccountControl","ServicePrincipalName","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity")
    

    $KerberosDelegationArray = @()
    [array]$KerberosDelegationObjects = Get-ADObject -filter {((UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $DomainDC -Properties $ADLimitedProperties -SearchBase $DomainDN 

    foreach ($KerberosDelegationObjectItem in $KerberosDelegationObjects) {
        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x0080000) { 
            $KerberosDelegationServices = 'All Services'
            $KerberosType = 'Unconstrained' 
        } else { 
            $KerberosDelegationServices = 'Specific Services'
            $KerberosType = 'Constrained' 
        } 

        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x1000000) { 
            $KerberosDelegationAllowedProtocols = 'Any (Protocol Transition)'
            $KerberosType = 'Constrained with Protocol Transition'
        } else { 
            $KerberosDelegationAllowedProtocols = 'Kerberos'
        }

        if ($KerberosDelegationObjectItem.'msDS-AllowedToActOnBehalfOfOtherIdentity') { 
            $KerberosType = 'Resource-Based Constrained Delegation'
        } 

        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationServices -Value $KerberosDelegationServices -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name DelegationType -Value $KerberosType -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationAllowedProtocols -Value $KerberosDelegationAllowedProtocols -Force

        [array]$KerberosDelegationArray += $KerberosDelegationObjectItem
    }

    $KerberosDelegationArray | Sort DelegationType | Select DistinguishedName,DelegationType,Name,ServicePrincipalName | Format-Table -AutoSize
    $KerberosDelegationArray | Sort DelegationType | Export-CSV "$ReportDir\TrimarcADChecks-KerberosDelegationReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-KerberosDelegationReport-$DomainName.csv" 
}

function Get-NameForGUID{
    # From http://blog.wobl.it/2016/04/active-directory-guid-to-friendly-name-using-just-powershell/
    [CmdletBinding()]
    Param(
        [guid]$guid,
        [string]$ForestDNSName
    )
    Begin{
        if (!$ForestDNSName) { 
            $ForestDNSName = (Get-ADForest $ForestDNSName).Name 
        }

        if ($ForestDNSName -notlike "*=*") { 
            $ForestDNSNameDN = "DC=$($ForestDNSName.replace(".", ",DC="))" 
        }

        $ExtendedRightGUIDs = "LDAP://cn=Extended-Rights,cn=configuration,$ForestDNSNameDN"
        $PropertyGUIDs = "LDAP://cn=schema,cn=configuration,$ForestDNSNameDN"
    }
    Process{
        if ($guid -eq "00000000-0000-0000-0000-000000000000"){
            Return "All"
        } else {
            $rightsGuid = $guid
            $property = "cn"
            $SearchAdsi = ([ADSISEARCHER]"(rightsGuid=$rightsGuid)")
            $SearchAdsi.SearchRoot = $ExtendedRightGUIDs
            $SearchAdsi.SearchScope = "OneLevel"
            $SearchAdsiRes = $SearchAdsi.FindOne()
            if ($SearchAdsiRes){
                Return $SearchAdsiRes.Properties[$property]
            } else {
                $SchemaGuid = $guid
                $SchemaByteString = "\" + ((([guid]$SchemaGuid).ToByteArray() | %{$_.ToString("x2")}) -Join "\")
                $property = "ldapDisplayName"
                $SearchAdsi = ([ADSISEARCHER]"(schemaIDGUID=$SchemaByteString)")
                $SearchAdsi.SearchRoot = $PropertyGUIDs
                $SearchAdsi.SearchScope = "OneLevel"
                $SearchAdsiRes = $SearchAdsi.FindOne()
                if ($SearchAdsiRes){
                    Return $SearchAdsiRes.Properties[$property]
                } else {
                    Write-Host -f Yellow $guid
                    Return $guid.ToString()
                }
            }
        }
    }
}

function Get-DomainPermissions {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $ForestDNSName
    )

    $ForestDomainObjectData = Get-ADObject $ADDomainInfo.DistinguishedName -Properties * -Server $DomainDC
    $ForestDomainObjectSecurityData = $ForestDomainObjectData.nTSecurityDescriptor.Access
    
    $ForestDomainObjectPermissions = @()

    foreach ($ForestDomainObjectSecurityDataItem in $ForestDomainObjectSecurityData) {
        $ObjectTypeName = Get-NameForGUID $ForestDomainObjectSecurityDataItem.ObjectType -ForestDNSName $ForestDNSName
        $InheritedObjectTypeName = Get-NameForGUID $ForestDomainObjectSecurityDataItem.InheritedObjectType -ForestDNSName $ForestDNSName

        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name ObjectTypeName -Value $ObjectTypeName -Force
        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name InheritedObjectTypeName -Value $InheritedObjectTypeName -Force

        [array]$ForestDomainObjectPermissions += $ForestDomainObjectSecurityDataItem
    }

    $ForestDomainObjectPermissions | Sort IdentityReference | Select IdentityReference,ActiveDirectoryRights,InheritedObjectTypeName,ObjectTypeName,`
    InheritanceType,ObjectFlags,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags,ObjectType,InheritedObjectType | `
    Export-CSV "$ReportDir\TrimarcADChecks-DomainRootPermissionReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainRootPermissionReport-$DomainName.csv" 
}

function Get-DuplicateSPNs {
    Param (
        $ReportDir,
        $DomainName
    )

    $SetSPN = SetSPN -X -F | Where {$_ -notlike "Processing entry*"}
    $SetSPN
    $SetSPN | Out-File "$ReportDir\TrimarcADChecks-ADForestDuplicateSPNReport-$DomainName.txt"
    Write-Host "File save to $ReportDir\TrimarcADChecks-ADForestDuplicateSPNReport-$DomainName.csv" 
}

function Get-SYSVOLcpassword {
    Param (
        $ReportDir,
        $DomainName
    )

    $GPPPasswordData = findstr /S /I cpassword "\\$DomainName\SYSVOL\$DomainName\Policies\*.xml"
    $GPPPasswordData
    $GPPPasswordData | Out-File "$ReportDir\TrimarcADChecks-GPPPasswordDataReport-$DomainName.txt"
    Write-Host "File save to $ReportDir\TrimarcADChecks-GPPPasswordDataReport-$DomainName.csv" 
}

function Get-GPOOwners {
    Param (
        $ReportDir,
        $DomainName
    )

    [Array]$DomainGPOs = Get-GPO -All -Domain $DomainName
    $DomainGPOs | Select DisplayName,Owner | Format-Table -AutoSize
    $DomainGPOs | Out-File "$ReportDir\TrimarcADChecks-DomainGPOData-$DomainName.csv"
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainGPOData-$DomainName.csv"
}

function Get-GPOPermissions {
    Param (
        $ReportDir,
        $DomainName
    )

    [Array]$DomainGPOs = Get-GPO -All -Domain $DomainName
    $GPOPermissions = foreach ($DomainGPO in $DomainGPOs)
    {
        Get-GPPermissions -Guid $DomainGPO.Id -All | Where {$_.Trustee.SidType.ToString() -ne "WellKnownGroup"} | Select `
        @{n='GPOName';e={$DomainGPO.DisplayName}},
        @{n='AccountName';e={$_.Trustee.Name}},
        @{n='AccountType';e={$_.Trustee.SidType.ToString()}},
        @{n='Permissions';e={$_.Permission}}
    }

    $GPOPermissions | Format-Table
    $GPOPermissions | Export-CSV "$ReportDir\TrimarcADChecks-DomainGPOPermissions-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\TrimarcADChecks-DomainGPOPermissions-$DomainName.csv"
}

# Import Modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

# Create Folders
$ReportDir = "$($RootDir)Trimarc-ADReports"
New-Item -Type Directory -Path $RootDir -Force | Out-Null
New-Item -Type Directory -Path $ReportDir -Force | Out-Null

# Default Var
[int]$UserLogonAge = '180'
[int]$UserPasswordAge = '180'

# Log File
$TimeVal = Get-Date -UFormat '%Y-%m-%d-%H-%M'
Start-Transcript "$ReportDir\InvokeTrimarcADChecks-LogFile.txt" -Force

if (!$DomainName) { $DomainName = (Get-ADDomain).DNSRoot } 

## Get AD Forest
$ADForestInfo = Get-ADForest
$ADDomainInfo = Get-ADDomain $DomainName
$DomainDC = $ADDomainInfo.PDCEmulator 

Write-Host "Starting AD Discovery & Checks" -Fore Cyan

if (($ADForestInfo.Domains).count -gt 1) { 
    Write-Host "There are $(($ADForestInfo.Domains).count) domains in the AD Forest.
     Only the currently selected domain ($DomainName) is being analyzed." }
else { 
    Write-Host "The AD Forest is a single domain forest and is now being analyzed."
}

## Get AD Forest & Domain Info
$ForestDNSName = $ADForestInfo.Name
$ADForestName = $ADForestInfo.RootDomain
$DomainDN = $ADDomainInfo.DistinguishedName

Write-Host "`nForest Name: $ADForestName" -Fore Cyan
Get-ADForestInfo -DomainName $DomainName

## Get Domain Controllers 
Write-Host "`nAD Forest Domain Controllers:" -Fore Cyan
Get-DomainControllers -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Tombstone Lifetime
Write-Host "`nThe AD Forest Tombstone lifetime:" -Fore Cyan
Get-TombstoneInfo -DomainDC $DomainDC

## AD Backups
Write-Host "`nDetermining last supported backup of AD partitions:" -ForegroundColor Cyan
Get-ADBackups -DomainName $DomainName -DomainDC $DomainDC

## AD Trusts
Write-Host "`nActive Directory Trusts:" -Fore Cyan
Get-ADTrustInfo -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Get Domain User Information
Write-Host "`nDomain User Report:" -ForegroundColor Cyan
Get-DomainUsers -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -UserLogonAge $UserLogonAge -UserPasswordAge $UserPasswordAge

## Domain Password Policy
Write-Host "`nDomain Password Policy:" -Fore Cyan
Get-DomainPasswordPolicy -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Default Domain Administrator Account 
Write-Host "`nDefault Domain Administrator Account:" -Fore Cyan
Get-DomainAdminUser -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -ADDomainInfo $ADDomainInfo

## KRBTGT Account Password
Write-Host "`nDomain Kerberos Service Account (KRBTGT):" -Fore Cyan
Get-KRBTGT -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Identify AD Admins
Write-Host "`nAD Admins:" -Fore Cyan
Get-ADAdmins -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Identify AD Admins with SPNs
Write-Host "`nAD Admin Accounts with SPNs:" -Fore Cyan
Get-SPNs -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Protected Users group membership, compare with AD Admins
Write-Host "`nDomain Protected Users Group Membership:" -Fore Cyan
Get-ProtectedUsers -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Discover Default privileged group membership
Get-DomainPrivilegedADGroups -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC
    
## Identify Accounts with Kerberos Delegation
Write-Host "`nDomain Accounts with Kerberos Delegation:" -Fore Cyan
Get-KerberosDelegation -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -DomainDN $DomainDN

## Get Domain Permissions
Write-Host "`nGathering Domain Permissions:" -Fore Cyan
Get-DomainPermissions -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -ForestDNSName $ForestDNSName

## Duplicate SPNs
Write-Host "`nAD Forest Duplicate SPN Report:" -Fore Cyan
Get-DuplicateSPNs -ReportDir $ReportDir -DomainName $DomainName

## Scan SYSVOL for Group Policy Preference Passwords
Write-Host "`nSYSVOL Scan for Group Policy Preference Passwords:" -Fore Cyan
Get-SYSVOLcpassword -ReportDir $ReportDir -DomainName $DomainName

## Get GPO Owners
Write-Host "`nGPO Owners:" -Fore Cyan
Get-GPOOwners -ReportDir $ReportDir -DomainName $DomainName

## Get GPO Permissions
Write-Host "`nGPO Permissions:" -Fore Cyan
Get-GPOPermissions -ReportDir $ReportDir -DomainName $DomainName

#####
$EndMessageText = 
@"
Data files generated and saved to $ReportDir

############################################################################################################################################################################
#                                                                                                                                                                          #
# Contact Trimarc to perform a full Active Directory Security Assessment which covers these security items (& many more) and provides detailed actionable recommendations  #
#                                                                                                                                                                          #
#                                                        ----------------------------------------------------------                                                        #
#                                                        |   TrimarcSecurity.com   |   info@TrimarcSecurity.com   |                                                        #
#                                                        ----------------------------------------------------------                                                        #
#                                                                                                                                                                          #
############################################################################################################################################################################
"@
$EndMessageText
Stop-Transcript
