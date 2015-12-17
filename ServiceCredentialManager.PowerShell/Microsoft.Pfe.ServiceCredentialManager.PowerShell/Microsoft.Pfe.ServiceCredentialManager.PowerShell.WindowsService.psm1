#
# Copyright © Microsoft Corporation. All Rights Reserved.
# This code released under the terms of the 
# Microsoft Public License (MS-PL, http://opensource.org/licenses/ms-pl.html.)
# Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
# We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that. 
# You agree: 
# (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
# (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; 
# and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code 
#

# Import the helper functions.
Import-Module -Name "$PSScriptRoot\Microsoft.Pfe.ServiceCredentialManager.PowerShell.psm1" -Force -DisableNameChecking

# .ExternalHelp Microsoft.Pfe.ServiceCredentialManager.PowerShell.WindowsService.psm1-help.xml
function Set-WindowsServiceCredential
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UserNamePassword')]
        [string] $ServiceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [pscredential] $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserNamePassword')]
        [string] $UserName,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserNamePassword')]
        [string] $Password,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'UserNamePassword')]
        [switch] $DomainCredential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'UserNamePassword')]
        [string] $TargetComputerName = 'localhost'
    )

    #
    # Get the new credential.
    #

    switch ($PSCmdlet.ParameterSetName)
    {
        'Credential' {
            $newCredential = $Credential
        }

        'UserNamePassword' {
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $newCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList $UserName, $securePassword
        }
    }

    #
    # Verifies the given credential.
    #

    if (-not (testCredential -Credential $newCredential -AsDomain:$DomainCredential))
    {
        $context = if ($DomainCredential) { 'domain' } else { 'machine' }
        Write-Error -Message ('Faild the verification of the user "{0}" credentials in {1} context.' -f $newCredential.UserName, $context)
        return $false
    }
    Write-Verbose -Message ('Succeeded the verification of the user "{0}" credentials.' -f $newCredential.UserName)

    #
    # Get the service's instance.
    #
    # Ref: Win32_Service class
    #      https://msdn.microsoft.com/en-us/library/aa394418(v=vs.85).aspx
    #

    $w32Service = Get-WmiObject -ComputerName $TargetComputerName -Class 'Win32_Service' -Filter ('Name="{0}"' -f $ServiceName)
    if ($w32Service -eq $null)
    {
        Write-Error -Message ('Cannot found the "{0}" service on "{1}".' -f $ServiceName, $TargetComputerName)
        return $false
    }
    Write-Verbose -Message ('Found the "{0}" service on "{1}".' -f $ServiceName, $TargetComputerName)

    # Save the service's state.
    $originalServiceStatus = $w32Service.State

    #
    # Stop the target service if it is running.
    #
    # Ref: StopService method of the Win32_Service class
    #      https://msdn.microsoft.com/en-us/library/aa393673(v=vs.85).aspx
    #

    switch ($originalServiceStatus)
    {
        'Running' {
            Write-Verbose -Message ('Stopping the "{0}" service on "{1}"...' -f $ServiceName, $TargetComputerName)

            $result = $w32Service.StopService()
            if ($result.ReturnValue -ne 0)
            {
                $wmiErrorMessage = getWmiErrorMessageText -WmiReturnValue $result.ReturnValue
                Write-Error -Message ('Failed to stop "{0}" service on "{1}". {2}' -f $ServiceName, $TargetComputerName, $wmiErrorMessage)
                return $false
            }

            Write-Verbose -Message ('The "{0}" service on "{1}" is stopped.' -f $ServiceName, $TargetComputerName)
        }
        'Stopped' {
            Write-Verbose -Message ('The "{0}" service on "{1}" is already stopped.' -f $ServiceName, $TargetComputerName)
        }
        default {
            Write-Error -Message ('The "{0}" service on "{1}" is in "{2}".' -f $ServiceName, $TargetComputerName, $originalServiceStatus)
            return $false
        }
    }

    #
    # Set the new credential to the service.
    #
    # Ref: Change method of the Win32_Service class
    #      https://msdn.microsoft.com/en-us/library/aa384901(v=vs.85).aspx
    # Ref: StartService method of the Win32_Service class
    #      https://msdn.microsoft.com/en-us/library/aa393660(v=vs.85).aspx
    #

    Write-Verbose ('Set the new credentials "{0}" to "{1}" service on the "{2}".' -f $newCredential.UserName, $ServiceName, $TargetComputerName)
    $result = $w32Service.Change($null, $null, $null, $null, $null, $null, $newCredential.UserName, $newCredential.GetNetworkCredential().Password, $null, $null, $null)
    if ($result.ReturnValue -ne 0)
    {
        $wmiErrorMessage = getWmiErrorMessageText -WmiReturnValue $result.ReturnValue
        Write-Warning -Message ('Failed to set the new credentials "{0}" to "{1}" service on "{2}". {3}' -f $newCredential.UserName, $ServiceName, $TargetComputerName, $wmiErrorMessage)

        # Recovering the service state from stopped.
        if ($originalServiceStatus -eq 'Running')
        {
            Write-Verbose -Message ('Recovering state of "{0}" service on "{1}"...' -f $ServiceName, $TargetComputerName)
            $result = $w32Service.StartService()
            if ($result.ReturnValue -ne 0)
            {
                $wmiErrorMessage = getWmiErrorMessageText -WmiReturnValue $result.ReturnValue
                Write-Error -Message ('Failed to start "{0}" service on "{1}". {2}' -f $ServiceName, $TargetComputerName, $wmiErrorMessage)
                return $false
            }
        }
    }

    #
    # Restore the service state.
    #
    # ref: ManagementObject.Get Method ()
    #      https://msdn.microsoft.com/en-us/library/k18t5sbs.aspx
    # Ref: StartService method of the Win32_Service class
    #      https://msdn.microsoft.com/en-us/library/aa393660(v=vs.85).aspx
    #

    # Refresh state of service.
    $w32Service.Get()

    if (($originalServiceStatus -eq 'Running') -and ($w32Service.State -eq 'Stopped'))
    {
        Write-Verbose -Message ('Restoring state of "{0}" service on "{1}"...' -f $ServiceName, $TargetComputerName)
        $result = $w32Service.StartService()
        if ($result.ReturnValue -ne 0)
        {
            $wmiErrorMessage = getWmiErrorMessageText -WmiReturnValue $result.ReturnValue
            Write-Error -Message ('Failed to start "{0}" service on "{1}". {2}' -f $ServiceName, $TargetComputerName, $wmiErrorMessage)
            return $false
        }
    }

    Write-Verbose ('Set the new credentials to the "{0}" service on "{1}" was completed.' -f $ServiceName, $TargetComputerName)
    return $true
}

# .ExternalHelp Microsoft.Pfe.ServiceCredentialManager.PowerShell.WindowsService.psm1-help.xml
function Get-WindowsServiceCredential
{
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string] $ServiceName,

        [Parameter(Mandatory = $false)]
        [string] $TargetComputerName = 'localhost'
    )

    $w32Service = Get-WmiObject -ComputerName $TargetComputerName -Class 'Win32_Service' -Filter ('Name="{0}"' -f $ServiceName)
    if ($w32Service -eq $null)
    {
        Write-Error -Message ('Cannot found the "{0}" service on "{1}".' -f $ServiceName, $TargetComputerName)
        return $null
    }
    Write-Verbose -Message ('Found the "{0}" service on "{1}".' -f $ServiceName, $TargetComputerName)

    return [pscustomobject] @{
        ComputerName = $TargetComputerName
        ServiceName  = $ServiceName
        UserName     = $w32Service.StartName
    }
}

Export-ModuleMember -Function @(
    'Set-WindowsServiceCredential',
    'Get-WindowsServiceCredential'
)
