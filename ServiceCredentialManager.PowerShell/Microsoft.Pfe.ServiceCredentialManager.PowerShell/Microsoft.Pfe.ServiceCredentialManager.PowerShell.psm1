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

function getWmiErrorMessageText
{
    [OutputType([string])]
    param (
        [uint32] $WmiReturnValue
    )

    switch ($WmiReturnValue)
    {
         0 { return 'Success: The request was accepted.' }
         1 { return 'Not Supported: The request is not supported.' }
         2 { return 'Access Denied: The user did not have the necessary access.' }
         3 { return 'Dependent Services Running: The service cannot be stopped because other services that are running are dependent on it.' }
         4 { return 'Invalid Service Control: The requested control code is not valid, or it is unacceptable to the service.' }
         5 { return 'Service Cannot Accept Control: The requested control code cannot be sent to the service.' }
         6 { return 'Service Not Active: The service has not been started.' }
         7 { return 'Service Request Timeout: The service did not respond to the start request in a timely fashion.' }
         8 { return 'Unknown Failure: Unknown failure when starting the service.' }
         9 { return 'Path Not Found: The directory path to the service executable file was not found.' }
        10 { return 'Service Already Running: The service is already running.' }
        11 { return 'Service Database Locked: The database to add a new service is locked.' }
        12 { return 'Service Dependency Deleted: A dependency this service relies on has been removed from the system.' }
        13 { return 'Service Dependency Failure: The service failed to find the service needed from a dependent service.' }
        14 { return 'Service Disabled: The service has been disabled from the system.' }
        15 { return 'Service Logon Failed: The service does not have the correct authentication to run on the system.' }
        16 { return 'Service Marked For Deletion: This service is being removed from the system.' }
        17 { return 'Service No Thread: The service has no execution thread.' }
        18 { return 'Status Circular Dependency: The service has circular dependencies when it starts.' }
        19 { return 'Status Duplicate Name: A service is running under the same name.' }
        20 { return 'Status Invalid Name: The service name has invalid characters.' }
        21 { return 'Status Invalid Parameter: Invalid parameters have been passed to the service.' }
        22 { return 'Status Invalid Service Account: The account under which this service runs is either invalid or lacks the permissions to run the service.' }
        23 { return 'Status Service Exists: The service exists in the database of services available from the system.' }
        24 { return 'Service Already Paused: The service is currently paused in the system.' }
        default { return ('Unknown return value: {0}' -f $WmiReturnValue) }
    }
}

function getDomainName
{
    [OutputType([string])]
    [CmdletBinding()]
    param ()

    # Standalone role of a computer.
    # Ref: Win32_ComputerSystem class
    #      https://msdn.microsoft.com/en-us/library/aa394102(v=vs.85).aspx
    $standaloneRoles = @(
        0,  # Standalone Workstation
        2   # Standalone Server
    )

    # Get an instance of Win32_ComputerSystem class on this computer.
    $thisComputer = Get-WmiObject -Class 'Win32_ComputerSystem'

    # Verify this computer's role.
    # If this computer is standalone (workgroup), domain name is not available.
    if ($standaloneRoles -contains $thisComputer.DomainRole)
    {
        Write-Error -Message ('This computer ({0}) is not a member of a domain.' -f $env:COMPUTERNAME)
        return $null
    }

    # Return a domain name of this computer.
    return $thisComputer.Domain
}

function testCredential
{
    [OutputType([bool])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [pscredential] $Credential,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $AsDomain
    )

    # Load the assembly.
    $assemblyName = 'System.DirectoryServices.AccountManagement'
    $assembly = [System.Reflection.Assembly]::LoadWithPartialName($assemblyName)
    if ($assembly -eq $null)
    {
        Write-Error -Message ('Failed to load assembly "{0}".' -f $assemblyName)
        return $false
    }

    # Prepare the parameters for PrincipalContext's constructor.
    if ($AsDomain)
    {
        # For domain context parameters.
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $nameForContext = getDomainName
        if ($nameForContext -eq $null)
        {
            return $false
        }
    }
    else
    {
        # For machine (workgroup) context parameters.
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $nameForContext = $env:COMPUTERNAME
    }

    # Create an instance of PrincipalContext.
    $principalContext = New-Object -TypeName 'System.DirectoryServices.AccountManagement.PrincipalContext' -ArgumentList $contextType, $nameForContext

    # Validate a credential.
    Write-Verbose ('Validate {0}''s credential in the {1} context ({2}).' -f $Credential.UserName, $nameForContext, $contextType)
    return $principalContext.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)
}
