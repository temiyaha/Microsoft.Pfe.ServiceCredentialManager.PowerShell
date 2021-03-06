##
## Require run as administrator
##

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

Import-Module -Name "$PSScriptRoot\Microsoft.Pfe.ServiceCredentialManager.PowerShell\Microsoft.Pfe.ServiceCredentialManager.PowerShell.psd1" -Force

$serviceName = 'TheWindowsService'
$computerName = 'WG'
$userName = 'WG\ServiceUser'

# Use the input password by the interactive user.
$message = ('Please input the service credential for {0} service.' -f $serviceName)
$cred = Get-Credential -Message $message -UserName $userName

# You can use a plain text password if you wish.
#$plainTextPassword = 'SuperSecretPassword'
#$securePassword = ConvertTo-SecureString -String $plainTextPassword -AsPlainText -Force
#$cred = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList $userName, $securePassword

Set-WindowsServiceCredential -ServiceName $serviceName -Credential $cred -TargetComputerName $computerName -Verbose
