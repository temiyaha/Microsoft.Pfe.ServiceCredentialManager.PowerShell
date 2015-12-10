# Microsoft.Pfe.ServiceCredentialManager.PowerShell
Microsoft.Pfe.ServiceCredentialManager.PowerShell

# Releases

# Cmdlets in module
- Set-WindowsServiceCredential: Set a credential for a Windows service.
- Get-WindowsServiceCredential: Get a credential information of Windows service.

# Examples

## Example 1: Set a domain user credential for a Windows service

```powershell
PS > $serviceName = 'TheWindowsService'
PS > $computerName = 'DOMSERVER'
PS > $userName = 'ServiceUser@contoso.local'
PS >
PS > # Use the input password by the interactive user.
PS > $message = ('Please input the service credential for {0} service.' -f $serviceName)
PS > $cred = Get-Credential -Message $message -UserName $userName
PS >
PS > Set-WindowsServiceCredential -ServiceName $serviceName -Credential $cred -DomainCredential -TargetComputerName $computerName -Verbose
Verbose: Succeeded the verification of the user "ServiceUser@contoso.local" credentials.
Verbose: Found the "TheWindowsService" service on "DOMSERVER".
Verbose: The "TheWindowsService" service on "DOMSERVER" is already stopped.
Verbose: Set the new credentials "ServiceUser@contoso.local" to "TheWindowsService" service on the "DOMSERVER".
Verbose: Set the new credentials to the "TheWindowsService" service on "DOMSERVER" was completed.
True
```

## Example 2: Set a local user credential for a Windows service

```powershell
PS > $serviceName = 'TheWindowsService'
PS > $computerName = 'WG'
PS > $userName = 'WG\ServiceUser'
PS >
PS > # Use the input password by the interactive user.
PS > $message = ('Please input the service credential for {0} service.' -f $serviceName)
PS > $cred = Get-Credential -Message $message -UserName $userName
PS >
PS > Set-WindowsServiceCredential -ServiceName $serviceName -Credential $cred -TargetComputerName $computerName -Verbose
Verbose: Succeeded the verification of the user "WG\ServiceUser" credentials.
Verbose: Found the "TheWindowsService" service on "WG".
Verbose: The "TheWindowsService" service on "WG" is already stopped.
Verbose: Set the new credentials "WG\ServiceUser" to "TheWindowsService" service on the "WG".
Verbose: Set the new credentials to the "TheWindowsService" service on "WG" was completed.
True
```

## Example 3: Get the credential information of Windows service from multiple servers

```powershell
PS > $targetComputerNames = 'SERVER00','SERVER01'
PS > $serviceNames = 'TheWindowsService','LanmanServer','LanmanWorkstation','Spooler'
PS >
PS > foreach ($targetComputerName in $targetComputerNames)
>>   {
>>       foreach ($serviceName in $serviceNames)
>>       {
>>           Get-WindowsServiceCredential -ServiceName $serviceName -TargetComputerName $targetComputerName
>>       }
>>   }

ComputerName    ServiceName          UserName
------------    -----------          --------
SERVER00        TheWindowsService    contoso\administrator
SERVER00        LanmanServer         LocalSystem
SERVER00        LanmanWorkstation    NT AUTHORITY\NetworkService
SERVER00        Spooler              LocalSystem
SERVER01        TheWindowsService    Administrator@contoso.local
SERVER01        LanmanServer         LocalSystem
SERVER01        LanmanWorkstation    NT AUTHORITY\NetworkService
SERVER01        Spooler              LocalSystem
```

# Reporting bugs or suggesting features
