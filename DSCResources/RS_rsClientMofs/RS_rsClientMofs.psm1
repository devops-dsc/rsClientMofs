Function Get-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure,
      [bool]$Logging
   )
   @{
  Name = $Name
  Ensure = $Ensure
  }
}
Function Test-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure,
      [bool]$Logging
   )
   $logSource = $PSCmdlet.MyInvocation.MyCommand.ModuleName
   New-EventLog -LogName "DevOps" -Source $logSource -ErrorAction SilentlyContinue
   . "C:\cloud-automation\secrets.ps1"
   try{
      $catalog = (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
   }
   catch {
      if($Logging) {
         Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retreive service catalog `n $($_.Execption.Message)"
      }
   }
   $AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
   $tokenuri = ($monitoruri, "agent_tokens" -join '/')
   $environmentGuids = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "environmentGuid") | % {($_.split("=")[1] -replace '"', "").trim()})
   $entityuri = ($monitoruri, "entities" -join '/')
   $servers = @()
   try {
      $entities = (Invoke-RestMethod -Uri $entityuri -Method GET -Headers $authToken).values
   }
   catch {
      Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retreive Monitoring Entities `n $($_.Exception.Message)"
   }
   foreach($environmentGuid in $environmentGuids) {
      try {
         $servers += (((Invoke-RestMethod -Uri $("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid -join '/') -Method GET -Headers $AuthToken -ContentType application/json).servers).servers)
      }
      catch {
         if($Logging) {
            Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retrieve server object from Servermill `n $($_.Exception.Message)"
         }
      }
   }
   foreach($server in $servers) {
      if($($server.serverName)) {
         if(($entities | ? label -eq $($server.serverName).agent_id) -ne $($server.guid)) {
            if(($entities | ? label -eq $($server.serverName)) -eq $null) {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Warning -EventId 1000 -Message "No Monitor Entity found for this server `n $($_.Exception.Message)"
            }
            return $false 
         }
      }
   }
   $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
   $currentConfigs = ((Get-Item -Path "C:\Program Files\WindowsPowerShell\DscService\Configuration\*").BaseName -notmatch "mof")
   foreach($currentConfig in $currentConfigs) {  
      if($servers.guid -notcontains $currentConfig) {
         try {
            Remove-Item -Path $(($("C:\Program Files\WindowsPowerShell\DscService\Configuration", $currentConfig) -join '\'), "*" -join '')
         }
         catch {
            if($Logging) {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to remove file `n $($_.Exception.Message)"
            }
         }
      }
   }
   foreach($environment in $environments) {
      if(!(Test-Path -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\'))) {
         return $false
      }
      if(!(Test-Path -Path $($d.wD), $($environment, ".hash" -join '')) -join '\') {
         return $false
      }
      if( ((Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).Hash) -ne (Get-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\') )) {
         return $false
      }
   }
   foreach($server in $servers) {
      if($($server.serverName)) {
         if(!(Test-Path -Path $("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($server.guid, ".mof" -join '') -join '\'))) {
            return $false
         }
         if(!(Test-Path -Path $("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($server.guid, ".mof.checksum" -join '') -join '\'))) {
            return $false
         }
      }
   }
   return $true
}
Function Set-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure,
      [bool]$Logging
   )
   . "C:\cloud-automation\secrets.ps1"
   $logSource = $PSCmdlet.MyInvocation.MyCommand.ModuleName
   try {
      $catalog = (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
   }
   catch {
      if($Logging) {
         Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retreive service catalog `n $($_.Execption.Message)"
      }
   }
   $AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
   $tokenuri = ($monitoruri, "agent_tokens" -join '/')
   $environmentGuids = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "environmentGuid") | % {($_.split("=")[1] -replace '"', "").trim()})
   $entityuri = ($monitoruri, "entities" -join '/')
   try {
      $entities = (Invoke-RestMethod -Uri $entityuri -Method GET -Headers $authToken).values
   }
   catch {
      Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retreive Monitoring Entities `n $($_.Exception.Message)"
   }
   $servers = @()
   foreach($environmentGuid in $environmentGuids) {
      try {
         $servers += (((Invoke-RestMethod -Uri $("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid -join '/') -Method GET -Headers $AuthToken -ContentType application/json).servers).servers)
      }
      catch {
         if($Logging) {
            Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retrieve server object from Servermill `n $($_.Exception.Message)"
         }
      }
   }
   try {
      $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
   }
   catch {
      if($Logging) {
         Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retrieve monitoring tokens `n $($_.Exception.Message)"
      }
   }
   foreach($server in $servers) {
      if($server.serverName) {
         if($(($agent_tokens | ? {$_.label -eq $($server.guid)}).id).count -gt 1) {
            $tokens = $($agent_tokens | ? {$_.label -eq $($server.guid)}).id
            foreach($token in $tokens) {
               $deleteTokenUri = $($tokenuri, $token -join '/')
               try {
                  Invoke-RestMethod -Uri $deleteTokenUri -Method DELETE -Headers $AuthToken  -ContentType application/json
               }
               catch {
                  if($Logging) {
                     Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to delete token `n $($_.Exception.Message)"
                  }
               }
            }
         }
         try {
            $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
         }
         catch {
            if($Logging) {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retrieve monitoring tokens `n $($_.Exception.Message)"
            }
         }
         $body = @{'label' = $($server.guid);} | ConvertTo-Json
         if($($agent_tokens | ? {$_.label -eq $($server.guid)}).id -eq $null) { 
            try {
               Invoke-RestMethod -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json
            }
            catch {
               if($Logging) {
                  Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to create token `n $($_.Exception.Message)"
               }
            }
         }
      }
   }
   try {
      $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
   }
   catch {
      if($Logging) {
         Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to retrieve monitoring tokens `n $($_.Exception.Message)"
      }
   }
   $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
   foreach($environment in $environments) {
      if(Test-Path -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')) {
         if(Test-Path -Path $($d.wD, $($environment, ".hash" -join '') -join '\')) {
            if(((Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).Hash) -ne (Get-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\'))) {
               $environmentServers = $servers | ? {$_.environmentName -eq $environment}
               foreach($environmentServer in $environmentServers) {
                  try {
                     Remove-Item -Path $(("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($environmentServer.guid, "*" -join '') -join '\')) -Force
                  }
                  catch {
                     if($Logging) {
                        Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to remove file `n $($_.Exception.Message)"
                     }
                  }
                  try {
                     if(($($agent_tokens | ? {$_.label -eq $($environmentServer.guid)}).id) -eq $null) {
                        $body = @{'label' = $($environmentServer.guid);} | ConvertTo-Json
                        $agentToken = ((Invoke-WebRequest -UseBasicParsing -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json).Headers).'X-Object-ID'
                     }
                     else {
                        $agentToken = $($agent_tokens | ? {$_.label -eq $($environmentServer.guid)}).id
                     }
                     powershell.exe $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\') -Node $($environmentServer.servername), -ObjectGuid $($environmentServer.guid), -MonitoringID $($environmentServer.guid), -MonitoringToken $agentToken
                  }
                  catch {
                     if($Logging) {
                        Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to create configuration Mof `n $($_.Exception.Message)"
                     }
                  }
               }
               Set-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).hash
            }
         }
      }
      if(!(Test-Path -Path $($d.wD, $($environment, ".hash" -join '') -join '\'))) {
         $environmentServers = $servers | ? {$_.environmentName -eq $environment}
         foreach($environmentServer in $environmentServers) {
            try {
               Remove-Item -Path $(("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($environmentServer.guid, "*" -join '') -join '\')) -Force
            }
            catch {
               if($Logging) {
                  Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to remove file `n $($_.Exception.Message)"
               }
            }
            try {
               if(($($agent_tokens | ? {$_.label -eq $($environmentServer.guid)}).id) -eq $null) {
                  $body = @{'label' = $($environmentServer.guid);} | ConvertTo-Json
                  $agentToken = ((Invoke-WebRequest -UseBasicParsing -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json).Headers).'X-Object-ID'
               }
               else {
                  $agentToken = $($agent_tokens | ? {$_.label -eq $($environmentServer.guid)}).id
               }
               powershell.exe $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\') -Node $($environmentServer.servername) -ObjectGuid $($environmentServer.guid) -MonitoringID $($environmentServer.guid) -MonitoringToken $agentToken
            }
            catch {
               if($Logging) {
                  Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to create configuration Mof `n $($_.Exception.Message)"
               }
            }
         }
         Set-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).hash
      }
   }
   $missingConfigs = @()
   foreach($server in $servers) {
      if($($server.serverName)) {
         if(!(Test-Path -Path $("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($server.guid, ".mof" -join '') -join '\'))) {
            $missingConfigs += $($server.guid)
         }
         if(!(Test-Path -Path $("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($server.guid, ".mof.checksum" -join '') -join '\'))) {
            $missingConfigs += $($server.guid)
         }
         if((($entities | ? label -eq $($server.serverName).agent_id) -ne $null) -and (($entities | ? label -eq $($server.serverName).agent_id) -ne $server.guid)) {
            try {
               $entityID = ($entities | ? label -eq $server.serverName).id
               $entityUri = $($entityuri, $entityID -join '/')
               $entityBody = @{"agent_id" = $server.guid} | ConvertTo-Json
               Invoke-RestMethod -Uri $entityuri -Method Put -Headers $AuthToken -Body $entityBody -ContentType application/json
            }
            catch {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to update Entity agent_id `n $($_.Exception.Message)"
            }
         }
      }  
   }
   $missingConfigs = $missingConfigs | sort -Unique
   if($missingConfigs) {
      foreach($missingConfig in $missingConfigs) {
         $missingEnvironment = ($servers | ? {$_.guid -eq $missingConfig}).environmentName
         try {
            Remove-Item $("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($missingConfig, "*" -join '') -join '\') -Force
         }
         catch {
            if($Logging) {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to remove file `n $($_.Exception.Message)"
            }
         }
         try {
            if(($($agent_tokens | ? {$_.label -eq $($missingConfig.guid)}).id) -eq $null) {
               $body = @{'label' = $($missingConfig.guid);} | ConvertTo-Json
               $agentToken = ((Invoke-WebRequest -UseBasicParsing -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json).Headers).'X-Object-ID'
            }
            else {
               $agentToken = $($agent_tokens | ? {$_.label -eq $($missingConfig.guid)}).id
            }
            powershell.exe $($d.wD, $d.mR, $(($servers | ? {$_.guid -eq $missingConfig}).environmentName, ".ps1" -join '') -join '\') -Node $(($servers | ? {$_.guid -eq $missingConfig}).serverName) -ObjectGuid $(($servers | ? {$_.guid -eq $missingConfig}).guid) -MonitoringID $(($servers | ? {$_.guid -eq $missingConfig}).guid) -MonitoringToken $agentToken
         }
         catch {
            if($Logging) {
               Write-EventLog -LogName DevOps -Source $logSource -EntryType Error -EventId 1002 -Message "Failed to create configuration Mof `n $($_.Exception.Message)"
            }
         }
      }
   }
}
Export-ModuleMember -Function *-TargetResource