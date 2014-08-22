Function Get-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure
   )
   @{
  Name = $Name
  Ensure = $Ensure
  }
}
Function Test-TargetResource {
   param (
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure
   )
   . "C:\cloud-automation\secrets.ps1"
   $catalog = (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
   $AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $environmentGuids = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "environmentGuid") | % {($_.split("=")[1] -replace '"', "").trim()})
   $servers = @()
   foreach($environmentGuid in $environmentGuids) {
      $servers += (((Invoke-RestMethod -Uri $("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid -join '/') -Method GET -Headers $AuthToken -ContentType application/json).servers).servers)
   }
   #((Get-Item -Path "C:\Program Files\WindowsPowerShell\DscService\Configuration\*").BaseName -notmatch "mof") -notmatch $servers.guid | % ($_) {Remove-Item -Path $(((("C:\Program Files\WindowsPowerShell\DscService\Configuration", $_) -join '\')), "*" -join '') }
   $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
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
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Ensure
   )
   . "C:\cloud-automation\secrets.ps1"
   $catalog = (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
   $AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
   $tokenuri = ($monitoruri, "agent_tokens" -join '/')
   $environmentGuids = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "environmentGuid") | % {($_.split("=")[1] -replace '"', "").trim()})
   $servers = @()
   foreach($environmentGuid in $environmentGuids) {
      $servers += (((Invoke-RestMethod -Uri $("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid -join '/') -Method GET -Headers $AuthToken -ContentType application/json).servers).servers)
   }
   $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
   foreach($server in $servers) {
      if($server.serverName) {
         if($(($agent_tokens | ? {$_.label -eq $($server.guid)}).id).count -gt 1) {
            $tokens = $($agent_tokens | ? {$_.label -eq $($server.guid)}).id
            foreach($token in $tokens) {
               $deleteTokenUri = $($tokenuri, $token -join '/')
               Invoke-RestMethod -Uri $deleteTokenUri -Method DELETE -Headers $AuthToken  -ContentType application/json
            }
         }
         $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
         $body = @{'label' = $($server.guid);} | ConvertTo-Json
         if($($agent_tokens | ? {$_.label -eq $($server.guid)}).id -eq $null) { 
            Invoke-RestMethod -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json
         }
      }
   }
   $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
   $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
   foreach($environment in $environments) {
      if(Test-Path -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')) {
         if(((Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).Hash) -ne (Get-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\'))) {
            $environmentServers = $servers | ? {$_.environmentName -eq $environment}
            foreach($environmentServer in $environmentServers) {
               Remove-Item -Path $(("C:\Program Files\WindowsPowerShell\DscService\Configuration", $($environmentServer.guid, "*" -join '') -join '\')) -Force
               powershell.exe $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\') -Node $($environmentServer.servername), -ObjectGuid $($environmentServer.guid), -MonitoringID $($environmentServer.guid), -MonitoringToken $($agent_tokens | ? {$_.label -eq $($environmentServer.guid)}).id
            }
            Set-Content -Path $($d.wD, $($environment, ".hash" -join '') -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).hash
         }
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
      }  
   }
   
}
