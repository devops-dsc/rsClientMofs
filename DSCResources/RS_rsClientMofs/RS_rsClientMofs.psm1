$VerbosePreference = "Continue"
. "C:\cloud-automation\secrets.ps1"

Function Get-ServiceCatalog {
   return (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
}

Function Get-DevicesInPreferences {
   param (
      [string]$environmentGuid
   )
   $uri = "https://prefs.api.rackspacecloud.com/v1/WinDevOps"
   try {
      $testPrefs = (Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ContentType applicaton/json)
   }
   catch {
      if($testPrefs -eq $null) {
         $uri = "https://prefs.api.rackspacecloud.com/v1/WinDevOps"
         (Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Post -ContentType applicaton/json)
      }
   }
   $uri = ("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid, "servers" -join '/')
   try {
      write-verbose "retrieving list of servers in ServerMill Preferences"
      $returnValue = ((Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ContentType applicaton/json).servers)
      foreach($value in $returnValue) {
         write-verbose "Devices Get-DevicesInPreferences $value.serverName"
      }
      return $returnValue
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve devices from ServerMill preferences `n $($_.Exception.Message)"
   }
}

Function Get-TargetResource {
   param (
      [string]$Name,
      [string]$Ensure
   )
   @ {
      Name = $Name
      Ensure = $Ensure
   }
   
   
}

Function Test-TargetResource {
   param (
      [string]$Name,
      [string]$Ensure
   )
   return $false
   
}

Function Set-TargetResource {
   
   
}