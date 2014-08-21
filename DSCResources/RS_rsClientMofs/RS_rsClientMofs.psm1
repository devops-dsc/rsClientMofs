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
  $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
  foreach($environment in $environments) {
    if(!(Test-Path -Path $($environment, ".ps1" -join ''))) {
      return $false
    }
    if(!(Test-Path -Path $($environment, ".hash" -join ''))) {
      return $false
    }
    if( ((Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).Hash) -ne (Get-Content -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\') )) {
      return $false
    }
  }
  else {
    return $true
  }
}
Function Set-TargetResource {
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
  $environments = (((Get-Content -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')) -match "EnvironmentName") | % {($_.split("=")[1] -replace '"', "").trim()})
  foreach($environment in $environments) {
    if(Test-Path -Path $($environment, ".ps1" -join '')) {
        if(((Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\')).Hash) -ne (Get-Content -Path $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\'))) {
          $environmentServers = $servers.Where($_.environmentName -eq $environment)
          foreach($environmentServer in $environmentServers) {
            powershell.exe $($d.wD, $d.mR, $($environment, ".ps1" -join '') -join '\') -Node $($environmentServer.servername), -ObjectGuid $($environmentServer.guid)
          }
        }
        Set-Content -Path $($d.wD, $d.mR, $($environment, ".hash" -join ''), -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, $($environment, ".ps1" -join ''), -join '\')).hash
    }
  }
}
