$VerbosePreference = "Continue"
. "C:\cloud-automation\secrets.ps1"

Function Get-TargetResource {
  param (
    [string]$Name,
    [Ensure]$Ensure
  )
  @{
  Name = $Name
  Ensure = $Ensure
  }
}

Function Test-TargetResource {
  param (
    [string]$Name,
    [Ensure]$Ensure
  )
  return $false
}

Function Set-TargetResource {
  param (
    [string]$Name,
    [Ensure]$Ensure
  )
}
