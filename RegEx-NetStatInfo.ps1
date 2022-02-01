Function Get-NetStat
{
<#
.SYNOPSIS
  Takes data from netstat.exe and writes to custom object
.DESCRIPTION
  Takes data from netstat.exe and writes to custom object.
  If running PowerShell v2 or on 2008/2008R2/7 use this.
  If running 2012+, use the built in commands: Get-NetTCPConnection/Get-NetUDPEndPoint
.NOTES
  Regular Expression CheatSheet:
  \s             - whitespace
  \S             - anything except whitespace
  +              - one or more match
  (?<groupName>) - Logical Named Groups
#>
[CmdletBinding()]
Param()
  [array]$netstat = NETSTAT.EXE -ano
  foreach($n in $netstat){
  $null = $n.TrimStart() -match `
    '(?<Protocol>\S+)\s+(?<LocalAddress>\S+)\s+(?<ForeignAddress>\S+)\s+(?<State>\S+)\s+(?<PID>\S+)'

  If($Matches -and $n -notmatch 'local|proto|address|foreign|active')
      {
      $results =  @{
          Protocol = $Matches.Protocol
          LocalAddress = $Matches.LocalAddress
          ForeignAddress = $Matches.ForeignAddress
          State = $Matches.State
          PID = $Matches.PID
          }
      New-Object -TypeName PSObject -Property $results
      $Matches = $null
      }
  }

}

Get-NetStat | Out-GridView