# Suspicious Powershell

## MDE --> Powershell Downloads
```name: PowerShell downloads
description: |
  Finds PowerShell execution events that could involve a download.
requiredDataConnectors:
- connectorId: MicrosoftThreatProtection
  dataTypes:
  - DeviceProcessEvents
query: |
  DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName in~ ("powershell.exe", "powershell_ise.exe")
  | where ProcessCommandLine has "Net.WebClient"
     or ProcessCommandLine has "DownloadFile"
     or ProcessCommandLine has "Invoke-WebRequest"
     or ProcessCommandLine has "Invoke-Shellcode"
     or ProcessCommandLine has "http"
     or ProcessCommandLine has "IEX"
     or ProcessCommandLine has "Start-BitsTransfer"
     or ProcessCommandLine has "mpcmdrun.exe"
  | project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
  | top 100 by Timestamp
```
  
  
## MDE --> Powershell Interactions

```name: PowerShell interactions
description: |
  Finds PowerShell execution events drawn from Ukraine crisis malware reporting
requiredDataConnectors:
- connectorId: MicrosoftThreatProtection
  dataTypes:
  - DeviceProcessEvents
query: |  
  DeviceProcessEvents
|where FileName in~ ("powershell","powershell_ise.exe"
|where ProcessCommandLine has_any("-bxor","-exec bypass","comsvcs.dll")
|project Timestamp, DeviceId, ReportId, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## MDE --> PostGressSQL Abuse
```
name: PowerShell interactions
description: |
  Detection known examples of postgressql abuse for detected wipers 
requiredDataConnectors:
- connectorId: MicrosoftThreatProtection
  dataTypes:
  - DeviceProcessEvents
query: |  
  DeviceProcessEvents
|where ProcessCommandLine contains "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE"
```
