# Background

[CISA Alert AA22-074A](https://www.cisa.gov/uscert/ncas/alerts/aa22-074a)

## Core Exploit Hunted
The actors also modified a domain controller file, c:\windows\system32\drivers\etc\hosts, redirecting Duo MFA calls to localhost instead of the Duo server [T1556]

## Powershell/MDE
Select-String -Path $Env:SystemDrive'\Windows\System32\Drivers\etc\hosts' -Pattern 'duosecurity'
