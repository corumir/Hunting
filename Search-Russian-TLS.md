# Hunt for install Russian TLS Certs

The invasion of Ukraine has resulted in significant activity and controls applied against Russia, such as: global sanctions, foreign business closures, and restrictions on exports, imports, and travel. In addition, there has been an increase in cyber activity, ranging from cyberattacks and BGP routing changes to website blocking and certificate cancelling or non-renewals. 

In an effort to reduce their reliance on Western/EU certificates, Russia is redirecting users who visit key websites to a TLS certificate hosted at gosuslugi[.]ru/tls in order to install a government root Certificate Authority certificate. Anyone who has navigated to this location has also likely downloaded and installed this TLS Certificate. 

## Issues
Russia providing its own certificates enables a new method of control authority allowing them to gain practical control of internet browsing for those domains. This enables Russia to modify HTTP responses in order to inject validation tokens and/or modify DNS responses to do the same. The obvious intent here is not only control but also the ability to read, decrypt, and interdict internet traffic. 

A MiTM attack, an attack occurring when an entity intercepts communications between two parties, is made possible for any communication using a Russian CA, as acting as the CA could allow Russia to modify traffic between the two parties and covertly eavesdrop on what would otherwise be an encrypted conversation. The ramifications of such activity could result in the harvesting of login credentials and personal information, cyberespionage, or sabotaging communications. 

## Powershell/MDE
**Note**: Change $CertPath variable to the proper location, e.g., "Cert:LocalMachine\my" 

>Get-ChildItem -Path $CertPath -Recurse | Where-Object {$_.Subject -Match "Russian"} | Select-Object FriendlyName, Thumbprint, Subject, NotBefore, NotAfter 

OR

>Get-ChildItem -Recurse Cert:\* | Where-Object {$_.Subject -like "*C=RU*" -or $_.Issuer -like "*C=RU*"} 
