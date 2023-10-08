# SNMP-Scan
Simple Powershell script which can be used to scan CIDR ranges and Active Directory for systems running SNMP. Default Community string used is "public" unless specified otherwise. Supports SNMPv1 and SNMPv2c.

# Load into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/SNMP-Scan/main/SNMP-Scan.ps1")
```

# Usage
At minimum -Targets is required, otherwise SNMP-Scan supports optional parameters as shown below
```
# Mandatory parameters
SNMP-Scan -Targets DC01.security.local  # Specifc name or IP
SNMP-Scan -Targets All                  # All enabled systems in Acitve Directory
SNMP-Scan -Targets Servers              # All servers in Active Directory
SNMP-Scan -Targets 10.10.10.0/24        # Scan an entire CIDR range

# Optional Parameters
-Threads 10                                  # Specify number of threads to run (Default 40)
-SuccessOnly                                 # Show only successful results
-Domain                                      # Run against an alternate domain (Default is $env:userdnsdomain)
-Port                                        # Specify alternate port (Default is UDP 161)
```

# Images

![image](https://github.com/The-Viper-One/SNMP-Scan/assets/68926315/2a8ca32a-974c-4a0c-8d41-2f450b1c9a27)
