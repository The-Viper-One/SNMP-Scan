Function SNMP-Scan {
[CmdletBinding()]
Param(

    [Parameter(Mandatory=$False, Position=1, ValueFromPipeline=$true)]
    [String]$Targets = '',

    [Parameter(Mandatory=$False, Position=2, ValueFromPipeline=$true)]
    [String]$Domain = "$env:USERDNSDOMAIN",

    [Parameter(Mandatory=$False, Position=3, ValueFromPipeline=$true)]
    [String]$Threads = "40",

    [Parameter(Mandatory=$False, Position=4, ValueFromPipeline=$true)]
    [int]$Port = "",

    [Parameter(Mandatory=$False, Position=5, ValueFromPipeline=$true)]
    [Switch]$SuccessOnly,

    [Parameter(Mandatory=$False, Position=6, ValueFromPipeline=$true)]
    [String]$Community = "public"
)

$Password = $Community

$startTime = Get-Date
Set-Variable MaximumHistoryCount 32767

Write-Host
Write-Host

$Banner = @'
 _____ _   ____  ________       _____ _____  ___  _   _ 
/  ___| \ | |  \/  | ___ \     /  ___/  __ \/ _ \| \ | |
\ `--.|  \| | .  . | |_/ /_____\ `--.| /  \/ /_\ \  \| |
 `--. \ . ` | |\/| |  __/______|`--. \ |   |  _  | . ` |
/\__/ / |\  | |  | | |         /\__/ / \__/\ | | | |\  |
\____/\_| \_|_|  |_|_|         \____/ \____|_| |_|_| \_/                                                                                                                                                                                                                                         

'@

Write-Output "$Banner"
Write-Output "Github : https://github.com/the-viper-one"
Write-Host
Write-Host


function Get-IPRange {
    param (
        [string]$CIDR
    )
    
    $ErrorActionPreference = "Stop"
    try {
        # Extract the base IP and subnet mask from the CIDR notation
        $baseIP, $prefixLength = $CIDR -split "/"
        
        # Ensure the base IP and prefix length are valid
        if(-not ($baseIP -match "^(\d{1,3}\.){3}\d{1,3}$") -or -not ($prefixLength -match "^\d+$")) {
            throw "Invalid CIDR format. Ensure you use the format: xxx.xxx.xxx.xxx/yy"
        }

        # Calculate the number of IP addresses in the range
        $ipCount = [math]::Pow(2, (32 - [int]$prefixLength))
        
        # Convert the base IP to a decimal number
        $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipDecimal = [BitConverter]::ToUInt32($ipBytes, 0)
        
        # Generate all IP addresses within the range
        $ipAddresses = 0..($ipCount - 1) | ForEach-Object {
            $currentIPDecimal = $ipDecimal + $_
            $currentIPBytes = [BitConverter]::GetBytes($currentIPDecimal)
            [Array]::Reverse($currentIPBytes)
            "$($currentIPBytes[0]).$($currentIPBytes[1]).$($currentIPBytes[2]).$($currentIPBytes[3])"
        }
        
        return $ipAddresses
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}


if ($Targets -match "^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$") {
    if ($Matches[0] -like "*/*") {
        $Computers = Get-IPRange -CIDR $Targets
        $CIDRorIP = $True
    }
    else {
    $CIDRorIP = $True
        $Computers = $Targets
    }
}

else {
$CIDRorIP = $False
$directoryEntry = [ADSI]"LDAP://$domain"
$searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))

if ($Targets -eq "Workstations") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -notlike "*windows*server*" -and $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "Servers") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -like "*server*" -and $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") {

$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll()

}
elseif ($Targets -eq "All" -or $Targets -eq "Everything") {


$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }`

}


elseif ($Method -ne "Spray"){
if ($Targets -is [string]) {
    $ipAddress = [System.Net.IPAddress]::TryParse($Targets, [ref]$null)
    if ($ipAddress) {
        Write-Host "IP Addresses not yet supported" -ForegroundColor "Red"
        break
    }
    else {
        
        if ($Targets -notlike "*.*") {
            $Targets = $Targets + "." + $Domain
        }
        
        $computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0] -in $Targets }
            
            }
        }
    }
}

if ($CIDRorIP -eq $False){
$NameLength = ($computers | ForEach-Object { $_.Properties["dnshostname"][0].Length } | Measure-Object -Maximum).Maximum
$OSLength = ($computers | ForEach-Object { $_.Properties["operatingSystem"][0].Length } | Measure-Object -Maximum).Maximum
}


# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($ComputerName, $Password)

function Test-UdpPort {
    param(
        [string]$ComputerName,
        [int]$Port = 161
    )
    
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $encoding = [System.Text.Encoding]::ASCII
    $timeout = 50  # in milliseconds
    
    Try {
        $udpClient.Connect($ComputerName, $Port)
        $udpClient.Client.ReceiveTimeout = $timeout
        
        # Sending a message to probe the UDP port
        $bytes = $encoding.GetBytes("Test")
        $udpClient.Send($bytes, $bytes.Length) | Out-Null
        
        # Wait for a possible response or ICMP unreachable message
        $udpClient.Receive([ref]$null)
    }
    Catch {
        # Handling the exception based on timeout or other network issue
        if ($_.Exception.Message -match "No such host is known") {
            return "Host Unknown"
        }
        elseif ($_.Exception.Message -match "An existing connection was forcibly closed by the remote host") {
            return "Port Closed"
        }
        elseif ($_.Exception.Message -match "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond") {
            return "Port Open"
        }
        elseif ($_.Exception.GetType().Name -eq "SocketException") {
            # Treat any SocketException as a potential indicator that port might be open
            # Especially when ICMP messages are suppressed and we get a timeout (ErrorCode 10060)
            return "Port Open"
        }
        else {
            return "Error: $($_.Exception.Message)"
        }
    }
    Finally {
        $udpClient.Close()
    }
    
    return "Port is closed"
}

Start-Sleep -Milliseconds 50 ; Test-UdpPort -ComputerName $ComputerName

   
   
   
   
   
   
   function Get-SnmpValue {
    param (
        [string]$ComputerName,
        [string]$Password,
        [string]$Oid = '.1.3.6.1.2.1.1.5.0'
    )
    
    $SNMP = New-Object -ComObject olePrn.OleSNMP
    $Output = $null
    
    Try {
        $SNMP.open($ComputerName, $Password, 2, 500)
        $Output = $SNMP.get($Oid)
    }
    Catch {
        return "Unable to connect"
    }
    Finally {
        $SNMP.Close()
    }

    return $Output
}


return Get-SnmpValue -ComputerName $ComputerName -Password $Password

}




if ($CIDRorIP -eq $True){
function Get-FQDNDotNet {
    param ([string]$IPAddress)
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
        return $hostEntry.HostName
    }
    catch {}
}

function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength
    )

    # Resolve the FQDN
    $DnsName = Get-FQDNDotNet -IPAddress $ComputerName
    
    # Prefix
    Write-Host "SNMP " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-16}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    # Display ComputerName and OS
    Write-Host ("{0,20}" -f $DnsName) -NoNewline
    Write-Host "   " -NoNewline

    
    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}
}

if ($CIDRorIP -eq $False){
function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength
    )

    # Prefix
    Write-Host "SNMP " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
    # Display ComputerName and OS
    Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
    Write-Host "   " -NoNewline

    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}
}



# Create and invoke runspaces for each computer
foreach ($computer in $computers) {


    if ($CIDRorIP -eq $False){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    if ($CIDRorIP -eq $True){
    $ComputerName = $Computer
    }
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Password)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}



$FoundResults = $False

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)

            if ($result -eq "Port Closed"){continue}
            if ($result -eq "Host Unknown"){continue}

            if ($result -eq "Unable to connect") {Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Red -statusSymbol "[-] " -NameLength $NameLength -OSLength $OSLength -statusText "Access Denied" ; continue} 
                
            if ($result -ne "") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -NameLength $NameLength -OSLength $OSLength -statusText Success
                $FoundResults = $True
                
                # Dispose of all other runspaces for this computer
                $runspaces | Where-Object {
                    $_.ComputerName -eq $runspace.ComputerName -and -not $_.Completed
                } | ForEach-Object {
                    $_.Runspace.Dispose()
                    $_.Handle.AsyncWaitHandle.Close()
                    $_.Completed = $true
                }
                continue
            } 

            # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })


Write-Host
Write-Host


if ($FoundResults -eq $False){
Write-Host "- " -ForegroundColor "Red" -NoNewline
Write-Host "Unable to authenticate to any SNMP Hosts"
Write-Host
}

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()

Write-Host ""
$Time = (Get-Date).ToString("HH:mm:ss")
Write-Host "Script Completed : $Time"
$elapsedTime = (Get-Date) - $startTime

# Format the elapsed time
$elapsedHours = "{0:D2}" -f $elapsedTime.Hours
$elapsedMinutes = "{0:D2}" -f $elapsedTime.Minutes
$elapsedSeconds = "{0:D2}" -f $elapsedTime.Seconds
$elapsedMilliseconds = "{0:D4}" -f $elapsedTime.Milliseconds

# Display the formatted elapsed time
$elapsedTimeFormatted = "$elapsedHours h:$elapsedMinutes m:$elapsedSeconds s:$elapsedMilliseconds mi"
Write-Host "Elapsed Time     : $elapsedTime"


}
