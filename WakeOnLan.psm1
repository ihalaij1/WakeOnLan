<#

Invoke-WakeOnLan

Chris Warwick, @cjwarwickps, January 2012.  This version, December 2025.


Cmdlet to send a Wake-on-Lan packet to a specified target MAC addresses.


Wake on Lan (WOL) uses a “Magic Packet” that consists of six bytes of 0xFF (the physical layer broadcast address), followed
by 16 copies of the 6-byte (48-bit) target MAC address (see http://en.wikipedia.org/wiki/Wake-on-LAN).

This packet is sent via UDP to the LAN Broadcast addresses (255.255.255.255) on arbitrary Port 4000.

Construction of this packet in PowerShell is very straight-forward: (“$Packet = [Byte[]](,0xFF*6)+($Mac*16)”).

This script has a (hard-coded) table of saved MAC addresses to allow machine aliases to be specified as parameters to the
function (the real addresses have been obfuscated here) and uses a regex to validate MAC address strings.

It would be possible to use DNS and the ARP Cache to resolve MAC addresses, however, the ARP cache will only be populated with
a valid entry for any given target adapter for a relative short period of time after the last use of the address (10 minutes
or less depending on usage); ARP cannot be used to dynamically resolve the address of a suspended adapter.


#>


#Requires -Version 2



<#
.Synopsis
    This cmdlet sends Wake-on-Lan Magic Packets to the specified Mac addresses.
.Description
    Wake on Lan (WOL) uses a “Magic Packet” that consists of six bytes of 0xFF (the physical layer broadcast address), followed
    by 16 copies of the 6-byte (48-bit) target MAC address (see http://en.wikipedia.org/wiki/Wake-on-LAN).

    This packet is sent via UDP to the LAN Broadcast addresses (255.255.255.255) on arbitrary Port 4000.

    Construction of this packet in PowerShell is very straight-forward: (“$Packet = [Byte[]](,0xFF*6)+($Mac*16)”).

    This script has a (hard-coded) table of saved MAC addresses to allow machine aliases to be specified as parameters to the
    function (the real addresses have been obfuscated here) and uses a regex to validate MAC address strings.  The address
    aliases are contained in a hash table in the script - but they could very easily be obtained from an external source such as
    a text file or a CSV file (this is left as an exercise for the reader).

    It would be possible to use DNS and the ARP Cache to resolve MAC addresses, however, the ARP cache will only be populated with
    a valid entry for any given target adapter for a relative short period of time after the last use of the address (10 minutes
    or less depending on usage); ARP cannot be used to dynamically resolve the address of a suspended adapter.
.Example
    Invoke-WakeOnLan 00-1F-D0-98-CD-44 [-Verbose]
    Sends WOL packets to the specified address
.Example
    Invoke-WakeOnLan 00-1F-D0-98-CD-44, 00-1D-92-3B-C2-C8 [-Verbose]
    Sends WOL packets to the specified addresses
.Example
    Invoke-WakeOnLan Server3 [-Verbose]
    Sends WOL packets to the specified target using an alias.  The alias must currently be hard-coded in the script.
.Inputs
    An array of MAC addresses.  Each address must be specified as a sequence of 6 hex-coded bytes seperated by ':' or '-'
    The input can also contain aliases - these must currently be hard-coded in the script (see examples)
    MAC addresses can be piped to the cmdlet.
.Outputs
    Wake-on-Lan packets are sent to the specified addresses
.Parameter MacAddress
    An array of MAC addresses.  Each address must be specified as a sequence of 6 hex-coded bytes seperated by ':' or '-'
.Functionality
    Sends Wake-on-Lan Magic Packets to the specified Mac addresses
#>
Function Invoke-WakeOnLan {
	[CmdletBinding()]
	Param (
	    [Parameter(ValueFromPipeline)]
	    [String[]]$MacAddress
	)

    Begin {
        # The following table contains aliases for commonly used MAC addresses; modify as required.
        $StaticLookupTable=@{
            Hyperion  = '00-1F-D0-98-CD-44'
	        Nova      = '00-1D-92-3B-C2-C8'
	        Desktop   = '00-15-58-9B-6A-1B'
	        Laptop    = '00-17-08-42-D5-18'
	        AD2       = '00-1F-D0-98-CD-5C'
	        Server3   = '00-0E-2E-49-25-32'
            Media     = '1C-6F-65-D7-20-D7'
        }

        # Find first active IPv4 interface (non-loopback)
        # Pick interface in the 192.168.x.x range
        $nic = Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -like '192.168.*' } |
            Select-Object -First 1


        if (-not $nic) {
            throw "No active IPv4 network interface found."
        }

        # Compute simple /24 broadcast
        $octets = $nic.IPAddress.Split('.') | ForEach-Object {[int]$_}
        $broadcastIP = "$($octets[0]).$($octets[1]).$($octets[2]).255"
        $broadcast = [System.Net.IPAddress]::Parse($broadcastIP)

        # Prepare UDP client
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.EnableBroadcast = $true
        $Endpoint = New-Object System.Net.IPEndPoint($broadcast, 9)
    }

    Process {
        foreach ($MacString in $MacAddress) {
            # Replace alias with real MAC if exists
            if ($StaticLookupTable.ContainsKey($MacString)) {
                $MacString = $StaticLookupTable[$MacString]
            }

            # Validate MAC address format
            if ($MacString -notmatch '^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$') {
                Write-Warning "Invalid MAC address: $MacString"
                continue
            }

            # Convert MAC to byte array
            $Mac = $MacString -split '[:-]' | ForEach-Object { [byte]("0x$_") }

            # Build magic packet
            $Packet = [byte[]](,0xFF * 6) + ($Mac * 16)

            # Send packet
            [void]$UdpClient.Send($Packet, $Packet.Length, $Endpoint)
            Write-Verbose "Sent WOL to $MacString via broadcast $broadcast"
        }
    }

    End {
        $UdpClient.Close()
        $UdpClient.Dispose()
    }
}
