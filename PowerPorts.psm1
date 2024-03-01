<#
    PowerPorts module file (C) 2023-2024 by The Daltas Group LLC
    This software is licensed under the GNU General Public License v2.0
    This software is provided AS IS without warranty.
#>

Add-Type -TypeDefinition (Get-Content (Join-Path -Path $PSScriptRoot -ChildPath "Scanner.cs") -Raw) -Language CSharp
Add-Type -TypeDefinition (Get-Content (Join-Path -Path $PSScriptRoot -ChildPath "Interrogator.cs") -Raw) -Language CSharp

function Get-PwpPorts {
    <#
        .SYNOPSIS
        Gets a collection of TCP port numbers for many common services such as
        SMTP, HTTP, SMB, FTP, and DNS.
        .PARAMETER Names
        Specify this switch to get the names of the ports rather than the numbers.
        You can send the names or the numbers to the Test-PwPHostOrIp cmdlet.
    #>
    param( 
        [switch]
        $Names
    )
    if( $Names ) {
        foreach( $p in [System.Enum]::GetNames( [PowerPorts.TcpService] ) ) {
            Write-Output $p
        }
    } else {
        foreach( $p in [System.Enum]::GetValues( [PowerPorts.TcpService] ) ) {
            Write-Output $p
        }
    }
}

function Get-PwpSubnet {
    $myIp = ([System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName())).AddressList | Where-Object {
        $_.AddressFamily -eq "InterNetwork"
    }
    if( -not $myIp ) {
        throw "No local IPv4 address found"
    }
    if( $myIp.Length -gt 1 ) {
        $myIp = $myIp[0]
    }
    $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        ($_.OperationalStatus -eq "Up") -and ($_.NetworkInterfaceType -ne "Loopback")
    }
    if( -not $nics ) {
        throw "No network adapters are online"
    }
    $mask = $null
    foreach( $nic in $nics ) {
        $ipProps = $nic.GetIPProperties()
        foreach( $ua in $ipProps.UnicastAddresses ) {
            if( $ua.Address -eq $myIp ) {
                $mask = $ua.IPv4Mask
            }
        }
    }
    if( -not $mask ) {
        throw "No IPv4 subnet mask found"
    }
    $ipBytes = $myIp.GetAddressBytes()
    $snBytes = $mask.GetAddressBytes()

    $hostBits = [System.BitConverter]::ToUInt32( $snBytes, 0 )

    # 0 is 32 (LUT)
    # 1 is 31 (LUT)
    # 2 is 30
    # 4 is 29
    # 8 is 28
    # 16 is 27
    # 32 is 26
    # 64 is 25
    # 128 is 24
    # 2 ^ x = 31 - x

    # Create the classless subnet address from the IP address and the subnet mask
    $subnet = [System.Array]::CreateInstance( [byte], 4 )
    for( $i = 0; $i -lt $cidr.Length; $i++ ) {
        $subnet[$i] = $snBytes[$i] -band $ipBytes[$i]
    }
    $subnetAddress = New-Object -TypeName "System.Net.IPAddres" -ArgumentList @($subnet)
}

function Test-PwpHostOrIp {
    <#
        .SYNOPSIS
        Scans the target hostname or IPv4 address for open TCP ports.
        .PARAMETER Hostname
        Specify the target host using a hostname.
        .PARAMETER Ipv4Addr
        Specify the target host using an IPv4 address.
        .PARAMETER Ports
        Specify the target TCP ports to interrogate.
    #>
    param(
        [Parameter(ParameterSetName="Hostname",Mandatory,Position=0)]
        [string]
        $Hostname,
        [Parameter(ParameterSetName="IpAddr",Mandatory,Position=0)]
        [string]
        $Ipv4Addr,
        [Parameter(ParameterSetName="Hostname",Mandatory,Position=1,ValueFromPipeline)]
        [Parameter(ParameterSetName="IpAddr",Mandatory,Position=1,ValueFromPipeline)]
        [object[]]
        $Ports
    )
    begin {
        $scanner = New-Object -TypeName "PowerPorts.TcpScanner"
        if( $Hostname ) {
            $Ipv4Addr = (Resolve-DnsName -Name $Hostname | ? Type -eq A).IPAddress
        }
    } process {
        foreach( $port in $Ports ) {
            $portNumber = 0
            if( ($port.GetType().Name) -eq "String" ) {
                $portNumber = [System.Enum]::Parse( [PowerPorts.TcpService], $port )
            } else {
                $portNumber = $port
            }
            if( $portNumber -le 0 ) {
                Write-Warning "$port is not a valid TCP port"
            } else {
                $scanner.StartScan( $Ipv4Addr, $portNumber )
            }
        }
    } end {
        while( $true ) {
            if( $scanner.IsProcessing ) {
                Start-Sleep -Milliseconds 100
            } else {
                break;
            }
        }
        Write-Output ($scanner.Results)
    }    
}

function Read-PwpDataFromPort {
    <#
        .SYNOPSIS
        Opens a listening socket on any TCP port, awaits data then outputs it to the host or to a file.
        .PARAMETER PortNumber
        The TCP port number to listen on.
        .PARAMETER Buffer
        An optional buffer length indicator. By default, this is 1024 bytes.
        .PARAMETER Path
        If specified, the data received on the socket will be written to this file.
        .PARAMETER Encoding
        The text encoding to use when outputting the data to the host.
    #>
    param(
        [Parameter(Mandatory,Position = 0,ValueFromPipeline)]
        [ValidateRange(1,65535)]
        [int]$PortNumber,
        [Parameter(Position = 1)]
        [string]$Greeting,
        [ValidateRange(1024,1073741824)]
        [int]$Buffer = 1024,
        $Path,
        [ValidateSet("Ascii","Utf8","Unicode")]
        $Encoding = "Ascii"
    )
    $data = [System.Array]::CreateInstance( [byte], $Buffer )
    if( $data ) {
        $enc = switch( $Encoding ) {
            "Ascii" { [System.Text.Encoding]::ASCII }
            "Utf8" { [System.Text.Encoding]::UTF8 }
            "Unicode" { [System.Text.Encoding]::Unicode }
        }
        $server = Get-PwpSocketListener $PortNumber
        $server.Start()
        $stream = ($server.AcceptTcpClient()).GetStream()
        if( $Greeting ) {
            $bytes = $enc.GetBytes( $Greeting )
            $stream.Write( $bytes, 0, $bytes.Length )
        }
        $dataRead = $stream.Read( $data, 0, $Buffer )
        $stream.Close()
        $server.Stop()
        if( $Path ) {
            $fs = [System.IO.File]::OpenWrite( $Path )
            if( $fs ) {
                $fs.Write( $data, 0, $dataRead )
                $fs.Close()
            }
        } else {
            Write-Output ($enc.GetString( $data, 0, $dataRead ))
        }
    } else {
        Write-Warning "Failed to allocate read buffer"
    }
}

function Get-PwpSocketListener {
    param(
        [Parameter(Mandatory,Position = 0)]
        [int]$PortNumber
    )
    Write-Output (New-Object -TypeName "System.Net.Sockets.TcpListener" -ArgumentList (New-Object -TypeName "System.Net.IPEndPoint" -ArgumentList @( [IPAddress]::Any, $PortNumber )) )
}

function Get-PwpIpv4Address {
    <#
        .SYNOPSIS
        Resolves a hostname to an IPv4 address, if it has one.
    #>
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position = 0)]
        [string]
        $Hostname
    )
    Write-Output ((Resolve-DnsName -Name $Hostname | Where-Object { $_.Type -eq "A" }).IPAddress)
}

function Get-PwpGreeting {
    <#
        .SYNOPSIS
        Gets a string which contains a typical Greeting from a Client to a Server upon connection designed to be used with
        Get-PwpInterrogate to scan network devices for service discovery.
    #>
    param(
        [Parameter(Mandatory,Position = 0,ValueFromPipeline)]
        [ValidateSet("SMTP","ESMTP","HTTP")]
        [string]
        $Type
    )
    switch( $Type ) {
        "SMTP" {
            Write-Output "HELO"
        }
        "ESMTP" {
            Write-Output "EHLO"
        }
        "HTTP" {
            Write-Output (Get-Content "$PSScriptRoot\HTTP.Request.txt" -Raw)
        }
    }
}

function Get-PwpInterrogate {
    <#
        .SYNOPSIS
        Interrogates the target host and outputs the response to the pipeline.
        .PARAMETER Hostname
        Specify the target host using a hostname.
        .PARAMETER Ipv4Addr
        Specify the target host using an IPv4 address.
        .PARAMETER Port
        Specify the target TCP port to interrogate. Valid options are any number between 1 and 65535.
        .PARAMETER Timeout
        An optional timeout value in milliseconds, which defaults to 1 second.
        Can be set to any value between 100 and 30,000 ms.
        .PARAMETER Greeting
        An optional greeting to send to the target host upon connection.
        .PARAMETER PassThru
        An optional switch to output an object to the pipeline with the results.
    #>
    param(
        [Parameter(ParameterSetName="Hostname",Mandatory)]
        [string]
        $Hostname,
        [Parameter(ParameterSetName="IpAddr",Mandatory)]
        [string]
        $Ipv4Addr,
        [Parameter(ParameterSetName="Hostname",Mandatory,Position=1,ValueFromPipeline)]
        [Parameter(ParameterSetName="IpAddr",Mandatory,Position=1,ValueFromPipeline)]
        [ValidateRange(1,65535)]
        [int]
        $Port,
        [Parameter(ParameterSetName="Hostname",Position=2)]
        [Parameter(ParameterSetName="IpAddr",Position=2)]
        [ValidateRange(100,30000)]
        [int]
        $Timeout = 1000,
        [Parameter(ParameterSetName="Hostname",Position=3)]
        [Parameter(ParameterSetName="IpAddr",Position=3)]
        [string]
        $Greeting,
        [Parameter(ParameterSetName="Hostname")]
        [Parameter(ParameterSetName="IpAddr")]
        [switch]
        $PassThru
    )
    begin { }
    process {
        $intg = New-Object -TypeName "PowerPorts.TcpInterrogator"
        if( $EnforceReadTimeout ) {
            $intg.EnforceReadTimeout = $true
        }
        if( $Hostname ) {
            $Ipv4Addr = Get-PwpIpv4Address $Hostname
        }
        if( $Greeting ) {
            $intg.Greeting = $Greeting
        }
        $intg.Interrogate( $Ipv4Addr, $Port )
        $spin = 100
        while( $true ) {
            if( $intg.IsProcessing ) {
                Start-Sleep -Milliseconds $spin
                $wait -= $spin
            } else {
                break;
            }
        }
        if( $PassThru ) {
            $payload = [PSCustomObject]@{
                Hostname = $Hostname
                Ipv4Addr = $Ipv4Addr
                Port = $Port
                Greeting = $Greeting
                IsConnected = $intg.IsConnected
                Response = $intg.Response
                Timeout = $Timeout
            }
            Write-Output $payload
        } else {
            Write-Output ($intg.Response)
        }
    }
    end { }
}