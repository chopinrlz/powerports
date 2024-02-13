<#
    PowerPorts module file (C) 2023-2024 by The Daltas Group LLC
    This software is licensed under the GNU General Public License v2.0
    This software is provided AS IS without warranty.
#>

$scanner = Get-Content "$PSScriptRoot\Scanner.cs" -Raw
Add-Type -TypeDefinition $scanner -Language CSharp

function Get-PwpPorts {
    [System.Enum]::GetValues( [PowerPorts.TcpService] ) | % {
        [int]$x = $_
        Write-Output "$_ = $x"
    }
}

function Get-PwpSubnet {
    param(
        [string]
        $Cidr
    )
    $parts = $Cidr -split '\.'
    $end = $parts[3] -split '/'
    $a = $parts[0]
    $b = $parts[1]
    $c = $parts[2]
    $d = $end[0]
    $s = $end[1]
    "$a.$b.$c.$d/$s"
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
                Start-Sleep 1
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
        [ValidateRange(1024,1073741824)]
        [int]$Buffer = 1024,
        $Path,
        [ValidateSet("Ascii","Utf8","Unicode")]
        $Encoding = "Ascii"
    )
    $data = [System.Array]::CreateInstance( [byte], $Buffer )
    if( $data ) {
        $server = Get-PwpSocketListener $PortNumber
        $server.Start()
        $stream = ($server.AcceptTcpClient()).GetStream()
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
            $enc = switch( $Encoding ) {
                "Ascii" { [System.Text.Encoding]::ASCII }
                "Utf8" { [System.Text.Encoding]::UTF8 }
                "Unicode" { [System.Text.Encoding]::Unicode }
            }
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