<#
    PowerPorts module file (C) 2023-2024 by The Daltas Group LLC
    This software is licensed under the GNU General Public License v2.0
    This software is provided AS IS without warranty.
#>

$scanner = Get-Content "$PSScriptRoot\Scanner.cs" -Raw
Add-Type -TypeDefinition $scanner -Language CSharp

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
            $scanner.StartScan( $Ipv4Addr, $port )
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