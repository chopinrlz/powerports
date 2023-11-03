<#
    PowerPorts module file (C) 2023 by The Daltas Group LLC
    This software is licensed under the GNU General Public License v2.0
    This software is provided AS IS without warranty.
#>

function Get-PowerPortsSubnet {
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