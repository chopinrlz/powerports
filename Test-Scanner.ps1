$scanner = Get-Content "$PSScriptRoot\Scanner.cs" -Raw
Add-Type -TypeDefinition $scanner -Language CSharp
$x = New-Object -TypeName "PowerPorts.TcpScanner"
$x.Connect( "127.0.0.1", 5534 )
while( $true ) {
    if( $x.IsProcessing ) {
        Start-Sleep 1
    } else {
        break;
    }
}
($x.Results) | Format-Table