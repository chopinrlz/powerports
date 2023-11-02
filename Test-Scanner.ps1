Write-Host "Creating an array of ports to test"
$ports = 21,22,23,80,443,445,1433,8080,15430
Write-Host "Importing the port scanner source code"
$scanner = Get-Content "$PSScriptRoot\Scanner.cs" -Raw
Write-Host "Compiling the port scanner"
Add-Type -TypeDefinition $scanner -Language CSharp
Write-Host "Creating the port scanner object"
$x = New-Object -TypeName "PowerPorts.TcpScanner"
Write-Host "Initiating a scan of all ports"
$ports | % { $x.StartScan( "127.0.0.1", $_ ) }
Write-Host "Waiting for all connection attempts to complete"
while( $true ) {
    if( $x.IsProcessing ) {
        Start-Sleep 2
    } else {
        break;
    }
}
Write-Host "Reporting connection results"
($x.Results) | Format-Table