param(
	[string]
	$Hostname = "localhost"
)

Import-Module .\PowerPorts.psd1

"--- TEST 1 --- Hostname"
Test-PwpHostOrIp -Hostname $Hostname -Ports (Get-PwPPorts) | Format-Table

"--- TEST 2 --- IPv4 Address"
Test-PwpHostOrIp -Ipv4Addr 127.0.0.1 -Ports (Get-PwPPorts) | Format-Table

"--- TEST 3 --- Pipeline"
Get-PwPPorts | Test-PwpHostOrIp -Hostname $Hostname | Format-Table

"--- TEST 4 --- Export JSON"
$json = Join-Path -Path $PSScriptRoot -ChildPath "Test-PwpHostOrIp.Test4.Results.json"
if( Test-Path $json ) { Remove-Item -Path $json -Force }
Get-PwPPorts | Test-PwpHostOrIp -Hostname $Hostname | ConvertTo-Json | Out-File $json

"--- TEST 5 --- Export CSV"
$csv = Join-Path -Path $PSScriptRoot -ChildPath "Test-PwpHostOrIp.Test5.Results.csv"
if( Test-Path $csv ) { Remove-Item -Path $csv -Force }
Get-PwPPorts | Test-PwpHostOrIp -Hostname $Hostname | Export-Csv $csv