param(
    [string]
    $WebServer = "webserver"
)

Import-Module .\PowerPorts.psd1

"--- TEST 1 --- HTTP Greeting"
Get-PwpInterrogate -Hostname $WebServer -Port 80 -Greeting (Get-PwpGreeting HTTP)

"--- TEST 2 --- HTTP Greeting --- PassThru"
Get-PwpInterrogate -Hostname $WebServer -Port 80 -Greeting (Get-PwpGreeting HTTP) -PassThru

"--- TEST 3 --- HTTP Greeting Pipeline"
80 | Get-PwpInterrogate -Hostname $WebServer -Greeting (Get-PwpGreeting HTTP)

"--- TEST 4 --- HTTP Greeting Pipeline - PassThru"
80 | Get-PwpInterrogate -Hostname $WebServer -Greeting (Get-PwpGreeting HTTP) -PassThru

"--- TEST 5 --- HTTP Greeting Positional"
Get-PwpInterrogate -Hostname $WebServer 80 100 (Get-PwpGreeting HTTP)

"--- TEST 6 --- HTTP Greeting Positional - PassThru"
Get-PwpInterrogate -Hostname $WebServer 80 100 (Get-PwpGreeting HTTP) -PassThru

"--- TEST 7 --- HTTP Greeting - All Named Params"
Get-PwpInterrogate -Hostname $WebServer -Port 80 -Timeout 100 -Greeting (Get-PwpGreeting HTTP) -PassThru

"--- TEST 8 --- No Carrier Test"
40000..40005 | Get-PwpInterrogate -Hostname $WebServer -Timeout 100 -PassThru | Format-Table

"--- TEST 9 --- Export CSV"
$outputFile = Join-Path -Path $PSScriptRoot -ChildPath "Test9.Results.csv"
if( Test-Path $outputFile ) { Remove-Item -Path $outputFile -Force }
40000..40005 | Get-PwpInterrogate -Hostname $WebServer -Timeout 100 -PassThru | Export-Csv $outputFile