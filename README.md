# powerports
Multi-threaded TCP/IP network port scanner and network data debugger for PowerShell.
# Installation
1. Clone this repo
2. Install all files to a module folder in your `PSModulePath`
3. Open PowerShell
# Usage
## Port Scanning
Use the `Test-PwpHostOrIp` cmdlet to scan hosts for open TCP ports.
## Debugging Network Data
Use the `Read-PwpDataFromPort` cmdlet to open a TCP socket and wait for incoming data.
The data can be written to the host or saved to a file for inspection.