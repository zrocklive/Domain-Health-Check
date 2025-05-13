# DomainHealthChecker.ps1
# Requires Active Directory Module and Administrator privileges

param(
    [switch]$IncludeWorkstations,
    [int]$PortCheck = 5985,
    [int]$TimeoutSeconds = 30
)

$reportPath = "$PSScriptRoot\DomainHealthReport_$(Get-Date -Format 'yyyyMMddHHmm').html"
$computers = Get-ADComputer -Filter * -Properties OperatingSystem, IPv4Address, LastLogonDate | 
    Where-Object { ($_.OperatingSystem -like "*Server*") -or $IncludeWorkstations }

$style = @"
<style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background-color: #f8f9fa; font-weight: 600; }
    .pass { background-color: #d4edda; color: #155724; }
    .warn { background-color: #fff3cd; color: #856404; }
    .fail { background-color: #f8d7da; color: #721c24; }
    .info { background-color: #d1ecf1; color: #0c5460; }
</style>
"@

$report = foreach ($computer in $computers) {
    $system = [PSCustomObject]@{
        ComputerName      = $computer.Name
        IPAddress         = $computer.IPv4Address
        Status            = "Offline"
        ConnectivityType  = "N/A"
        OSDriveFree       = "N/A"
        NTPStatus         = "N/A"
        NTPOffset         = "N/A"
        KerberosTickets   = "N/A"
        LastBootTime      = "N/A"
        PSRemoting        = "Disabled"
        LastLogon         = $computer.LastLogonDate
    }

    # Enhanced connectivity check
    $icmpStatus = $null
    $tcpStatus = $null
    
    try {
        # ICMP check with error handling
        $icmpStatus = Test-Connection -ComputerName $system.ComputerName -Count 1 -Quiet -ErrorAction Stop
    }
    catch {
        $icmpStatus = $false
    }

    if (-not $icmpStatus) {
        # TCP port check as fallback
        $tcpTest = Test-NetConnection -ComputerName $system.ComputerName -Port $PortCheck -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $tcpStatus = $tcpTest.TcpTestSucceeded
    }

    if ($icmpStatus -or $tcpStatus) {
        $system.Status = "Online"
        $system.ConnectivityType = if ($icmpStatus) { "ICMP" } else { "TCP/$PortCheck" }

        $session = $null
        try {
            # Remote system checks
            $session = New-PSSession -ComputerName $system.ComputerName -ErrorAction Stop -SessionOption (New-PSSessionOption -IdleTimeout ($TimeoutSeconds * 1000))
            $system.PSRemoting = "Enabled"

            # Drive space check
            $osDrive = Invoke-Command -Session $session -ScriptBlock {
                Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
            } -ErrorAction Stop
            
            if ($osDrive) {
                $system.OSDriveFree = "{0:N1}% ({1:N1}GB free)" -f 
                    ($osDrive.FreeSpace / $osDrive.Size * 100),
                    ($osDrive.FreeSpace / 1GB)
            }

            # NTP check
            $ntpStatus = Invoke-Command -Session $session -ScriptBlock {
                $service = Get-Service W32Time -ErrorAction SilentlyContinue
                $config = w32tm /query /status
                return [PSCustomObject]@{
                    ServiceStatus = $service.Status
                    NTPOffset     = ($config -match '^Phase Offset:' -split ':\s+')[1]
                    Source        = ($config -match '^Source:' -split ':\s+')[1]
                }
            } -ErrorAction SilentlyContinue
            
            if ($ntpStatus) {
                $system.NTPStatus = $ntpStatus.ServiceStatus
                $system.NTPOffset = $ntpStatus.NTPOffset
            }

            # Kerberos check
            $kerberos = Invoke-Command -Session $session -ScriptBlock {
                Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ID = 16,17,18
                } -MaxEvents 1 -ErrorAction SilentlyContinue
            }
            
            $system.KerberosTickets = if ($kerberos) { "Issues detected" } else { "Normal" }

            # Uptime check
            $lastBoot = Invoke-Command -Session $session -ScriptBlock {
                Get-CimInstance -ClassName Win32_OperatingSystem | 
                    Select-Object -ExpandProperty LastBootUpTime
            }
            $system.LastBootTime = $lastBoot.ToString()
        }
        catch {
            $system.PSRemoting = "Access Denied"
            Write-Warning "Error connecting to $($system.ComputerName): $_"
        }
        finally {
            if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        }
    }

    # Output the system object
    $system
}

# Generate HTML Report with conditional formatting
$htmlReport = $report | ConvertTo-Html -Head $style -PreContent @"
<h1>Domain Health Report</h1>
<h3>Generated: $(Get-Date)</h3>
<h4>Scanned Systems: $($report.Count)</h4>
"@ | ForEach-Object {
    $_ -replace '<td>Online</td>','<td class="pass">Online</td>' `
       -replace '<td>Offline</td>','<td class="fail">Offline</td>' `
       -replace '<td>Enabled</td>','<td class="pass">Enabled</td>' `
       -replace '<td>Normal</td>','<td class="pass">Normal</td>' `
       -replace '<td>Disabled</td>','<td class="fail">Disabled</td>' `
       -replace '<td>Access Denied</td>','<td class="warn">Access Denied</td>' `
       -replace '<td>Issues detected</td>','<td class="warn">Issues detected</td>'
}

$htmlReport | Out-File $reportPath -Encoding UTF8

# Post-report actions
Write-Host "`nReport generated: $reportPath" -ForegroundColor Cyan
Write-Host "`nTroubleshooting Tips:`n" -ForegroundColor Yellow
Write-Host "1. For systems showing 'Offline' but responding to TCP:"
Write-Host "   - Check WinRM configuration: Test-WSMan <ComputerName>"
Write-Host "   - Verify firewall rules: Get-NetFirewallRule -Name *WinRM*"
Write-Host "2. For Kerberos issues:"
Write-Host "   - Check system time synchronization"
Write-Host "   - Validate SPN records: setspn -L <ComputerName>"
Write-Host "3. For disk space warnings:"
Write-Host "   - Consider cleanup or expanding storage"
