# Domain System Health Audit Script
# Generates HTML report with dropdowns and system status

$reportPath = "$env:USERPROFILE\Documents\DomainHealthReport.html"
$systems = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

$reportData = @()
foreach ($system in $systems) {
    try {
        $cimSession = New-CimSession -ComputerName $system -ErrorAction Stop
        
        # System Information
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $cimSession | 
            Where-Object {$_.DriveType -eq 3} |
            Select-Object DeviceID, Size, FreeSpace,
                @{Name="UsedGB";Expression={[math]::Round(($_.Size - $_.FreeSpace)/1GB,2)}},
                @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}
        
        # Security Checks
        $kerberosConfig = Invoke-Command -ComputerName $system -ScriptBlock {
            @{
                KerberosEnabled = (Get-Item WSMan:\localhost\Service\Auth\Kerberos).Value
                AllowUnencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value
            }
        }
        
        # Last User Check
        $lastUser = Get-ChildItem "\\$system\c$\Users" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1 Name, LastWriteTime

        # Best Practice Checks
        $bestPractices = [PSCustomObject]@{
            PendingReboot = Test-PendingReboot -ComputerName $system
            WindowsUpdateStatus = (Get-Service -Name wuauserv -ComputerName $system).Status
            FirewallEnabled = (Get-NetFirewallProfile -PolicyStore PersistentStore).Enabled
        }

        $reportData += [PSCustomObject]@{
            Hostname       = $system
            OSVersion      = $os.Caption
            LastBootTime   = $os.LastBootUpTime
            Disks          = $disks
            KerberosStatus = $kerberosConfig
            LastUser       = $lastUser
            BestPractices  = $bestPractices
        }
    }
    catch {
        Write-Warning "Unable to connect to $system"
    }
}

# HTML Report Generation
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Domain Systems Health Report</title>
    <style>
        .system-card { border: 1px solid #ddd; margin: 10px; padding: 15px; border-radius: 5px; }
        .disk-table { margin: 10px 0; display: none; }
        .critical { color: #dc3545; font-weight: bold; }
        .warning { color: #ffc107; }
        button { margin: 5px; padding: 5px 10px; }
    </style>
</head>
<body>
    <h1>Domain Systems Health Report</h1>
    <h3>Generated: $(Get-Date)</h3>
"@

foreach ($system in $reportData) {
    $html += @"
    <div class="system-card">
        <h2>$($system.Hostname)</h2>
        <p>OS: $($system.OSVersion)</p>
        <p>Last Boot: $($system.LastBootTime)</p>
        
        <button onclick="toggleDisks('$($system.Hostname)')">Show Disks</button>
        <div id="$($system.Hostname)-disks" class="disk-table">
            $($system.Disks | ConvertTo-Html -Fragment)
        </div>

        <h3>Security Status:</h3>
        <ul>
            <li>Kerberos Enabled: $($system.KerberosStatus.KerberosEnabled)</li>
            <li>Unencrypted Allowed: <span class="$(
                if ($system.KerberosStatus.AllowUnencrypted) {'critical'} else {'warning'}
            )">$($system.KerberosStatus.AllowUnencrypted)</span></li>
        </ul>

        <h3>User Activity:</h3>
        <p>Last User Profile: $($system.LastUser.Name) @ $($system.LastUser.LastWriteTime)</p>

        <h3>Best Practices:</h3>
        <ul>
            <li>Pending Reboot: $($system.BestPractices.PendingReboot)</li>
            <li>Windows Update Service: $($system.BestPractices.WindowsUpdateStatus)</li>
            <li>Firewall Enabled: $($system.BestPractices.FirewallEnabled)</li>
        </ul>
    </div>
"@
}

$html += @"
<script>
    function toggleDisks(hostname) {
        const diskDiv = document.getElementById(hostname + '-disks');
        diskDiv.style.display = diskDiv.style.display === 'none' ? 'block' : 'none';
    }
</script>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Force
Write-Host "Report generated: $reportPath" -ForegroundColor Green
