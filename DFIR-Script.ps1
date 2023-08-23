$ASCIIBanner = @"
  _____                                           _              _   _     _____    ______   _____   _____  
 |  __ \                                         | |            | | | |   |  __ \  |  ____| |_   _| |  __ \ 
 | |__) |   ___   __      __   ___   _ __   ___  | |__     ___  | | | |   | |  | | | |__      | |   | |__) |
 |  ___/   / _ \  \ \ /\ / /  / _ \ | '__| / __| | '_ \   / _ \ | | | |   | |  | | |  __|     | |   |  _  / 
 | |      | (_) |  \ V  V /  |  __/ | |    \__ \ | | | | |  __/ | | | |   | |__| | | |       _| |_  | | \ \ 
 |_|       \___/    \_/\_/    \___| |_|    |___/ |_| |_|  \___| |_| |_|   |_____/  |_|      |_____| |_|  \_\
"@
Write-Host $ASCIIBanner
Write-Host "`n"
Write-Host "By twitter: @BertJanCyber, Github: Bert-JanP"
Write-Host "===========================================`n"

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator..."
}
else {
    Write-Host "No Administrator session detected. For the best performance run as Administrator. Not all items can be collected..."
    Write-Host "DFIR Session starting..."
}

Write-Host "Creating output directory..."
$CurrentPath = Get-Location
$ExecutionTime = $(Get-Date -f yyyy-MM-dd)
$OutputFolderPath = "$($CurrentPath)\DFIR-$($env:computername)-$($ExecutionTime)"
New-Item -Path $OutputFolderPath -ItemType Directory -Force | Out-Null
Write-Host "Output directory created: $OutputFolderPath..."

function Get-NetworkAdapters {
    Write-Host "Collecting information about local network adapters..."
    $NetworkAdaptersOutput = "$OutputFolderPath\NetworkAdapters.csv"
    Get-NetIPAddress | Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, IPAddress, AddressState | ConvertTo-Csv -NoTypeInformation | Out-File -Force -FilePath $NetworkAdaptersOutput
}
function Get-ShadowCopies {
    Write-Host "Collecting Shadow Copies..."
    $ShadowCopy = "$OutputFolderPath\ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
}

function Get-OpenConnections {
    Write-Host "Collecting Open Connections..."
    $ConnectionsFolder = "$OutputFolderPath\Connections"
	New-Item -Path $ConnectionsFolder -ItemType Directory -Force | Out-Null
    $OpenConnectionsOutput = "$ConnectionsFolder\OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $OpenConnectionsOutput
}

function Get-AutoRunInfo {
    Write-Host "Collecting AutoRun info..."
    $PersistenceFolder = "$OutputFolderPath\Persistence"
	New-Item -Path $PersistenceFolder -ItemType Directory -Force | Out-Null
    $RegKeyOutput = "$AutoRunFolder\AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
}

function Get-InstalledDrivers {
    Write-Host "Collecting Installed Drivers..."
    $PersistenceFolder = "$OutputFolderPath\Persistence"
    $RegKeyOutput = "$PersistenceFolder\InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput
}

function Get-ActiveUsers {
    Write-Host "Collecting Active users..."
    $UserFolder = "$OutputFolderPath\UserInformation"
	New-Item -Path $UserFolder -ItemType Directory -Force | Out-Null
    $ActiveUserOutput = "$UserFolder\ActiveUsers.txt"
    query user /server:$server | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-LocalUsers {
    Write-Host "Collecting Local users..."
    $UserFolder = "$OutputFolderPath\UserInformation"
    $ActiveUserOutput = "$UserFolder\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-ActiveProcesses {
    Write-Host "Collecting Active Processes..."
    $ProcessFolder = "$OutputFolderPath\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($process.ExecutablePath -ne $null)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
}

function Get-SecurityEventCount {
    Write-Host "Collecting stats Security Events last 48 hours..."
    $SecurityEvents = "$OutputFolderPath\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\EventCount.txt"
    $SecurityEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-2)
    $SecurityEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending | Out-File -Force -FilePath $ProcessOutput
}

function Get-SecurityEvents {
    Write-Host "Collecting Security Events last 48 hours..."
    $SecurityEvents = "$OutputFolderPath\SecurityEvents"
    mkdir -Force $SecurityEvents | Out-Null
    $ProcessOutput = "$SecurityEvents\SecurityEvents.txt"
    get-eventlog security -After (Get-Date).AddDays(-2) | Format-List * | Out-File -Force -FilePath $ProcessOutput
}

function Get-EVTXFiles {
    Write-Host "Collecting Important EVTX Files..."
    $EventViewer = "$OutputFolderPath\Event Viewer"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    foreach ($channel in $channels) {
        Copy-Item -Path "$($evtxPath)\$($channel).evtx" -Destination "$($EventViewer)\$($channel).evtx"
    }
}

function Get-OfficeConnections {
    Write-Host "Collecting connections made from office applciations..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $OfficeConnection = "$ConnectionFolder\ConnectionsMadeByOffice.txt"
    Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache* -erroraction 'silentlycontinue' | Out-File -Force -FilePath $OfficeConnection 
}

function Get-NetworkShares {
    Write-Host "Collecting Active Network Shares..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $ProcessOutput = "$ConnectionFolder\NetworkShares.txt"
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ | Format-Table | Out-File -Force -FilePath $ProcessOutput
}

function Get-SMBShares {
    Write-Host "Collecting SMB Shares..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $ProcessOutput = "$ConnectionFolder\SMBShares.txt"
    Get-SmbShare | Out-File -Force -FilePath $ProcessOutput
}

function Get-RDPSessions {
    Write-Host "Collecting RDS Sessions..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $ProcessOutput = "$ConnectionFolder\RDPSessions.txt"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
}

function Get-RemotelyOpenedFiles {
    Write-Host "Collecting Remotly Opened Files..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $ProcessOutput = "$ConnectionFolder\RemotelyOpenedFiles.txt"
    openfiles | Out-File -Force -FilePath $ProcessOutput
}

function Get-DNSCache {
    Write-Host "Collecting DNS Cache..."
    $ConnectionFolder = "$OutputFolderPath\Connections"
    $ProcessOutput = "$ConnectionFolder\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
}

function Get-PowershellHistory {
    Write-Host "Collecting Powershell History..."
    $PowershellHistoryOutput = "$OutputFolderPath\PowershellHistory.txt"
    history | Out-File -Force -FilePath $PowershellHistoryOutput
}

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "Collecting Recently Installed Software EventLogs..."
    $ApplicationFolder = "$OutputFolderPath\Applications"
    mkdir -Force $ApplicationFolder | Out-Null
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *| Out-File -Force -FilePath $ProcessOutput
}

function Get-RunningServices {
    Write-Host "Collecting Running Services..."
    $ApplicationFolder = "$OutputFolderPath\Applications"
    $ProcessOutput = "$ApplicationFolder\RecentlyInstalledSoftwareEventLogs.txt"
    Get-Service | Where-Object {$_.Status -eq "Running"} | format-list | Out-File -Force -FilePath $ProcessOutput
}

function Get-ScheduledTasks {
    Write-Host "Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = "$OutputFolderPath\ScheduledTask"
    mkdir -Force $ScheduledTaskFolder| Out-Null
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksList.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List | Out-File -Force -FilePath $ProcessOutput
}

function Get-ScheduledTasksRunInfo {
    Write-Host "Collecting Scheduled Tasks Run Info..."
    $ScheduledTaskFolder = "$OutputFolderPath\ScheduledTask"
    $ProcessOutput = "$ScheduledTaskFolder\ScheduledTasksListRunInfo.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Out-File -Force -FilePath $ProcessOutput
}

function Get-ConnectedDevices {
    Write-Host "Collecting Information about Connected Devices..."
    $DeviceFolder = "$OutputFolderPath\ConnectedDevices"
    New-Item -Path $DeviceFolder -ItemType Directory -Force | Out-Null
    $ConnectedDevicesOutput = "$DeviceFolder\ConnectedDevices.csv"

    Get-PnpDevice | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput
}


function Zip-Results {
    Write-Host "Write results to $OutputFolderPath.zip..."
    Compress-Archive -Force -LiteralPath $OutputFolderPath -DestinationPath "$OutputFolderPath.zip"
}

#Run all functions that do not require admin priviliges
function Run-WithoutAdminPrivilege {
    Get-NetworkAdapters
    Get-OpenConnections
    Get-AutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-OfficeConnections
    Get-NetworkShares
    Get-SMBShares
    Get-RDPSessions
    Get-PowershellHistory
    Get-DNSCache
    Get-InstalledDrivers    
    Get-RecentlyInstalledSoftwareEventLogs
    Get-RunningServices
    Get-ScheduledTasks
    Get-ScheduledTasksRunInfo
    Get-ConnectedDevices
}

#Run all functions that do require admin priviliges
Function Run-WithAdminPrivilges {
    Get-SecurityEventCount
    Get-SecurityEvents
    Get-RemotelyOpenedFiles
    Get-ShadowCopies
    Get-EVTXFiles
}

if ($IsAdmin) {
    Run-WithoutAdminPrivilege
    Run-WithAdminPrivilges
}
else {
    Run-WithoutAdminPrivilege
}

Zip-Results

