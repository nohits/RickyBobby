# RickBobby speeds up windows machines
#

function Invoke-RickyBobby {

    do {
        '
        0) Exit
        1) ClearJunkFiles
        2) EnhancePerformance
        3) EnhanceSecurity
        4) ClearBloatware
        5) BackupRegistry'

        # Prompt user which function they would like to use
        $input = Read-Host 'Select Function'

        # Determines if the user entry is empty or not
        if ( ([string]::IsNullOrEmpty($input))) {
            Write-Host "This tool cannot work without input."
        }

        # All available functions are listed below they will be called if the input condition matches the values
        switch ($input) {

            # Cleans up pc junk files - browsing data, temp files, and other app cache...
            1 {  
                function Clear-Chrome {
                    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
                    if (Test-Path $chromePath) {
                        Get-Process -Name chrome | Stop-Process -Force
                        Remove-Item "$chromePath\Cookies" -Force 
                        Remove-Item "$chromePath\History" -Force
                        Remove-Item "$chromePath\Web Data" -Force
                        Remove-Item "$chromePath\Login Data" -Force
                        Remove-Item "$chromePath\Visited Links" -Force
                        Remove-Item "$chromePath\DownloadMetadata" -Force
                        Remove-Item "$chromePath\Cache\*" -Recurse -Force
                    }
                }

                function Clear-Firefox {
                    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
                    if (Test-Path $firefoxPath) {
                        $profileFolders = Get-ChildItem -Path $firefoxPath
                        foreach ($folder in $profileFolders) {
                            Get-Process -Name firefox | Stop-Process -Force
                            Remove-Item "$folder\logins.json" -Force pscre
                            Remove-Item "$folder\places.sqlite" -Force
                            Remove-Item "$folder\cookies.sqlite" -Force
                            Remove-Item "$folder\downloads.json" -Force
                            Remove-Item "$folder\formhistory.sqlite" -Force
                            Remove-Item "$folder\cache2\*" -Recurse -Force
                            Remove-Item "$folder\sessionstore-backups\*" -Recurse -Force
                        }
                    }
                }

                function Clear-Edge {
                    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
                    if (Test-Path $edgePath) {
                        Get-Process -Name msedge | Stop-Process -Force
                        Remove-Item "$edgePath\Network\Cookies" -Force
                        Remove-Item "$edgePath\History" -Force
                        Remove-Item "$edgePath\Web Data" -Force
                        Remove-Item "$edgePath\Login Data" -Force
                        Remove-Item "$edgePath\Visited Links" -Force
                        Remove-Item "$edgePath\DownloadMetadata" -Force
                        Remove-Item "$edgePath\Cache\Cache_Data\*" -Recurse -Force
                    }
                }

                function Clear-Junk {
                    Clear-DnsClientCache
                    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 4351
                    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Force -ErrorAction SilentlyContinue -Recurse
                    Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Force -ErrorAction SilentlyContinue -Recurse
                    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Force -ErrorAction SilentlyContinue -Recurse
                    Remove-Item -Path $env:LocalAppData\Microsoft\Windows\WebCache\*.* -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "$env:SystemRoot\Traces\WindowsUpdate\*" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $env:SystemRoot\Logs\waasmedic -Force -ErrorAction SilentlyContinue -Recurse
                    Remove-Item -Path $env:SystemRoot\inf\setupapi.app.log -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $env:SystemRoot\comsetup.log -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $env:SystemRoot\setupapi.log -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $env:SystemRoot\Panther\* -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "$env:WINDIR\Temp\*" -Force -ErrorAction SilentlyContinue -Recurse
                    Remove-Item -Path "$env:APPDATA\Sun\Java\Deployment\cache" -Confirm:$false -Force
                    Remove-Item -Path "$env:TEMP\*" -Force -ErrorAction SilentlyContinue -Recurse
                    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
                    Dism.exe /Online /Cleanup-Image /StartComponentCleanup
                    Dism.exe /Online /Cleanup-Image /Restorehealth
                }

                function Clear-Disposal {
                    $shell = New-Object -ComObject Shell.Application
                    $recycleBin = $shell.Namespace(0xA)
                    $recycleBin.Items() | ForEach-Object { $_.InvokeVerb("delete")}
                    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow -Wait
                }

                Write-Output "Clearing junk files..."
                Clear-Chrome
                Clear-Firefox
                Clear-Edge
                Clear-Junk
                Clear-Disposal
                Write-Output "! Cleaned !"
            }


            # Enhance system performance, security, and privacy by mostly tweaking the registry.
            2 {
                function Optimize-Memory {
                    $pageFile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
                    $pageFile.AutomaticManagedPagefile = $true
                    $pageFile.put() | Out-Null
                    [system.gc]::Collect()
                }

                function Optimize-Drives {
                    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLinkedConnections -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Type DWord -Value 0
	                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Type DWord -Value 0
                    Stop-Service "WSearch" -WarningAction SilentlyContinue
                    Defrag C: -Verbose
                    #chkdsk C: /F /R /X 
                }

                function Optimize-Tasks {
                    Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
                    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
                    Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
                    Get-ScheduledTask -TaskName QueueReporting | Disable-ScheduledTask -ErrorAction SilentlyContinue
                    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
                    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
                    Get-CimInstance -ClassName Win32_StartupCommand | % { Disable-ScheduledTask -TaskName $_.Name -TaskPath $_.Location} -ErrorAction SilentlyContinue
                    foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
                        Set-ItemProperty ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
                    }
                }

                function Optimize-Features {
                    $features = @(
                    'SMB1Protocol',
                    'MediaPlayback',
                    'WCF-Services45',
                    'NetFx4-AdvSrvs',
                    'WorkFolders-Client',
                    'MSRDC-Infrastructure',
                    'Xps-Foundation-Xps-Viewer',
                    'Printing-Foundation-Features',
                    'Printing-XPSServices-Features'
                    'Internet-Explorer-Optional-amd64',
                    'MicrosoftWindowsPowerShellV2Root',
                    'Printing-PrintToPDFServices-Features'
                    )

                    foreach ($feature in $features) {
                        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
                    }
                }

                function Optimize-Tracking {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name Device Metadata -Force
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\" -Name Search -Force
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\" -Name TabPreloader -Force
                    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
                    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name TailoredExperiencesWithDiagnosticDataEnabled -Type "DWORD" -Value 0 -Force
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableSoftLanding -Type "DWORD" -Value 1 -Force
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableConsumerAccountStateContent -Type "DWORD" -Value 1 -Force
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type "DWORD" -Value 1 -Force
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name SyncDisabled -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name DisableOnline -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocationScripting -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type "DWORD" -Value 99 -Force
                    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0
                    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name Start -Type "DWORD" -Value 4 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type "DWORD" -Value 2 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type "DWORD" -Value 2 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowPrelaunch -Type "DWORD" -Value 0 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name AllowTabPreloading -Type "DWORD" -Value 0 -Force
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -Type "String" -Force
                }

                function Optimize-PowerPlan {
                    $highPerformanceGuid = (Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "ElementName='High performance'").InstanceID.Split("\\")[1]

                    if ($highPerformanceGuid) {
                        powercfg -setactive $highPerformanceGuid
                        Write-Host "Success - High Performance Power Plan IS Active." -ForegroundColor Green
                    } 
                    else {
                        Write-Warning "Failure -  High Performance Power Plan IS NOT Active."
                    }
                }

                Write-Host "Optimizing PC performance, privacy, speed, reliability, and security..."
                Optimize-Tasks
                Optimize-Memory
                Optimize-PowerPlan
                Optimize-Features
                Optimize-Tracking
                Optimize-Drives
                Write-Host "! Optimized !"
            }


            # Stop and Disable unnecessary windows services using the blacklist below
            3 {
                $servicesBlacklist = @(
                    'ALG',
                    'Fax',
                    'WinRM',
                    'DoSvc',
                    'irmon',
                    'wisvc',
                    'lfsvc',
                    'icssvc',
                    'HvHost',
                    'vmicvss',
                    'vmicrdv',
                    'WwanSvc',
                    'NfsClnt',
                    'SSDPSRV',
                    'MSiSCSI',
                    'WSearch',
                    'SNMPTRAP',
                    'SEMgrSvc',
                    'AJRouter',
                    'iphlpsvc',
                    'shpamsvc',
                    'seclogon',
                    'BthHFSrv',
                    'SCardSvr',
                    'DiagTrack',
                    'SmsRouter',
                    'MapsBroker',
                    'CscService',
                    'RetailDemo',
                    'OneSyncSvc',
                    'WFDSConSvc',
                    'RpcLocator',
                    'UnistoreSvc',
                    'BthAvctpSvc',
                    'TermService',
                    'PeerDistSvc',
                    'SCPolicySvc',
                    'FrameServer',
                    'XblGameSave',
                    'vmictimesync',
                    'RemoteAccess',
                    'vmicshutdown',
                    'SharedAccess',
                    'ScDeviceEnum',
                    'wercplsupport',
                    'WdiSystemHost',
                    'vmicheartbeat',
                    'vmicvmsession',
                    'SensorService',
                    'XboxNetApiSvc',
                    'RemoteRegistry',
                    'XblAuthManager',
                    'vmickvpexchange',
                    'UevAgentService',
                    'MessagingService',
                    'dmwappushservice',
                    'MessagingService',
                    'SensorDataService',
                    'vmicguestinterface',
                    'TabletInputService',
                    'PimIndexMaintenanceSvc',
                    'diagnosticshub.standardcollector.service'

                )

                function Kill-NoNeedServices {
                    param (
                        [string]$serviceName
                    )

                    try {
                        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
                        Set-Service -Name $serviceName -StartupType Disabled
                        Write-Host "Success - $serviceName service IS Stopped and Disabled." -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Failure - $serviceName service IS NOT Stopped or Disabled. Error: $_" -ForegroundColor Red
                    }
                }

                foreach ($service in $servicesBlacklist) { 
                    Kill-NoNeedServices -ServiceName $service
                }
            }


            # Remove all windows default bloatware except for the items whitelisted below
            4 {
                [regex]$appsToExclude =
                    '.NET
                    Framework|`
                    Microsoft.Paint3D|`
                    Microsoft.MSPaint|`
                    Microsoft.WindowsStore|`
                    Microsoft.ScreenSketch|`
                    Microsoft.WindowsCamera|`
                    Microsoft.Windows.Photos|`
                    Microsoft.StorePurchaseApp|`
                    Microsoft.WindowsCalculator|`
                    Microsoft.WebpImageExtension|`
                    Microsoft.WebMediaExtensions|`
                    Microsoft.HEIFImageExtension|`
                    Microsoft.VP9VideoExtensions|`
                    Microsoft.DesktopAppInstaller|`
                    Microsoft.MicrosoftStickyNotes|`
                    CanonicalGroupLimited.UbuntuonWindows'
                $ProvAppsToRemove = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $appsToExclude}

                foreach ($App in $ProvAppsToRemove) { 
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName
                }

                Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $appsToExclude} | Remove-AppxPackage -ErrorAction SilentlyContinue
            }


            # Backup registry to the users desktop
            5 {
                $backupFilePath = "$env:USERPROFILE\Desktop\RegistryBackup.reg"
                $backupDirectory = Split-Path $backupFilePath

                if (!(Test-Path $backupDirectory)) { 
                    New-Item -Path $backupDirectory -ItemType Directory -Force
                }

                Write-Host "Saving registry backup to $backupFilePath"
                reg export HKLM "$backupFilePath" /y
            }
        }
    }

    while ($input -ne 0)

}
