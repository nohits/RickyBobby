[Download RickyBobby](https://github.com/nohits/RickyBobby/archive/refs/heads/main.zip)

**Description**
This script is designed to clean and speed up your PC. This script performs maintenance tasks to improve system performance, such as clearing temporary files, optimizing system settings, and more.

**Features** 
- **ClearJunkFiles**: Removes temporary files and system cache to free up disk space. 
- **EnhancePC**: Adjusts settings to improve system speed and responsiveness. 
- **EnhanceSecurity**: Blocks trackers and improves privacy. Apps depending on location/tracking might fail.
- **ClearBloatware**: Removes default Windows bloatware. Essential Windows apps are whitelisted in script.
 - **BackupRegistry**: Backup registry. Recommended before running any functions.
 
**Installation**
```diff
- Clone this repository or download the zip file directly.
  git clone https://github.com/nohits/rickybobby.git
 
- Unzip folder in one of the directories listed in the '$env:PSModulePath' environment variable. 
  To install for all users, use the directory - C:\Program Files\WindowsPowerShell\Modules 

- Import the module  
  Import-Module RickyBobby

- To run the script or function, execute from powershell:
  Invoke-RickyBobby
```
<br>

**To Undo Changes** 
- Reinstall default Windows apps (Bloatware) 
```
Get-AppXPackage | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
```

- [Restore Windows default services](https://www.tenforums.com/attachments/tutorials/334219d1621785267-restore-default-services-windows-10-a-windows_10_default_services.zip) Registry file containing default values, open file to merge settings. 

<br>

The module requires admin privileges to execute most functions.
<br>
