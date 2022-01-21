<#
.SYNOPSIS
    Remediates defender issues and brings it to a secure state
.DESCRIPTION 
    * This script enables protection capabilities of Windows Defender Antivirus on Server 2016 and put the product into a healthy config. 
    * After it runs it will attempt a quick scan, if we cannot do a quick scan we will try with MSERT if the -RunMsert parameter is specified 
    * This includes repairing areas of Defender if disabled such as services and drivers, restoring AV to active mode, updating signatures and engine, enabling real time and cloud protection levels and smart screen
    DISCLAIMER: Use this script at your own risk, without warranty either expressed or implied, including, but not limited to, 
    the implied warranties of merchantability and/or fitness for a particular purpose.
    
    ***IMPORTANT: If you configure Defender via GPO or any type of system management tool (MEMCM, BigFix etc) you may need to disable or remove those configurations for this script to work.***

    For feedback, please email mdavenable@microsoft.com

    Requires,
    1.  Run the script as system like, psexec -i -s "powershell -ep Unrestricted -file <path_to_file> OR as a scheduled task"

.PARAMETER RunMsert
    If the quick scan fails, Run MSERT
.EXAMPLE
    ./ServerDefenderRestore.ps1
.EXAMPLE
    ./ServerDefenderRestore.ps1 -RunMsert
#> 
Param(
    [Parameter(Mandatory=$false)]
    [Switch]$RunMsert
    )

function Configure_SmartScreen()
{
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreenInShell -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableAppInstallControl -Value 1 -PropertyType DWORD -Force | Out-Null
}

function Check_DefenderService()
{
    $defservice = Get-Service -Name Windefend
    if ($defservice.status -eq "Stopped")
    {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -Value 2 -PropertyType DWORD -Force | Out-Null
        Get-Service Windefend | Where-Object {$defservice.status -eq "Stopped"} |  Start-Service
    }

    $defservice = Get-Service -Name Windefend
    if ($defservice.status -ne "Running")
    {
        LogErrorAndConsole "Unable to start defender service!!!"
    }
    else
    {
        LogAndConsole "`n!!!Defender service check passed!!!`n" -ForegroundColor Green
    }
}

function Remove_RemoveDisableRoutineActionKey()
{
    $RegKey = Get-ItemProperty -Path "HKLM:\software\policies\microsoft\windows defender" -Name "DisableRoutinelyTakingAction" -ErrorAction SilentlyContinue

    if ($RegKey)
    {
        Remove-ItemProperty -Path "HKLM:\software\policies\microsoft\windows defender" -Name "DisableRoutinelyTakingAction" -Force | Out-Null    
    }
}


function DisableLocalAdminMerge()
{
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name DisableLocalAdminMerge -Value 1 -PropertyType DWORD -Force | Out-Null
}

function Remove-DisableAntiSpyware
{
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $RegKey = Get-ItemProperty -Path $RegPath -Name "DisableAntispyware" -ErrorAction SilentlyContinue

    if ($RegKey)
    {
        Remove-ItemProperty -Path $RegPath -Name "DisableAntispyware" -Force | Out-Null

        $RegKey1 = Get-ItemProperty -Path $RegPath -Name "DisableAntispyware" -ErrorAction SilentlyContinue

        $WowRegPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender"
        $RegKey2 = Get-ItemProperty -Path $WowRegPath -Name "DisableAntispyware" -ErrorAction SilentlyContinue

        if ($RegKey1 -or $RegKey2)
        {
            LogErrorAndConsole "Failed to remove the registry key [DisableAntispyware]"
        }
    }
}

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name ForceDefenderPassiveMode -PropertyType DWord -value 0 -Force | Out-Null

function CheckTamperProtectionState()
{
    $tpv = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\features" -Name "TamperProtection"
    if (($tpv -band 1) -eq 1)
    {
        return $true
    }
    else
    {
        return $false
    }
}

# Verifies that the script is running as admin
function Check_IsElevated()
{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Output $true
    }
    else
    {
        Write-Output $false
    }
}

function Check_IsSystem()
{
    $idName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (!($idName -like "NT AUTHORITY\SYSTEM"))
    {
        Write-Output $false
    }
    else
    {
        Write-Output $true
    }
}

function CheckAndUpdateServiceStartType()
{
    $Service = Get-Service -Name WinDefend

    if ($Service.StartType -ine 'Automatic')
    {
        Set-Service -Name WinDefend -StartupType Automatic | Out-Null

        $Service = Get-Service -Name WinDefend

        if ($Service.StartType -ine 'Automatic')
        {
            LogErrorAndConsole "Failed to update service WinDefend startup type to Automatic"
        }
    }


    $Service = Get-Service -Name WdnisDrv

    if ($Service.StartType -ine 'Manual')
    {
        Set-Service -Name WdnisDrv -StartupType Manual | Out-Null

        $Service = Get-Service -Name WdnisDrv

        if ($Service.StartType -ine 'Manual')
        {
            LogErrorAndConsole "Failed to update service WdnisDrv startup type to Manual"
        }
    }

    $Service = Get-Service -Name wdfilter

    if ($Service.StartType -ine 'Boot')
    {
        Set-Service -Name wdfilter -StartupType Boot | Out-Null

        $Service = Get-Service -Name wdfilter

        if ($Service.StartType -ine 'Boot')
        {
            LogErrorAndConsole "Failed to update service wdfilter startup type to Boot"
        }
    }        

    $Service = Get-Service -Name wdboot

    if ($Service.StartType -ine 'Boot')
    {
        Set-Service -Name wdboot -StartupType Boot | Out-Null

        $Service = Get-Service -Name wdboot

        if ($Service.StartType -ine 'Boot')
        {
            LogErrorAndConsole "Failed to update service wdboot startup type to Boot"
        }
    }        
}

function Run-MSERT {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [switch]$RunFullScan,
        [switch]$DoNotRemediate
    )
    $Stage = "MSERTProcess"
    if ($DoNotRunMSERT) {
        $Message = "Skipping MSERT scan -DoNotRunMSERT set on $env:computername"
        $RegMessage = "Skipping mitigation -DoNotRunMSERT"
       
        return
    }

    #Check for KB4474419
    $OS = [System.Environment]::OSVersion
    if ($OS.Version.Major -eq 6 -and $OS.Version.Minor -eq 1) {
        $Hotfix = Get-HotFix -Id KB4474419 -ErrorAction SilentlyContinue

        if (-not ($Hotfix)) {
            $Message = "Unable to run MSERT: KB4474419 is missing on Server 2008 R2"
            $RegMessage = "Unable to run MSERT KB4474419 missing"

           
            throw
        }
    }

    #Check for running MSERT or MRT process before download
    $procsToWaitFor = @("mrt", "msert")
    :checkForRunningCleaner while ($true) {
        foreach ($procName in $procsToWaitFor) {
            $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($proc) {
                $pids = [string]::Join(",", $proc.Id)

                $Message = "Found $procName already running ($pids). Waiting for it to exit."
                $RegMessage = "msert already running waiting"
                $Stage = "MSERTProcess"
               

                Start-Sleep -Seconds 60
                continue checkForRunningCleaner
            }
        }
        break
    }


    if ((Get-Item $env:TEMP).PSDrive.Free -ge 314572800) {
        if ([System.Environment]::Is64BitOperatingSystem) {
            $MSERTUrl = "https://go.microsoft.com/fwlink/?LinkId=212732"
        } else {
            $MSERTUrl = "https://go.microsoft.com/fwlink/?LinkId=212733"
        }

        $Message = "Starting MSERTProcess on $env:computername"
        $RegMessage = "Starting MSERTProcess"
       

        try {
            $msertExe = "$($env:TEMP)\msert.exe"
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = "SilentlyContinue"
            $response = Invoke-WebRequest $MSERTUrl -UseBasicParsing
            [IO.File]::WriteAllBytes($msertExe, $response.Content)
            $Message = "MSERT download complete on $env:computername"
            $RegMessage = "MSERT download complete"
            $ProgressPreference = $oldProgressPreference
        } catch {
            $Message = "MSERT download failed on $env:computername"
            $RegMessage = "MSERT download failed"
           
            throw
        }
    } else {
        $drive = (Get-Item $env:TEMP).PSDrive.Root
        $Message = "MSERT download failed on $env:computername, due to lack of space on $drive"
        $RegMessage = "MSERT did not download. Ensure there is at least 300MB of free disk space on $drive"
       
        throw
    }

    #Start MSERT
    function RunMsert {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Invalid rule result')]
        param(
            [switch]$FullScan,
            [switch]$DoNotRemediate
        )

        $msertLogPath = "$env:SystemRoot\debug\msert.log"
        $msertLogArchivePath = "$env:SystemRoot\debug\msert.old.log"

        if (Test-Path $msertLogPath) {
            Get-Content $msertLogPath | Out-File $msertLogArchivePath -Append
            Remove-Item $msertLogPath
        }

        $msertArguments = "/Q"
        if ($FullScan) {
            $msertArguments = "/F /Q"
        }

        if ($DoNotRemediate) {
            $msertArguments += " /N"
        }

        Start-Process $msertExe -ArgumentList $msertArguments -Wait

        $detected = $false

        if (Test-Path $msertLogPath) {
            $matches = Select-String -Path $msertLogPath -Pattern "Threat Detected"
            if ($matches) {
                $detected = $true
            }
        } else {
            $Message = "Did not find expected scanner log file at $msertLogPath"
            $RegMessage = "No scanner log"
           
            throw
        }

        return $detected
    }

    $ScanMode = ""
    if ($RunFullScan) {
        Write-Warning -Message "Running a full scan can take hours or days to complete."
        Write-Warning -Message "Would you like to continue with the Full MSERT Scan?"

        while ($true) {
            $Confirm = Read-Host "(Y/N)"
            if ($Confirm -like "N") {
                return
            }
            if ($Confirm -like "Y") {
                break
            }
        }

        $ScanMode = "Full Scan"
    } else {
        Write-Verbose -Message "Quick scan will take several minutes to complete, please wait.." -Verbose

        $ScanMode = "Quick Scan"
    }

    if ($DoNotRemediate) {
        $ScanMode += " (No Remediation)"
    }

    $Message = "Running Microsoft Safety Scanner - Mode: $ScanMode on $env:computername"
    $RegMessage = "Running Microsoft Safety Scanner $ScanMode"
   

    $msertDetected = RunMsert -FullScan:$RunFullScan -DoNotRemediate:$DoNotRemediate

    if ($msertDetected) {
        Write-Warning -Message "THREATS DETECTED on $env:computername!"
        Get-Content $msertLogPath
        $Message = "Threats detected! Please review `"$msertLogPath`" as soon as possible. "
        if (!$RunFullScan) {
            $Message += "We highly recommend re-running this script with -RunFullScan. "
        }
        $Message += "For additional guidance, see `"$SummaryFile`"."
        $RegMessage = "Microsoft Safety Scanner is complete: THREATS DETECTED"
       
    } else {
        $Message = "Microsoft Safety Scanner is complete on $env:computername No known threats detected."
        $RegMessage = "Microsoft Safety Scanner is complete"
       
    }
}



#Log file name and location
$LogFileName = "defender_restore.log";
$LogFilePath = Join-Path (Get-Item -Path ".\").FullName $LogFileName;

function Log
{
    param($message);

    $currenttime    = Get-Date -format u;
    $outputstring   = "[" + $currenttime + "] " + $message;
    $outputstring | Out-File $LogFilepath -Append;
}

function LogAndConsole($message)
{
    Write-Host $message -ForegroundColor Green
    Log $message
}

function LogErrorAndConsole($message)
{
    Write-Host $message -ForegroundColor Red
    Log $message
}

if (!(Check_IsElevated))
{
    throw "Please run this script from an elevated PowerShell prompt"
}

LogAndConsole "checking cloud connectivity"
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe"
$pinfo.RedirectStandardError = $true
$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.Arguments = "-validatemapsconnection"
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null
$p.WaitForExit()
$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()
LogAndConsole "$stdout"
LogErrorAndConsole  "$stderr"

LogAndConsole "call mpcmdrun wdenable"
Start-Process "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -ArgumentList "-wdenable" -Wait -NoNewWindow

LogAndConsole "Set windefend service dependency correctly"
Start-Process "$($env:Windir)\system32\sc.exe" -ArgumentList "config windefend depend=RpcSs" -Wait -NoNewWindow

LogAndConsole "Updating WinDefend service startup type to Automatic if it is not"
CheckAndUpdateServiceStartType

LogAndConsole "Removing DisableAntiSpyware Registry Key"
Remove-DisableAntiSpyware

LogAndConsole "Removing DisableRoutineActionKey Registry Key"
Remove_RemoveDisableRoutineActionKey

LogAndConsole "Check if defender service is running"
Check_DefenderService

LogAndConsole "Enable cloud-deliveredprotection"
Set-MpPreference -MAPSReporting Advanced

LogAndConsole "Enable checking signatures before scanning"
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1

LogAndConsole "Enable behavior monitoring"
Set-MpPreference -DisableBehaviorMonitoring 0

LogAndConsole "Enable IOAV protection"
Set-MpPreference -DisableIOAVProtection 0

LogAndConsole "Enable script scanning"
Set-MpPreference -DisableScriptScanning 0

LogAndConsole "Enable removable drive scanning"
Set-MpPreference -DisableRemovableDriveScanning 0

LogAndConsole "Enable Block at first sight"
Set-MpPreference -DisableBlockAtFirstSeen 0

# LogAndConsole "Enable potentially unwanted apps"
# Set-MpPreference -PUAProtection Enabled

LogAndConsole "Schedule signature updates every 4 hours"
Set-MpPreference -SignatureUpdateInterval 4

LogAndConsole "Enable archive scanning"
Set-MpPreference -DisableArchiveScanning 0

LogAndConsole "Enable email scanning"
Set-MpPreference -DisableEmailScanning 0

LogAndConsole "Enabling scanning network files"
Set-MpPreference -DisableScanningNetworkFiles 0

LogAndConsole "Enabling scanning mapped network drives for fullscan"
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 0

LogAndConsole "Removing the threat default actions"
Remove-MpPreference -HighThreatDefaultAction
Remove-MpPreference -LowThreatDefaultAction
Remove-MpPreference -ModerateThreatDefaultAction
Remove-MpPreference -SevereThreatDefaultAction
Remove-MpPreference -UnknownThreatDefaultAction

LogAndConsole "Setting SignatureDisableUpdateOnStartupWithoutEngine to False (default value)"
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false -Force

LogAndConsole "Enabling real-time monitoring"
Set-MpPreference -DisableRealtimeMonitoring $false

# Set SmartScreen AppRep
Configure_SmartScreen

LogAndConsole "Removing broad exclusions"
Remove-MpPreference -ExclusionPath "C:\"
Remove-MpPreference -ExclusionPath "C:"
Remove-MpPreference -ExclusionPath "C:\*"
Remove-MpPreference -ExclusionPath "d:\"
Remove-MpPreference -ExclusionPath "d:"
Remove-MpPreference -ExclusionPath "d:\*"
Remove-MpPreference -ExclusionPath "%ProgramFiles%\Java"
Remove-MpPreference -ExclusionPath "c:\temp"
Remove-MpPreference -ExclusionPath "c:\temp\"
Remove-MpPreference -ExclusionPath "c:\temp\*"
Remove-MpPreference -ExclusionPath "c:\Users"
Remove-MpPreference -ExclusionPath "c:\Users\*"
Remove-MpPreference -ExclusionPath "C:\Windows\Temp"
Remove-MpPreference -ExclusionPath "C:\Windows\Temp\*"
Remove-MpPreference -ExclusionExtension ".7z"
Remove-MpPreference -ExclusionExtension ".bat"
Remove-MpPreference -ExclusionExtension ".exe"
Remove-MpPreference -ExclusionExtension ".dll"
Remove-MpPreference -ExclusionExtension ".bin"
Remove-MpPreference -ExclusionExtension ".cab"
Remove-MpPreference -ExclusionExtension ".cmd"
Remove-MpPreference -ExclusionExtension ".com"
Remove-MpPreference -ExclusionExtension ".cpl"
Remove-MpPreference -ExclusionExtension ".fla"
Remove-MpPreference -ExclusionExtension ".gif"
Remove-MpPreference -ExclusionExtension ".gz"
Remove-MpPreference -ExclusionExtension ".hta"
Remove-MpPreference -ExclusionExtension ".inf"
Remove-MpPreference -ExclusionExtension ".java"
Remove-MpPreference -ExclusionExtension ".jar"
Remove-MpPreference -ExclusionExtension ".jpeg"
Remove-MpPreference -ExclusionExtension ".jpg"
Remove-MpPreference -ExclusionExtension ".js"
Remove-MpPreference -ExclusionExtension ".msi"
Remove-MpPreference -ExclusionExtension ".ocx"
Remove-MpPreference -ExclusionExtension ".png"
Remove-MpPreference -ExclusionExtension ".ps1"
Remove-MpPreference -ExclusionExtension ".tmp"
Remove-MpPreference -ExclusionExtension ".vbe"
Remove-MpPreference -ExclusionExtension ".vbs"
Remove-MpPreference -ExclusionExtension ".wsf"
Remove-MpPreference -ExclusionExtension ".zip"
Remove-MpPreference -ExclusionExtension ".sys"
Remove-MpPreference -ExclusionExtension ".scr"
Remove-MpPreference -ExclusionExtension ".py"



# trigger AV sig update
LogAndConsole "Updating signatures"
try
{
    Update-MpSignature -UpdateSource MMPC #just do ADL
}
catch 
{
    LogAndConsole "Signature update may fail, but thats ok"
}
Start-Sleep -s 30
LogAndConsole "Attempting a System Scan, if permitted we will run MSERT"
try {
    Start-MpScan -ErrorAction Stop
}
catch {
  if ($RunMsert)  
  {
      Run-Msert
  }
}
LogAndConsole "Set EngineUpdatesChannel"
try {
    Set-MpPreference -EngineUpdatesChannel Broad -ErrorAction Stop
} catch {
    LogErrorAndConsole "EngineUpdatesChannel Failed, Likely old platform version"
}
LogAndConsole "Set PlatformUpdatesChannel"
try {
    Set-MpPreference -PlatformUpdatesChannel Broad -ErrorAction Stop
} catch {
    LogErrorAndConsole "PlatformUpdatesChannel Failed, Likely old platform version"
}
try {
    LogAndConsole "Set DefinitionUpdatesChannel"
    Set-MpPreference -DefinitionUpdatesChannel Broad -ErrorAction Stop
} catch {
    LogErrorAndConsole "DefinitionUpdatesChannel Failed, Likely old platform version"
}
LogAndConsole "Enable sample submission"
try {
    Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
} catch {
    LogAndConsole "Old platform version, setting Samples Consent to Always"
    Set-MpPreference -SubmitSamplesConsent Always
}

Write-Host "`nOutput Windows Defender AV settings status"  -ForegroundColor Green
Get-MpPreference
LogAndConsole "Config complete"
exit 0
