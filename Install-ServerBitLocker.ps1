<#
.SYNOPSIS
    Automates the installation and configuration of BitLocker Drive Encryption on Windows Servers.
    
.DESCRIPTION
    This script verifies TPM status, checks for Windows Server 2019+ compatibility, 
    installs necessary Windows features (including DC-specific sub-features), 
    and automates the encryption process using XtsAes256.

.REVISIONS
    03-09-2026 - Updated to support any Server OS higher than 2019. Now using XtsAes256 algorithm.
    06-05-2024 - Initial automation for Enterprise Staging environments.
#>

param(
	[Parameter(Mandatory=$false)][Switch]$setVmSetting
)

function Install-WindowsServerFeature {
	<#
	.SYNOPSIS
		Installs a specified Windows Server feature if it is not already installed.

	.DESCRIPTION
		This function checks if a Windows Server feature (role or feature) is installed.
		If the feature is not found or is in a 'Removed' state, it proceeds to install it.
		It uses the Install-WindowsFeature cmdlet, which is part of the Server Manager module.

		This function requires Administrator privileges.

	.PARAMETER FeatureName
		Specifies the name of the Windows Server feature to install.
		This parameter is mandatory. You can get a list of available features
		using 'Get-WindowsFeature'.

	.PARAMETER IncludeManagementTools
		Indicates that any associated management tools for the feature should also be installed.
		This is often useful for roles like IIS or Active Directory.

    .PARAMETER IncludeAllSubFeature
        Indicates that all sub-features of the specified feature should also be installed.
        This is particularly useful for BitLocker on Domain Controllers.

	.NOTES
		- This function must be run with Administrator privileges.
		- Some features may require a system restart after being installed.
		- Always verify the feature name using 'Get-WindowsFeature' before attempting to install it.

	.EXAMPLE
		# Install the 'Telnet-Client' feature
		Install-WindowsServerFeature -FeatureName "Telnet-Client"

	.EXAMPLE
		# Install the 'Web-Server' role and its management tools
		Install-WindowsServerFeature -FeatureName "Web-Server" -IncludeManagementTools

	.EXAMPLE
		# Check what would happen without actually installing (using -WhatIf)
		Install-WindowsServerFeature -FeatureName "Telnet-Client" -WhatIf

	.LINK
		https://learn.microsoft.com/en-us/powershell/module/servermanager/install-windowsfeature
		https://learn.microsoft.com/en-us/powershell/module/servermanager/get-windowsfeature
	#>
	
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$FeatureName,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeManagementTools,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllSubFeature
    )
	
	# Initialize the restart requirement flag to $false
    $restartRequired = $false

    # Check for Administrator privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This function requires Administrator privileges. Please run PowerShell as Administrator."
		return $false
    }

    Write-Host "Checking status of Windows Server feature '$FeatureName'..."

    try {
        # Get the status of the specified feature
        $featureStatus = Get-WindowsFeature -Name $FeatureName -ErrorAction SilentlyContinue

        if (-not $featureStatus) {
            Write-Host "Feature '$FeatureName' not found on this system. Please verify the feature name using 'Get-WindowsFeature'." -ForegroundColor Red
            return $false # Feature not found
        }

        # Check if the feature is already installed
        if ($featureStatus.Installed) {
            Write-Host "Feature '$FeatureName' is already installed. No action needed." -ForegroundColor DarkGray
            return $false # Already installed, no restart needed
        }

        # Use ShouldProcess for -WhatIf and -Confirm support
        if ($PSCmdlet.ShouldProcess("Install feature '$FeatureName'", "Are you sure you want to install the Windows Server feature '$FeatureName'?")) {
            Write-Host "Attempting to install Windows Server feature '$FeatureName'..." -ForegroundColor Cyan

            # Construct the arguments for Install-WindowsFeature using Splatting
            $installParams = @{
                Name = $FeatureName
                Confirm = $false # Suppress confirmation prompt from cmdlet itself
            }

            if ($IncludeManagementTools) {
                $installParams.Add("IncludeManagementTools", $true)
                Write-Host "Including management tools for feature '$FeatureName'..." -ForegroundColor Cyan
            }

            if ($IncludeAllSubFeature) {
                $installParams.Add("IncludeAllSubFeature", $true)
                Write-Host "Including all sub-features for feature '$FeatureName'..." -ForegroundColor Cyan
            }

            # Install the feature
            $installResult = Install-WindowsFeature @installParams -ErrorAction Stop

            # Check if installation was successful
            if ($installResult.Success) {
                Write-Host "Feature '$FeatureName' has been successfully installed." -ForegroundColor Green
            } else {
                Write-Host "Failed to install feature '$FeatureName'." -ForegroundColor Red
            }

            # Check if a restart is pending
            if ($installResult.RestartNeeded -eq "Yes") {
                Write-Warning "A system restart is required for the changes to fully take effect for feature '$FeatureName'."
				$restartRequired = $true
            }
        }
    }
    catch {
        Write-Host "An error occurred while trying to install feature '$FeatureName': $($_.Exception.Message)" -ForegroundColor Red
		return $false # Installation failed
    }

	# Return the boolean value indicating whether a restart is required.
    return $restartRequired
}

function Invoke-ComputerRestart{
	<#
		.NOTES
		To skip the prompt, use '-force'
		
		.Example
		Invoke-ComputerRestart -force;
		Invoke-ComputerRestart -force -t 10;
		
	#>
	
	param(
		[Parameter(Mandatory=$false)]
		[switch]$force,
		[Parameter(Mandatory=$false)]
		$t = 6
	)
	
	#$t = 10;
	
	if($force.isPresent){
		$reboot = $true;
	}else{
		do{
			$reboot = $(
				$selection = Read-Host "Would you like to reboot this computer? [Y or N]"; 
				switch($selection){
					'Y' {$true; $loopAgain = $false; break;}
					'N' {$loopAgain = $false; Write-Host "Manually reboot this machine" -ForeGroundColor Yellow; break;}
					default {Write-Host "Please enter a Y or N `n" -ForegroundColor Yellow;$loopAgain = $true}
				}
			)
		}while($loopAgain -eq $true)
	}
	
	if($reboot){
		Write-Host "Rebooting machine in $t seconds ..." -ForeGroundColor Cyan;
		Start-Sleep -s $t;
		Restart-Computer -Force -Confirm:$false -WarningAction SilentlyContinue;
	}
}

function Check-EncryptionProgress{
	param(
        [Parameter(Position = 0, Mandatory = $true)]
		$driveLetter
    )
	
	do{
		$volume = Get-BitLockerVolume -MountPoint $driveLetter;
		Write-Progress -Activity "Encrypting volume $($volume.MountPoint)" -Status "Encryption Progress:" -PercentComplete $volume.EncryptionPercentage;
		Start-Sleep -Seconds 2;
	}until($volume.VolumeStatus -eq 'FullyEncrypted')
	
	Write-Progress -Activity "Encrypting volume $($volume.MountPoint)" -Status "Encryption Progress:" -Completed;
}

function Print-BlRecoveryPassword{
	param(
        [Parameter(Position = 0, Mandatory = $true)]
		$recoveryKeyFolderPath,
		[Parameter(Position = 1, Mandatory = $true)]
		$driveLetter
    )
	
	try{
		# Get the recovery password ID
		$recoveryKey = Get-BitLockerVolume -MountPoint $driveLetter | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
		$recoveryKeyProtectorId = $recoveryKey.KeyProtectorId;
		$recoveryKeyPassword = $recoveryKey.RecoveryPassword;
		Write-Host "`nRecovery Password ID: $recoveryKeyProtectorId";
		Write-Host "Recovery Password: $recoveryKeyPassword";
		
		$BitLockerKeyBackupTxtFileName = "$($driveLetter)_$($recoveryKeyProtectorId).txt";
		#$BitLockerKeyBackupTxtFileName = "$bitlockerDriveFileName.txt";
		Write-Host "Creating $recoveryKeyFolderPath\$BitLockerKeyBackupTxtFileName" -ForegroundColor Cyan;
		New-Item "$recoveryKeyFolderPath\$BitLockerKeyBackupTxtFileName" -type file -force | Out-Null; 
		
		# # Backup the recovery password to a secure location
		# # This example uses a file, replace path with your desired location
		# #$recoveryKeyPath = "C:\BitlockerRecoveryKey.txt";
		Write-Host "Exporting Key Protector ID and Recovery Key to $recoveryKeyFolderPath\$BitLockerKeyBackupTxtFileName" -ForeGroundColor Cyan;
	
		# msg output to text file
		$backupKeyToTxtFileMsg = "BitLocker Drive Encryption recovery key 
To verify that this is the correct recovery key, compare the start of the following identifier with the identifier value displayed on your PC.
	
Identifier:
$recoveryKeyProtectorId
	
If the above identifier matches the one displayed by your PC, then use the following key to unlock your drive.
	
Recovery Key:
$recoveryKeyPassword
	
If the above identifier doesn't match the one displayed by your PC, then this isn't the right key to unlock your drive.
	
Try another recovery key.";
		$backupKeyToTxtFileMsg | Out-File -FilePath "$recoveryKeyFolderPath\$BitLockerKeyBackupTxtFileName" -Force;
		
		Write-Host "COPY THE KEY FILE $recoveryKeyFolderPath\$BitLockerKeyBackupTxtFileName TO A LOCATION OUTSIDE THIS MACHINE" -BackGroundColor Yellow -ForeGroundColor Black;
	}catch{
		Write-Host "$_." -ForeGroundColor Red;
		Write-Host "Exiting" -ForeGroundColor Red;
		exit;
	}
}

Function Set-VmAdvParameter{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True,Position=0)]
		[string]$ESXiHostIp,
		[Parameter(Mandatory=$True,Position=1)]
		[string]$vmName
	)

	## ignore invalid host certificate
	Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null;
	
	## Virtual Machine Advanced Settings to set
	$VMAdvSettings = @{
		"devices.hotplug" = $false;	
	}

	## Connect to ESXi Host
	Try{
		Write-Host "Connecting to ESXi Host `"$ESXiHostIp`"";
		Connect-VIServer -Server $ESXiHostIp -ErrorAction Stop | Out-Null;
	}Catch{
		Write-Host "Could not connect to `"$ESXiHostIp`"...exiting script" -ForeGroundColor "Red";
		Exit;
	}

	## Collect Virtual Machine in variable for processing
	Write-Host "Checking if virtual machine exists in `"$ESXiHostIp`"";
	$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue;
	
	if($vm){
		if($vm.PowerState -eq "PoweredOff"){
			## Set Virtual Machine Advanced Settings	
			ForEach($setting in ($VMAdvSettings.GetEnumerator() | Sort Name)){
			## Pulling values for each setting specified in $VMAdvSettings
			$name = $setting.name;
			$value = $setting.value;
				## Checking to see if current setting exists
				If($asetting = $vm | Get-AdvancedSetting -Name $name){
					If($asetting.Value -eq $value){
					Write-Host "Setting `"$name`" is already configured correctly to `"$value`" on `"$vm`"" -ForeGroundColor "Green";
					}else{
						Write-Host "Setting `"$name`" to `"$value`" on `"$vm`"" -ForeGroundColor "Cyan";
						$asetting | Set-AdvancedSetting -Value $value -Confirm:$false;
					}
				}else{
					Write-Host "Setting `"$name`" does not exist on `"$vm`" ...creating setting..." -ForeGroundColor "Cyan";
					$vm | New-AdvancedSetting -Name $name -Value $value -Confirm:$false;
				}
			}
		}else{
			Write-Host "Power off the VM before setting advanced attributes. Exiting" -ForeGroundColor Red;
			exit;
		}
	}else{
		Write-Host "Could not find $vmName on `"$ESXiHostIp`"" -ForeGroundColor Red;
	}

	## Disconnect from ESXi Host
	Write-Host "`nDisconnecting from ESXi Host $ESXiHostIp";
	Disconnect-VIServer -Server $ESXiHostIp -Force -Confirm:$false;
}

if($setVmSetting.IsPresent){
	# only perform the ESXi VM setting necessary to make the drives fixed instead of removable. Exit script at the end
	Set-VmAdvParameter;
	exit;
}

# Get the script directory
$scriptPath = Split-path -parent $MyInvocation.MyCommand.Definition;
$encryptionMethod = "XtsAes256";

# Get tpm info. Get-TPM will return an object. We need the TpmPresent and TpmReady attributes
$tpmInfo = Get-TPM;
if($tpmInfo.TpmPresent -and $tpmInfo.TpmReady){
	Write-Host "TPMPresent: $($tpmInfo.TpmPresent)" -ForeGroundColor Green;
	Write-Host "TPMReady: $($tpmInfo.TpmReady)" -ForeGroundColor Green;
	# $encryptDrives = $true;
}else{
	Write-Host "A TPM is required to implement BitLocker. Please install a TPM and try again. Exiting" -ForeGroundColor Red;
	#Write-Host "NOTE: A Group Policy can be used to bypass the TPM requirement, but that is a manual process. Exiting script" -ForeGroundColor Yellow;
	exit;
}

# --- 1. OS Version Check (Server 2019 or newer) ---
# Build 17763 = Server 2019. ProductType 2/3 = Domain Controller/Member Server.
$os = Get-CimInstance Win32_OperatingSystem;
$osVersion = [version]$os.Version;
$minVersion = [version]"10.0.17763";

if ($osVersion -lt $minVersion -or $os.ProductType -eq 1) {
    Write-Host "`nERROR: This script is only for Windows Server 2019 or newer" -ForegroundColor Red;
    Write-Host "Detected: $($os.Caption) (Version $($os.Version))" -ForegroundColor Yellow;
    exit;
}

Write-Host "OS Check Passed: Running on $($os.Caption)" -ForegroundColor Green;

# --- 2. Domain Controller Detection ---
# DomainRole 4 = Backup DC, 5 = Primary DC
$computerSystem = Get-CimInstance Win32_ComputerSystem;
$isDC = $computerSystem.DomainRole -in 4, 5;

if ($isDC) {
    Write-Host "Domain Controller detected. Enabling extended installation features" -ForegroundColor Cyan;
}

# --- 3. Feature Installation Loop ---
$featuresRequired = @("BitLocker", "EnhancedStorage")
$globalRestartNeeded = $false;

foreach ($feat in $featuresRequired) {
    # Initialize basic parameters for our function
    $params = @{
        FeatureName = $feat;
    }

    # APPLY LOGIC: Only install extra subfeatures/tools if it's a DC
    # Note: We still usually want Management Tools for BitLocker on member servers too
    if ($isDC) {
        $params["IncludeManagementTools"] = $true;
        $params["IncludeAllSubFeature"] = $true;;
    } 
	# elseif ($feat -eq "BitLocker") {
        # $params["IncludeManagementTools"] = $true
    # }

    # Call your Install-WindowsServerFeature function
    $needsRestart = Install-WindowsServerFeature @params;
    
    if ($needsRestart) {
        $globalRestartNeeded = $true;
    }
}

# --- 4. Handle Necessary Restarts ---
if ($globalRestartNeeded) {
    Write-Host "`nFeature installation complete. A restart is REQUIRED before encryption can begin" -ForegroundColor Yellow;
    Invoke-ComputerRestart;
    exit; # Exit here so the user re-runs the script in a fresh post-reboot state
}

Write-Host "`nAll required features are present. Proceeding to BitLocker configuration" -ForegroundColor Green;
Write-Host "";

# by default, BitLocker uses: 
# XTS-AES-128 (-EncryptionMethod Aes128, Aes256, XtsAes128, and XtsAes256)
# Encrypts the entire volume
# software encryption (recommend by MS because certain self-encrypting drives have vulnerabilities)
# IMPORTANT! - Reboot necessary for the C drive to start the encryption process before Data drives can be automatically unlocked
# - Enable-BitLockerAutoUnlock has a strict prerequisite: the Operating System (C:) drive must be fully protected before the Data (D:) drive can be linked to it for automatic unlocking

# get all the volumes in the machine
# Get-BitLockerVolume returns an array
$md = Get-BitLockerVolume;

# Identify the OS drive letter (This won't change, so it's safe to store)
$osDrive = ($md | Where-Object { $_.VolumeType -eq "OperatingSystem" }).MountPoint

foreach($d in $md){
    $bitlockerDriveLetter = ($d.MountPoint -replace (":", ""));
    
    if($d.VolumeStatus -eq "FullyEncrypted" -and $d.ProtectionStatus -eq "On"){
        Write-Host "The $bitlockerDriveLetter volume is $($d.EncryptionPercentage) percent encrypted" -ForeGroundColor Green;
    } elseif($d.VolumeStatus -eq "EncryptionInProgress") {
        # Check-EncryptionProgress -driveLetter $bitlockerDriveLetter;
		Write-Host "Volume $bitlockerDriveLetter status: $($d.VolumeStatus) ($($d.EncryptionPercentage)%)" -ForegroundColor Green;
        continue
    } elseif($d.VolumeStatus -eq "FullyDecrypted") {
        if($d.VolumeType -eq "OperatingSystem"){
            try{
				Write-Host "Enabling Recovery Password protector for volume $bitlockerDriveLetter" -ForeGroundColor Cyan;
				Add-BitLockerKeyProtector -MountPoint $bitlockerDriveLetter -RecoveryPasswordProtector | Out-Null;
				
                Print-BlRecoveryPassword -recoveryKeyFolderPath $scriptPath -driveLetter $bitlockerDriveLetter;
				
				Write-Host "Enabling TPM protector for volume $bitlockerDriveLetter" -ForeGroundColor Cyan;
                Enable-BitLocker -MountPoint $bitlockerDriveLetter -EncryptionMethod $encryptionMethod -TpmProtector;
                
                # REBOOT REQUIRED to start OS encryption after TPM binding
				Write-Host "";
                Invoke-ComputerRestart;
            }catch{
                Write-Host "Error on OS Drive: $_" -ForeGroundColor Red; exit;
            }
        }
        
        if($d.VolumeType -eq "Data"){
            try{
				# TRIGGER DATA ENCRYPTION
				Write-Host "Enabling Recovery Password protector for volume $bitlockerDriveLetter" -ForeGroundColor Cyan;
                Enable-BitLocker -MountPoint $bitlockerDriveLetter -EncryptionMethod $encryptionMethod -RecoveryPasswordProtector | Out-Null;
				
				Print-BlRecoveryPassword -recoveryKeyFolderPath $scriptPath -driveLetter $bitlockerDriveLetter;
                
                # NOW wait for the OS drive to finish (Ensures Protection is 'On' for Auto-Unlock)
				Write-Host "Checking OS Drive ($osDrive) encryption progress to finalize security chain" -ForegroundColor Cyan;
				Check-EncryptionProgress -driveLetter $osDrive;
				
				# Now wait for encryption to finish before Auto-Unlock
                Check-EncryptionProgress -driveLetter $bitlockerDriveLetter;
				
				Write-Host "Enabling Automatic Unlock for volume $bitlockerDriveLetter" -ForeGroundColor Cyan;
                Enable-BitLockerAutoUnlock -MountPoint $bitlockerDriveLetter;
            }catch{
                Write-Host "Error on Data Drive: $_" -ForeGroundColor Red; exit;
            }
        }
    } else {
		Write-Host "Cannot determine the BitLocker status of volume $(bitlockerDriveLetter)" -ForeGroundColor Yellow;
	}
	Write-Host "`n";
}

<#
To completely disable bitlocker on all drives:
Clear-BitLockerAutoUnlock 
Get-BitLockerVolume | Disable-BitLocker
#>

exit;