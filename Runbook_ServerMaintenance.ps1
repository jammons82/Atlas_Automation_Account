param(
    [Parameter(Mandatory=$false)]
    [string[]]$VMList = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = "",
    
    [Parameter(Mandatory=$false)]
    [string]$CredentialName = "Clean-Winupdate",
    
    [Parameter(Mandatory=$false)]
    [hashtable]$VMResourceGroups = @{}
)

# Import required modules
Import-Module Az.Accounts
Import-Module Az.Compute

# Directories to clean
$CleanupPaths = @(
    "C:\inetpub\logs\LogFiles\*",
    "C:\Windows\SoftwareDistribution\Download\*", 
    "C:\Windows\Temp\*"
)

# Function to use Azure VM Run Command for Azure VMs
function Invoke-AzureVMCleanup {
    param(
        [string]$VMName,
        [string]$ResourceGroupName
    )
    
    Write-Output "Using Azure VM Run Command for $VMName"
    
    $cleanupScript = @"
`$paths = @('C:\inetpub\logs\LogFiles\*', 'C:\Windows\SoftwareDistribution\Download\*', 'C:\Windows\Temp\*')
`$totalCleaned = 0
`$results = @()

Write-Host "=== CLEANUP START ==="

foreach (`$path in `$paths) {
    try {
        Write-Host "Processing path: `$path"
        `$items = Get-ChildItem -Path `$path -Recurse -Force -ErrorAction SilentlyContinue
        
        if (`$items) {
            `$itemCount = (`$items | Measure-Object).Count
            `$size = (`$items | Where-Object { -not `$_.PSIsContainer } | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            if (`$size -eq `$null) { `$size = 0 }
            
            Write-Host "Found `$itemCount items totaling `$([math]::Round(`$size / 1MB, 2)) MB"
            
            # Remove items
            `$items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            `$totalCleaned += `$size
            
            `$cleanedMB = [math]::Round(`$size / 1MB, 2)
            Write-Host "CLEANED: `$path - `$cleanedMB MB (`$itemCount items)"
            `$results += "CLEANED: `$path - `$cleanedMB MB (`$itemCount items)"
        } else {
            Write-Host "EMPTY: `$path - No files found"
            `$results += "EMPTY: `$path - No files found"
        }
    } catch {
        Write-Host "ERROR: `$path - `$(`$_.Exception.Message)"
        `$results += "ERROR: `$path - `$(`$_.Exception.Message)"
    }
}

`$totalCleanedMB = [math]::Round(`$totalCleaned / 1MB, 2)
Write-Host "=== CLEANUP COMPLETE ==="
Write-Host "TOTAL_CLEANED_MB: `$totalCleanedMB"
Write-Host "=== RESULTS ==="
`$results | ForEach-Object { Write-Host `$_ }
Write-Host "=== END ==="
"@
    
    try {
        Write-Output "Executing cleanup script on $VMName..."
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $cleanupScript -ErrorAction Stop
        
        # Parse the output to extract meaningful information
        $outputText = ""
        if ($result.Value -and $result.Value[0].Message) {
            $outputText = $result.Value[0].Message
        } elseif ($result.Value) {
            $outputText = $result.Value -join "`n"
        }
        
        Write-Output "Raw Azure VM Run Command output:"
        Write-Output $outputText
        
        # Extract total cleaned MB from output
        $totalCleanedMB = 0
        if ($outputText -match "TOTAL_CLEANED_MB: ([\d.]+)") {
            $totalCleanedMB = [decimal]$matches[1]
        }
        
        # Extract individual results
        $cleanupResults = @()
        $lines = $outputText -split "`n"
        $inResults = $false
        
        foreach ($line in $lines) {
            if ($line -match "=== RESULTS ===") {
                $inResults = $true
                continue
            }
            if ($line -match "=== END ===") {
                break
            }
            if ($inResults -and $line.Trim() -ne "") {
                $cleanupResults += $line.Trim()
            }
        }
        
        return @{
            ComputerName = $VMName
            ConnectionMethod = "Azure Run Command"
            CleanupResult = @{
                Results = $cleanupResults
                TotalCleanedMB = $totalCleanedMB
                RawOutput = $outputText
            }
            Success = $true
        }
    } catch {
        Write-Error "Azure VM Run Command failed for $VMName : $($_.Exception.Message)"
        return $null
    }
}

# Function to get disk space
function Get-DiskSpaceInfo {
    param([string]$ComputerName, [string]$ConnectionMethod)
    
    $scriptBlock = {
        Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | 
        Select-Object DeviceID, 
                      @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                      @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                      @{Name="PercentFree";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
    }
    
    switch ($ConnectionMethod) {
        "WinRM" {
            try {
                return Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
            } catch {
                Write-Warning "WinRM failed for $ComputerName : $($_.Exception.Message)"
                return $null
            }
        }
        "PsExec" {
            try {
                # For PsExec, we'll need to run a simpler command
                $result = & psexec \\$ComputerName -accepteula powershell.exe -Command "Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' | Select DeviceID,@{n='SizeGB';e={[math]::Round(`$_.Size/1GB,2)}},@{n='FreeSpaceGB';e={[math]::Round(`$_.FreeSpace/1GB,2)}}"
                return $result
            } catch {
                Write-Warning "PsExec failed for $ComputerName : $($_.Exception.Message)"
                return $null
            }
        }
        "SSH" {
            # For SSH, we'd need different commands (assuming Windows with SSH)
            Write-Warning "SSH disk space check not implemented for Windows VMs"
            return $null
        }
    }
}

# Function to perform cleanup
function Invoke-VMCleanup {
    param(
        [string]$ComputerName,
        [string]$ConnectionMethod,
        [PSCredential]$Creds
    )
    
    Write-Output "Starting cleanup for $ComputerName using $ConnectionMethod"
    
    # Get initial disk space
    $initialSpace = Get-DiskSpaceInfo -ComputerName $ComputerName -ConnectionMethod $ConnectionMethod
    
    $cleanupScript = {
        param($paths)
        
        $totalCleaned = 0
        $totalItems = 0
        $results = @()
        
        foreach ($path in $paths) {
            try {
                Write-Output "Processing path: $path"
                
                # Get items to be deleted and calculate size
                $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                if ($items) {
                    $itemCount = ($items | Measure-Object).Count
                    $sizeBeforeCleanup = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    if ($sizeBeforeCleanup -eq $null) { $sizeBeforeCleanup = 0 }
                    
                    Write-Output "Found $itemCount items totaling $([math]::Round($sizeBeforeCleanup / 1MB, 2)) MB"
                    
                    # Perform cleanup
                    $items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    
                    $totalCleaned += $sizeBeforeCleanup
                    $totalItems += $itemCount
                    $cleanedMB = [math]::Round($sizeBeforeCleanup / 1MB, 2)
                    
                    $results += "CLEANED: $path - $cleanedMB MB ($itemCount items)"
                    Write-Output "Cleaned $cleanedMB MB from $path"
                } else {
                    $results += "EMPTY: $path - No files found"
                    Write-Output "No files found in $path"
                }
            } catch {
                $results += "ERROR: $path - $($_.Exception.Message)"
                Write-Warning "Failed to clean $path : $($_.Exception.Message)"
            }
        }
        
        return @{
            Results = $results
            TotalCleanedMB = [math]::Round($totalCleaned / 1MB, 2)
            TotalItems = $totalItems
        }
    }
    
    # Execute cleanup based on connection method
    $cleanupResult = $null
    switch ($ConnectionMethod) {
        "WinRM" {
            $cleanupResult = $null
            try {
                Write-Output "Attempting WinRM connection to $ComputerName..."
                
                if ($Creds) {
                    $cleanupResult = Invoke-Command -ComputerName $ComputerName -Credential $Creds -ScriptBlock $cleanupScript -ArgumentList (,$CleanupPaths) -ErrorAction Stop
                } else {
                    $cleanupResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock $cleanupScript -ArgumentList (,$CleanupPaths) -ErrorAction Stop
                }
                
                if ($cleanupResult) {
                    Write-Output "WinRM connection successful - cleanup completed for $ComputerName"
                } else {
                    return $null
                }
            } catch {
                return $null
            }
        }
        
        "PsExec" {
            try {
                Write-Output "Attempting PsExec cleanup for $ComputerName"
                
                # Create a temporary script file for PsExec execution
                $tempScript = "cleanup_temp_$(Get-Random).ps1"
                $scriptContent = @"
`$paths = @('$($CleanupPaths -join "','")')
`$totalCleaned = 0
`$totalItems = 0

foreach (`$path in `$paths) {
    try {
        Write-Host "Processing path: `$path"
        `$items = Get-ChildItem -Path `$path -Recurse -Force -ErrorAction SilentlyContinue
        if (`$items) {
            `$itemCount = (`$items | Measure-Object).Count
            `$size = (`$items | Where-Object { -not `$_.PSIsContainer } | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            if (`$size -eq `$null) { `$size = 0 }
            `$items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            `$totalCleaned += `$size
            `$totalItems += `$itemCount
            `$cleanedMB = [math]::Round(`$size / 1MB, 2)
            Write-Host "CLEANED: `$path - `$cleanedMB MB (`$itemCount items)"
        } else {
            Write-Host "EMPTY: `$path - No files found"
        }
    } catch {
        Write-Host "ERROR: `$path - `$(`$_.Exception.Message)"
    }
}
Write-Host "TOTAL_CLEANED_MB: `$([math]::Round(`$totalCleaned / 1MB, 2))"
Write-Host "TOTAL_ITEMS: `$totalItems"
"@
                Set-Content -Path $tempScript -Value $scriptContent
                
                # Use credentials with PsExec if available
                if ($Creds) {
                    $username = $Creds.UserName
                    $password = $Creds.GetNetworkCredential().Password
                    $result = & psexec \\$ComputerName -u $username -p $password -accepteula -c $tempScript powershell.exe -ExecutionPolicy Bypass -File $tempScript
                } else {
                    $result = & psexec \\$ComputerName -accepteula -c $tempScript powershell.exe -ExecutionPolicy Bypass -File $tempScript
                }
                
                # Clean up temp script
                Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
                
                # Parse results
                $totalCleanedMB = 0
                $totalItems = 0
                $cleanupResults = @()
                
                foreach ($line in $result) {
                    if ($line -match "TOTAL_CLEANED_MB: ([\d.]+)") {
                        $totalCleanedMB = [decimal]$matches[1]
                    } elseif ($line -match "TOTAL_ITEMS: (\d+)") {
                        $totalItems = [int]$matches[1]
                    } elseif ($line -match "^(CLEANED|EMPTY|ERROR):") {
                        $cleanupResults += $line
                    }
                }
                
                Write-Output "PsExec cleanup completed for $ComputerName"
                return @{ 
                    Results = $cleanupResults
                    TotalCleanedMB = $totalCleanedMB
                    TotalItems = $totalItems
                    Method = "PsExec" 
                }
            } catch {
                Write-Warning "PsExec cleanup failed for $ComputerName : $($_.Exception.Message)"
                return $null
            }
        }
        
        "SSH" {
            try {
                Write-Output "Attempting SSH connection to $ComputerName..."
                # Assuming SSH to Windows with PowerShell available
                foreach ($path in $CleanupPaths) {
                    $escapedPath = $path -replace "'", "''"
                    if ($Creds) {
                        # For SSH with credentials, we'd typically use key-based auth or interactive
                        # This is a basic example - SSH with password requires additional setup
                        Write-Output "SSH with explicit credentials not fully implemented - using current context"
                        $sshCommand = "powershell.exe -Command `"Get-ChildItem -Path '$escapedPath' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue; Write-Host 'Cleaned $escapedPath'`""
                    } else {
                        $sshCommand = "powershell.exe -Command `"Get-ChildItem -Path '$escapedPath' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue; Write-Host 'Cleaned $escapedPath'`""
                    }
                    
                    Write-Output "Running SSH command for path: $path"
                    $result = ssh $ComputerName $sshCommand
                    Write-Output "SSH result: $result"
                }
                Write-Output "[SUCCESS] SSH connection successful - cleanup completed for $ComputerName"
                return @{ Results = @("SSH cleanup completed"); TotalCleanedMB = 0; Method = "SSH" }
            } catch {
                Write-Output "[FAILED] SSH connection failed for $ComputerName - $($_.Exception.Message)"
                return $null
            }
        }
    }
    
    # Get final disk space
    $finalSpace = Get-DiskSpaceInfo -ComputerName $ComputerName -ConnectionMethod $ConnectionMethod
    
    return @{
        ComputerName = $ComputerName
        ConnectionMethod = $ConnectionMethod
        CleanupResult = $cleanupResult
        InitialSpace = $initialSpace
        FinalSpace = $finalSpace
    }
}

# Function to test connectivity and determine best connection method
function Test-VMConnectivity {
    param([string]$ComputerName, [PSCredential]$Credential = $null, [string]$VMType = "OnPremises")
    
    $connectionMethods = @()
    
    # Test WinRM
    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        $connectionMethods += "WinRM"
    } catch {
        # Silently skip WinRM if not available
    }
    
    # Test if PsExec is available
    try {
        $psexecPath = Get-Command "psexec" -ErrorAction SilentlyContinue
        if ($psexecPath) {
            $connectionMethods += "PsExec"
        }
    } catch {
        # Silently skip PsExec if not available
    }
    
    # Test SSH
    try {
        if (Test-NetConnection -ComputerName $ComputerName -Port 22 -InformationLevel Quiet -ErrorAction Stop) {
            $connectionMethods += "SSH"
        }
    } catch {
        # Silently skip SSH if not available
    }
    
    return $connectionMethods
}

# Main execution
try {
    Write-Output "Starting VM Cleanup Automation Runbook"
    Write-Output "Cleanup paths: $($CleanupPaths -join ', ')"
    
    # Check for required tools
    Write-Output "`n=== TOOL AVAILABILITY CHECK ==="
    
    # Check for PsExec
    $psexecAvailable = Get-Command "psexec" -ErrorAction SilentlyContinue
    if ($psexecAvailable) {
        Write-Output "[AVAILABLE] PsExec found at: $($psexecAvailable.Source)"
    } else {
        Write-Output "[NOT FOUND] PsExec not found in PATH"
    }
    
    # Check for SSH client
    $sshAvailable = Get-Command "ssh" -ErrorAction SilentlyContinue
    if ($sshAvailable) {
        Write-Output "[AVAILABLE] SSH client found at: $($sshAvailable.Source)"
    } else {
        Write-Output "[NOT FOUND] SSH client not found in PATH"
    }
    
    Write-Output "========================`n"
    
    # Get credentials from Azure Automation Credential asset
    $Credential = $null
    if ($CredentialName) {
        try {
            $Credential = Get-AutomationPSCredential -Name $CredentialName
            Write-Output "Retrieved credentials for: $($Credential.UserName)"
            Write-Output "Credential domain: $($Credential.GetNetworkCredential().Domain)"
            Write-Output "Credential username: $($Credential.GetNetworkCredential().UserName)"
            
            # Test if password is retrieved (don't log the actual password)
            $pwdLength = $Credential.GetNetworkCredential().Password.Length
            Write-Output "Password retrieved: $($pwdLength -gt 0) (Length: $pwdLength chars)"
            
        } catch {
            Write-Warning "Failed to retrieve credential '$CredentialName': $($_.Exception.Message)"
            Write-Output "Continuing without explicit credentials (will use Hybrid Worker context)"
        }
    }
    
    # Connect to Azure if processing Azure VMs
    if ($VMList -or $ResourceGroupName) {
        try {
            # Connect using Managed Identity and suppress warnings
            Connect-AzAccount -Identity -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Write-Output "Connected to Azure using Managed Identity"
            
            if ($SubscriptionId) {
                Set-AzContext -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue | Out-Null
                Write-Output "Set context to subscription: $SubscriptionId"
            }
        } catch {
            Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
            throw
        }
    }
    
    # Collect all VMs to process
    $allVMs = @()
    
    # Get Azure VMs
    if ($ResourceGroupName) {
        Write-Output "Getting VMs from Resource Group: $ResourceGroupName"
        $azureVMs = Get-AzVM -ResourceGroupName $ResourceGroupName
        foreach ($vm in $azureVMs) {
            $allVMs += @{
                Name = $vm.Name
                Type = "Azure"
                ResourceGroup = $vm.ResourceGroupName
            }
        }
    } elseif ($VMList) {
        Write-Output "Getting VMs by name from VMList"
        foreach ($vmName in $VMList) {
            # Check if resource group was provided for this VM
            $resourceGroup = ""
            if ($VMResourceGroups -and $VMResourceGroups.ContainsKey($vmName)) {
                $resourceGroup = $VMResourceGroups[$vmName]
                Write-Output "Using specified Resource Group '$resourceGroup' for VM '$vmName'"
            }
            
            # Try to find the VM and its resource group if not specified
            try {
                if ($resourceGroup -eq "") {
                    Write-Output "Searching for Azure VM '$vmName' across all resource groups..."
                    # Search across all resource groups in the current subscription
                    $vm = Get-AzVM | Where-Object { $_.Name -eq $vmName } | Select-Object -First 1
                    
                    if (-not $vm) {
                        # Try searching across all accessible subscriptions
                        Write-Output "VM not found in current subscription, searching other subscriptions..."
                        $subscriptions = Get-AzSubscription
                        foreach ($sub in $subscriptions) {
                            try {
                                Set-AzContext -SubscriptionId $sub.Id | Out-Null
                                $vm = Get-AzVM | Where-Object { $_.Name -eq $vmName } | Select-Object -First 1
                                if ($vm) {
                                    Write-Output "Found Azure VM '$vmName' in subscription '$($sub.Name)'"
                                    break
                                }
                            } catch {
                                Write-Verbose "Could not search subscription $($sub.Name): $($_.Exception.Message)"
                            }
                        }
                        
                        # Set context back to original subscription if specified
                        if ($SubscriptionId) {
                            Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
                        }
                    }
                    
                    if ($vm) {
                        $resourceGroup = $vm.ResourceGroupName
                        Write-Output "Found Azure VM: $($vm.Name) in Resource Group: $($vm.ResourceGroupName)"
                    }
                } else {
                    # Verify the VM exists in the specified resource group
                    $vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName -ErrorAction SilentlyContinue
                    if ($vm) {
                        Write-Output "Verified Azure VM: $($vm.Name) in Resource Group: $resourceGroup"
                    }
                }
                
                if ($vm) {
                    $allVMs += @{
                        Name = $vmName
                        Type = "Azure"
                        ResourceGroup = $resourceGroup
                    }
                } else {
                    Write-Output "Azure VM '$vmName' not found in any accessible subscription. Adding as on-premises VM."
                    $allVMs += @{
                        Name = $vmName
                        Type = "OnPremises"
                        ResourceGroup = ""
                    }
                }
            } catch {
                Write-Warning "Error looking up VM '$vmName': $($_.Exception.Message). Adding as on-premises VM."
                $allVMs += @{
                    Name = $vmName
                    Type = "OnPremises"
                    ResourceGroup = ""
                }
            }
        }
    }
    
    Write-Output "Found $($allVMs.Count) VMs to process"
    
    # Initialize results array
    $results = @()
    
    # Process each VM
    foreach ($vm in $allVMs) {
        Write-Output "`n--- Processing VM: $($vm.Name) ---"
        
        # For Azure VMs, try Azure VM Run Command first (only if VM is running)
        if ($vm.Type -eq "Azure" -and $vm.ResourceGroup -ne "") {
            Write-Output "Attempting Azure VM Run Command for $($vm.Name) in Resource Group: $($vm.ResourceGroup)"
            
            # Check if VM is running before attempting Run Command
            try {
                $vmStatus = Get-AzVM -ResourceGroupName $vm.ResourceGroup -Name $vm.Name -Status
                $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).Code
                
                if ($powerState -eq "PowerState/running") {
                    Write-Output "VM $($vm.Name) is running, proceeding with Azure Run Command"
                    $result = Invoke-AzureVMCleanup -VMName $vm.Name -ResourceGroupName $vm.ResourceGroup
                    
                    if ($result -and $result.Success) {
                        $results += @{
                            VM = $vm.Name
                            Type = $vm.Type
                            Status = "Success"
                            Method = "Azure Run Command"
                            Result = $result
                        }
                        Write-Output "Successfully completed cleanup for $($vm.Name) using Azure Run Command"
                        continue
                    } else {
                        Write-Warning "Azure VM Run Command failed for $($vm.Name), trying other methods..."
                    }
                } else {
                    Write-Output "VM $($vm.Name) is not running (State: $powerState), skipping Azure Run Command and trying direct connection methods"
                }
            } catch {
                Write-Warning "Could not check VM status for $($vm.Name): $($_.Exception.Message). Trying other methods..."
            }
        } elseif ($vm.Type -eq "Azure" -and $vm.ResourceGroup -eq "") {
            Write-Warning "Azure VM $($vm.Name) found but Resource Group is empty. Trying direct connection methods..."
        }
        
        # Test connectivity and get available connection methods
        $availableMethods = Test-VMConnectivity -ComputerName $vm.Name -Credential $Credential -VMType $vm.Type
        
        if ($availableMethods.Count -eq 0) {
            Write-Warning "No connectivity methods available for $($vm.Name)"
            $results += @{
                VM = $vm.Name
                Type = $vm.Type
                Status = "Failed - No connectivity"
                Method = "None"
                Error = "No available connection methods"
            }
            continue
        }
        
        Write-Output "Available connection methods for $($vm.Name): $($availableMethods -join ', ')"
        
        # Try each connection method until one succeeds
        $success = $false
        $lastError = ""
        
        foreach ($method in $availableMethods) {
            Write-Output "Attempting cleanup using $method for $($vm.Name)"
            
            $result = Invoke-VMCleanup -ComputerName $vm.Name -ConnectionMethod $method -Creds $Credential
            
            # Check if the result is valid and contains actual cleanup data
            $isValidResult = $false
            if ($result -and $result.CleanupResult) {
                # Consider it successful if we have results (even if TotalCleanedMB is 0)
                if ($result.CleanupResult.Results -and $result.CleanupResult.Results.Count -gt 0) {
                    $isValidResult = $true
                } elseif ($result.CleanupResult.TotalCleanedMB -ge 0) {
                    $isValidResult = $true
                }
            }
            
            if ($isValidResult) {
                $results += @{
                    VM = $vm.Name
                    Type = $vm.Type
                    Status = "Success"
                    Method = $method
                    Result = $result
                }
                $success = $true
                Write-Output "[SUCCESS] Completed cleanup for $($vm.Name) using $method"
                break
            } else {
                $lastError = "Connection method $method returned invalid results for $($vm.Name)"
                # Don't show failed message for each method - just continue to next method silently
                continue
            }
        }
        
        if (-not $success) {
            $results += @{
                VM = $vm.Name
                Type = $vm.Type
                Status = "Failed - All methods failed"
                Method = "None"
                Error = $lastError
            }
        }
    }
    
    # Output summary
    Write-Output "`n=== CLEANUP SUMMARY ==="
    
    $successfulCleanups = @($results | Where-Object {$_.Status -eq 'Success'})
    $failedCleanups = @($results | Where-Object {$_.Status -like 'Failed*'})
    
    Write-Output "Total VMs processed: $($allVMs.Count)"
    Write-Output "Successful cleanups: $($successfulCleanups.Count)"
    Write-Output "Failed cleanups: $($failedCleanups.Count)"
    
    Write-Output "`n=== DETAILED RESULTS ==="
    foreach ($result in $results) {
        if ($result.Status -eq "Success") {
            $cleanupData = $result.Result.CleanupResult
            Write-Output "`n--- $($result.VM) ($($result.Method)) ---"
            
            if ($cleanupData -and $cleanupData.Results) {
                # Display individual path results
                foreach ($pathResult in $cleanupData.Results) {
                    Write-Output "  $pathResult"
                }
                
                # Display total
                if ($cleanupData.TotalCleanedMB -gt 0 -or ($cleanupData.TotalItems -and $cleanupData.TotalItems -gt 0)) {
                    if ($cleanupData.TotalItems) {
                        Write-Output "  TOTAL: $($cleanupData.TotalItems) items cleaned ($($cleanupData.TotalCleanedMB) MB total)"
                    } else {
                        Write-Output "  TOTAL: $($cleanupData.TotalCleanedMB) MB cleaned"
                    }
                } else {
                    Write-Output "  TOTAL: No files required cleaning"
                }
            } else {
                Write-Output "  Status: Cleanup completed (details not available)"
            }
        } else {
            Write-Output "`n--- $($result.VM) (FAILED) ---"
            Write-Output "  Status: $($result.Status)"
            if ($result.Error) {
                Write-Output "  Error: $($result.Error)"
            }
        }
    }
    
    Write-Output "`nRunbook completed successfully"
    
} catch {
    Write-Error "Runbook execution failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    throw
}
