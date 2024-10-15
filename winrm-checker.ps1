# Logging Function
function Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Write-Host $logMessage
    $logMessage | Out-File -Append -FilePath "C:\Windows\Temp\SCCM_WinRM_Reset_Log.txt"
}

# Separator for Readability
function Add-Separation {
    Write-Host "`n==============================`n"
    "`n==============================`n" | Out-File -Append -FilePath "C:\Windows\Temp\SCCM_WinRM_Reset_Log.txt"
}

# 1. Remove Existing WinRM Configuration
function Remove-WinRMConfig {
    Log "Removing existing WinRM configuration..."

    try {
        # Restarting WinRM service to ensure it is responsive
        Log "Restarting WinRM service..."
        Restart-Service -Name winrm -Force -ErrorAction Stop
        Log "WinRM service restarted successfully."

        # Add delay to ensure stability
        Start-Sleep -Seconds 5

        # Removing existing listeners using PowerShell cmdlet
        Log "Deleting existing WinRM listeners..."
        Get-ChildItem WSMan:\localhost\Listener | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        # Verify removal of listeners
        Log "Verifying removal of WinRM listeners..."
        $listeners = Get-ChildItem WSMan:\localhost\Listener 2>&1
        if ($listeners.Count -eq 0) {
            Log "Existing WinRM listeners removed successfully."
        } else {
            Log "ERROR: Some WinRM listeners were not removed:"
            $listeners | ForEach-Object { Log $_.Name }
        }

        # Clear the network stack to ensure no conflicts
        Log "Flushing DNS and resetting network settings..."
        ipconfig /flushdns | Out-String | ForEach-Object { Log $_ }
        netsh winsock reset | Out-String | ForEach-Object { Log $_ }
        Log "Network settings reset successfully."

    } catch {
        Log "ERROR: Failed to remove WinRM configuration. Exception: $_"
    }

    Add-Separation
}

# Helper Function: Display Progress Bar with Timer
function Show-Progress {
    param (
        [string]$Activity = "Processing...",
        [int]$DurationInSeconds = 5
    )
    $counter = 0
    while ($counter -lt $DurationInSeconds) {
        Write-Host "$Activity" -NoNewline
        for ($i = 1; $i -le 10; $i++) {
            Start-Sleep -Seconds 1
            Write-Host "." -NoNewline
        }
        Write-Host "`n"
        $counter++
    }
}

# 2. Remove WinRM Firewall Rules with Continuous Progress
function Remove-WinRMFirewallRules {
    Log "Removing WinRM firewall rules for HTTP and HTTPS..."

    try {
        # Start the progress job immediately
        $progressJob = Start-Job -ScriptBlock { Show-Progress -Activity "Fetching firewall rules" }

        # Fetch all firewall rules in a background job
        $fetchJob = Start-Job -ScriptBlock {
            Get-NetFirewallRule | Where-Object {
                $_ | Get-NetFirewallPortFilter | Where-Object {
                    $_.LocalPort -in @("5985", "5986")
                }
            }
        }

        $firewallRules = Receive-Job -Job $fetchJob -Wait -AutoRemoveJob
        Stop-Job -Job $progressJob  # Stop the progress job

        if ($firewallRules.Count -gt 0) {
            foreach ($rule in $firewallRules) {
                if ($rule.Name) {
                    Log "Removing firewall rule: $($rule.DisplayName)"
                    Remove-NetFirewallRule -Name $rule.Name -Confirm:$false
                } else {
                    Log "ERROR: Rule name is null. Skipping removal."
                }
            }

            # Start progress for verification
            $progressVerifyJob = Start-Job -ScriptBlock { Show-Progress -Activity "Verifying firewall rule removal" }

            # Verify removal
            $verifyJob = Start-Job -ScriptBlock {
                Get-NetFirewallRule | Where-Object {
                    $_ | Get-NetFirewallPortFilter | Where-Object {
                        $_.LocalPort -in @("5985", "5986")
                    }
                }
            }

            $remainingRules = Receive-Job -Job $verifyJob -Wait -AutoRemoveJob
            Stop-Job -Job $progressVerifyJob  # Stop the progress job

            if ($remainingRules.Count -eq 0) {
                Log "All relevant WinRM firewall rules removed successfully."
            } else {
                Log "ERROR: Some WinRM firewall rules were not removed:"
                $remainingRules | ForEach-Object { Log "Rule on port: $($_.LocalPort)" }
            }
        } else {
            Log "No matching WinRM firewall rules found."
        }
    } catch {
        Log "ERROR: Failed to remove WinRM firewall rules. Exception: $_"
    }

    Add-Separation
}

 # Remove Certificates Associated with WinRM HTTPS Listener
function Remove-WinRMCertificate {
    Log "Removing certificates associated with the WinRM HTTPS listener..."

    try {
        # Get current HTTPS listener and its certificate thumbprint
        $httpsListener = Get-ChildItem WSMan:\localhost\Listener | 
                         Where-Object { $_.Keys -match "Transport=HTTPS" }

        if ($httpsListener) {
            $thumbprint = $httpsListener.CertificateThumbprint
            Log "Found HTTPS listener with certificate: $thumbprint"

            # Check if the certificate exists in the local machine store
            $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | 
                    Where-Object { $_.Thumbprint -eq $thumbprint }

            if ($cert) {
                Log "Removing certificate with thumbprint: $thumbprint"
                $cert | Remove-Item -Force
                Log "Certificate removed successfully."
            } else {
                Log "No matching certificate found in the store for thumbprint: $thumbprint"
            }
        } else {
            Log "No HTTPS listener found. Skipping certificate removal."
        }
    } catch {
        Log "ERROR: Failed to remove WinRM certificate. Exception: $_"
    }

    Add-Separation
}

# 4. Reconfigure WinRM Settings
function Configure-WinRM {
    Log "Configuring WinRM..."
    try {
        winrm quickconfig -q
        Log "WinRM configuration completed successfully."
    } catch {
        Log "ERROR: Failed to configure WinRM. Exception: $_"
    }
    Add-Separation
}

# 4.1 Create HTTPS Listener with New Certificate
function Configure-WinRMHTTPSListener {
    Log "Creating new HTTPS listener for WinRM..."
    try {
        $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
            "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"
        Log "HTTPS listener configured with certificate: $($cert.Thumbprint)"
    } catch {
        Log "ERROR: Failed to create HTTPS listener. Exception: $_"
    }
    Add-Separation
}

# 4.2 Enable PowerShell Remoting
function Enable-PowershellRemoting {
    Log "Enabling PowerShell Remoting..."
    try {
        Enable-PSRemoting -Force -ErrorAction Stop
        Log "PowerShell Remoting enabled successfully."
    } catch {
        Log "ERROR: Failed to enable PowerShell Remoting. Exception: $_"
    }
    Add-Separation
}

# 4.3 Enable Firewall Rules for HTTP and HTTPS
function Create-WinRMFirewallRules {
    Log "Creating and enabling new WinRM firewall rules..."

    try {
        # Remove existing rules if they exist (clean start)
        Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WinRM*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        # Create HTTP-In rule for port 5985
        New-NetFirewallRule -DisplayName "WinRM HTTP-In" `
            -Name "WinRM-HTTP-In" -Protocol TCP -LocalPort 5985 `
            -Action Allow -Enabled True
        Log "WinRM HTTP-In rule created and enabled successfully."

        # Create HTTPS-In rule for port 5986
        New-NetFirewallRule -DisplayName "WinRM HTTPS-In" `
            -Name "WinRM-HTTPS-In" -Protocol TCP -LocalPort 5986 `
            -Action Allow -Enabled True
        Log "WinRM HTTPS-In rule created and enabled successfully."

    } catch {
        Log "ERROR: Failed to create WinRM firewall rules. Exception: $_"
    }

    Add-Separation
}

# 4.4 Set TrustedHosts
function Configure-WinRMTrustedHosts {
    Log "Setting TrustedHosts..."
    try {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Log "TrustedHosts configured to allow all connections."
    } catch {
        Log "ERROR: Failed to set TrustedHosts. Exception: $_"
    }
    Add-Separation
}

# 4.5 Restart WSMan Service
function Restart-WSMan {
    Log "Restarting WSMan service..."
    try {
        Restart-Service -Name winrm -Force -ErrorAction Stop
        Log "WSMan service restarted successfully."
    } catch {
        Log "ERROR: Failed to restart WSMan service. Exception: $_"
    }
    Add-Separation
}

# Main Function to Run All Steps
function Main {
    Remove-WinRMConfig
    Remove-WinRMFirewallRules
    Remove-WinRMCertificate
    Create-WinRMFirewallRules
    Configure-WinRM
    Configure-WinRMHTTPSListener
    Enable-PowershellRemoting
    Configure-WinRMTrustedHosts
    Restart-WSMan
    Log "WinRM Reset Script execution completed."
}

# Run the Script
Main
