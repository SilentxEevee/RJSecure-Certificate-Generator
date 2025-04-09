# Initialize logging in the script's directory
$workingDir = $PSScriptRoot  # Directory where the script is located
$logFile = Join-Path $workingDir "CertGeneratorLog.txt"
function Write-Log($message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Basic obfuscation
    $logMessage = "$timestamp - $message"
    $logMessage | Out-File -FilePath $logFile -Append
}

Write-Log "Script started"

# Load Windows Forms with explicit error checking
try {
    Write-Log "Attempting to load System.Windows.Forms"
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    [System.Windows.Forms.Application]::EnableVisualStyles()
    Write-Log "System.Windows.Forms loaded successfully"
}
catch {
    Write-Log "Failed to load System.Windows.Forms: $($_.Exception.Message)"
    [System.Windows.Forms.MessageBox]::Show("Failed to load Windows Forms: $($_.Exception.Message)`nCheck .NET Framework installation.", "Error", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
    exit
}

# Main script
try {
    Write-Log "Setting up working directory: $workingDir"
    $infPath = Join-Path $workingDir "request.inf"
    $cerPath = Join-Path $workingDir "codesign.cer"

    Write-Log "Creating GUI form"
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RJSecure Certificate Generator v1.0.0"
    $form.Size = New-Object System.Drawing.Size(450,350)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    # Common Name Label and TextBox
    $labelCN = New-Object System.Windows.Forms.Label
    $labelCN.Text = "Common Name (CN):"
    $labelCN.Location = New-Object System.Drawing.Point(20,20)
    $labelCN.Size = New-Object System.Drawing.Size(100,20)
    $form.Controls.Add($labelCN)

    $textBoxCN = New-Object System.Windows.Forms.TextBox
    $textBoxCN.Location = New-Object System.Drawing.Point(130,20)
    $textBoxCN.Size = New-Object System.Drawing.Size(280,20)
    # Left blank by default
    $form.Controls.Add($textBoxCN)

    # Password Button (triggers secure dialog)
    $labelPass = New-Object System.Windows.Forms.Label
    $labelPass.Text = "PFX Password:"
    $labelPass.Location = New-Object System.Drawing.Point(20,60)
    $labelPass.Size = New-Object System.Drawing.Size(100,20)
    $form.Controls.Add($labelPass)

    $buttonPass = New-Object System.Windows.Forms.Button
    $buttonPass.Text = "Set Password"
    $buttonPass.Location = New-Object System.Drawing.Point(130,60)
    $buttonPass.Size = New-Object System.Drawing.Size(100,20)
    $form.Controls.Add($buttonPass)

    # PFX Name Label and TextBox
    $labelPfx = New-Object System.Windows.Forms.Label
    $labelPfx.Text = "PFX Filename:"
    $labelPfx.Location = New-Object System.Drawing.Point(20,100)
    $labelPfx.Size = New-Object System.Drawing.Size(100,20)
    $form.Controls.Add($labelPfx)

    $textBoxPfx = New-Object System.Windows.Forms.TextBox
    $textBoxPfx.Location = New-Object System.Drawing.Point(130,100)
    $textBoxPfx.Size = New-Object System.Drawing.Size(280,20)
    $textBoxPfx.Text = "CodeSignCert"
    $form.Controls.Add($textBoxPfx)

    # Status Label
    $labelStatus = New-Object System.Windows.Forms.Label
    $labelStatus.Location = New-Object System.Drawing.Point(20,140)
    $labelStatus.Size = New-Object System.Drawing.Size(400,80)
    $labelStatus.Text = "Ready to generate certificate..."
    $form.Controls.Add($labelStatus)

    # Generate Button
    $buttonGenerate = New-Object System.Windows.Forms.Button
    $buttonGenerate.Location = New-Object System.Drawing.Point(130,240)
    $buttonGenerate.Size = New-Object System.Drawing.Size(100,30)
    $buttonGenerate.Text = "Generate"
    $form.Controls.Add($buttonGenerate)

    # Secure password dialog
    $script:password = $null
    $buttonPass.Add_Click({
        $passwordPrompt = New-Object System.Windows.Forms.Form
        $passwordPrompt.Text = "Enter PFX Password"
        $passwordPrompt.Size = New-Object System.Drawing.Size(300,150)
        $passwordPrompt.StartPosition = "CenterScreen"
        $passwordPrompt.FormBorderStyle = "FixedDialog"
        $passwordText = New-Object System.Windows.Forms.TextBox
        $passwordText.UseSystemPasswordChar = $true
        $passwordText.Location = New-Object System.Drawing.Point(50,30)
        $passwordText.Size = New-Object System.Drawing.Size(200,20)
        $passwordPrompt.Controls.Add($passwordText)
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"
        $okButton.Location = New-Object System.Drawing.Point(100,70)
        $okButton.Add_Click({
            $script:password = ConvertTo-SecureString $passwordText.Text -AsPlainText -Force
            $passwordPrompt.Close()
        })
        $passwordPrompt.Controls.Add($okButton)
        $passwordPrompt.ShowDialog()
    })

    # Button click event for Generate
    $buttonGenerate.Add_Click({
        Write-Log "Generate button clicked"
        $buttonGenerate.Enabled = $false
        $labelStatus.Text = "Generating certificate..."

        try {
            # Input validation
            if ([string]::IsNullOrWhiteSpace($textBoxCN.Text) -or $textBoxCN.Text -notmatch "^[a-zA-Z0-9\-]+$") {
                throw "Common Name must be non-empty and alphanumeric with hyphens only."
            }
            if (-not $script:password -or [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:password)).Length -lt 12) {
                throw "Password must be at least 12 characters. Click 'Set Password' to enter."
            }
            if ($textBoxPfx.Text -notmatch "^[a-zA-Z0-9\-]+$") {
                throw "PFX filename must be alphanumeric with hyphens only."
            }
            if (-not (Test-Path $infPath)) {
                throw "request.inf not found in the script directory ($workingDir). Please place it there and try again."
            }

            Write-Log "Running certreq"
            certreq -new $infPath $cerPath | Out-Null
            if (-not (Test-Path $cerPath)) {
                throw "Failed to create codesign.cer"
            }

            Write-Log "Importing certificate"
            Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\CurrentUser\My | Out-Null

            $certificate = Get-ChildItem -Path Cert:\CurrentUser\My | 
                Where-Object {$_.Subject -eq "CN=$($textBoxCN.Text)"} | 
                Sort-Object NotBefore -Descending | 
                Select-Object -First 1

            if ($certificate -eq $null) {
                throw "No certificate found with subject 'CN=$($textBoxCN.Text)'"
            }

            $pfxPath = Join-Path $workingDir "$($textBoxPfx.Text).pfx"
            if (Test-Path $pfxPath) {
                throw "PFX file already exists. Please choose a different name."
            }

            Write-Log "Exporting to PFX: $pfxPath"
            Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $script:password | Out-Null

            # Set restrictive permissions
            $acl = Get-Acl $pfxPath
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $pfxPath $acl

            Remove-Item $cerPath -Force
            $labelStatus.Text = "Success! Created $($textBoxPfx.Text).pfx`nLocation: $workingDir"
            Write-Log "Certificate generated successfully"
        }
        catch {
            $labelStatus.Text = "Error: $($_.Exception.Message)"
            Write-Log "Error during generation: $($_.Exception.Message)"
        }
        finally {
            $buttonGenerate.Enabled = $true
        }
    })

    # Show the form
    Write-Log "Showing GUI"
    [System.Windows.Forms.Application]::Run($form)
    Write-Log "GUI closed"
}
catch {
    Write-Log "Main script error: $($_.Exception.Message)"
    [System.Windows.Forms.MessageBox]::Show("Script failed: $($_.Exception.Message)", "Error", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
}
finally {
    Write-Log "Script ended"
}

