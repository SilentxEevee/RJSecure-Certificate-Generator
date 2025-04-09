README - RJSecure Certificate Generator v1.0.0

Description:
This tool generates self-signed code signing certificates using a provided request.inf file.
Extract the ZIP (RJSecure_Cert_Generator_1_0_0.zip) to any directory, edit request.inf as needed,
and run rjsecure_cert_generator.ps1 to launch the GUI.

Usage:
1. Extract RJSecure_Cert_Generator_1_0_0.zip to a folder of your choice.
2. Edit request.inf to set your desired Subject (e.g., CN=YourCompanyName).
3. Run rjsecure_cert_generator.ps1 in PowerShell.
4. In the GUI:
   - Enter Common Name (CN)
   - Click "Set Password" to securely input a password (minimum 12 characters)
   - Enter PFX Filename
   - Click "Generate"
5. The .pfx file will be created in the same directory as the script.

Security Features:
- Input validation for CN and PFX filename (alphanumeric with hyphens only)
- Secure password entry via dialog
- Restrictive file permissions on generated PFX
- Error logging to CertGeneratorLog.txt
- No hardcoded paths; uses the script directory

NIST SP 800-53 Compliance:
- CM-7: Least functionality (dynamic paths)
- IA-5: Authenticator management (SecureString for password)
- SI-10: Input validation (CN, PFX, password checks)
- SI-11: Error handling (try-catch blocks)
- SI-7: Integrity (file existence checks, permissions)

Version History:
- v1.0.0 (April 08, 2025):
  - Initial release with GUI
  - Added secure password dialog, input validation, file security
  - NIST-aligned features implemented

Requirements:
- Windows OS with PowerShell 5.1 or 7
- .NET Framework 4.5+ for Windows Forms
- request.inf file in the script directory

Support:
For issues, check CertGeneratorLog.txt in the script directory and create a ticket here on github and I will assist. 
