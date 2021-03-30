
#put me somewhere convenient, like "C:\ProgramData\custom_certify_the_web_scripts\deploy_to_softethervpn_server.ps1"

# # either $true or $false
# $result.IsSuccess

# # object containing all information Certify has about the saved Site
# $result.ManagedItem

# # the IIS (or other service) site ID
# $result.ManagedItem.ServerSiteId   # ex: 1, 2, 3, ...

# # the website root directory (if applicable)
# $result.ManagedItem.RequestConfig.WebsiteRootPath   # ex: "C:\inetpub\wwwroot"

# # the path to the created/renewed certificate PFX file
# $result.ManagedItem.CertificatePath   # ex: "C:\ProgramData\Certify\certes\assets\pfx\00f9e07e-83ca-4029-a173-4b704ee78996.pfx"

# # the certificate thumbprint
# $result.ManagedItem.CertificateThumbprintHash # ex: "78b1080a1bf5e7fc0bbb0c0614fc4a18932db5f9"

# # the previous certificate thumbprint
# $result.ManagedItem.CertificatePreviousThumbprintHash  # ex: "18c1060a1be5e6fc0bbb0c0614fc4a18932db5fa"

# # You can set $result.Abort to $true in a pre-request hook to prevent the certificate from
# # being requested (has no effect in post-request hooks)
# $result.Abort = $false





#command to update the tls certificate for softethervpn server:

#the script is provided the parameter $result, which contains status and details of the certificate renewal process performed by certify the web.
param($result, $softethervpnServerPassword)   # required to access the $result parameter


$passwordOfthePfxFile = ""
$pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored = "cert:\LocalMachine\My"
$pathOfPfxFile = $result.ManagedItem.CertificatePath
$pathOfLogFile = Join-Path $PSScriptRoot "log.txt"
# $pathOfFileContainingEncryptedSoftethervpnServerPassword = Join-Path $PSScriptRoot "softethervpnserverpassword-securestring.txt"
#I give up on trying to secure the softethervpn server password.

$pathOfFileContainingSoftethervpnServerPassword = Join-Path $PSScriptRoot "softethervpnserverpassword.txt"

"=====================================================" | Out-File $pathOfLogFile -Append
Get-Date | Out-File $pathOfLogFile -Append
$pathOfPfxFile | Out-File $pathOfLogFile -Append
# $result | get-member | Out-File $pathOfLogFile -Append
$result | Out-File $pathOfLogFile -Append
# $result.ManagedItem | get-member | Out-File $pathOfLogFile -Append
$result.ManagedItem | Out-File $pathOfLogFile -Append


# Copy-Item $pathOfPfxFile "C:\Users\njacksonadmin\Desktop\New folder\exported.pfx"



# $pathOfPfxFile = "C:\Users\njacksonadmin\Desktop\New folder\exported.pfx"
# $pathOfFileContainingEncryptedSoftethervpnServerPassword = "softethervpnserverpassword-securestring.txt"
# $pathOfLogFile = "log.txt"


# $certificate = Import-PfxCertificate -CertStoreLocation $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored -FilePath $pathOfPfxFile -Password (ConvertTo-SecureString -String $passwordOfthePfxFile -AsPlainText -Force) 
# $certificate = Import-PfxCertificate -CertStoreLocation $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored -FilePath $pathOfPfxFile  


# $certificate = (Get-ChildItem -Path $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored | Where {$_.Thumbprint -eq $result.ManagedItem.CertificateThumbprintHash})[0]
# $certificate = (Get-ChildItem -Path $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored)[0]

# Get-ChildItem -Path $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored

# cd "C:\Users\njacksonadmin\Desktop\New folder"
# $certificate | Export-PfxCertificate -FilePath $pathOfPfxFile  -Password $(ConvertTo-SecureString -String $passwordOfthePfxFile -Force -AsPlainText)

# if( $passwordOfthePfxFile.Length -eq 0 ){$securePassword = (New-Object System.Security.SecureString);} else {$securePassword = (ConvertTo-SecureString -String $passwordOfthePfxFile -AsPlainText -Force);}
# $certificate = Import-PfxCertificate -CertStoreLocation $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored -FilePath $pathOfPfxFile -Password $securePassword
# #I believe that the above call to Import-PfxCertificate will always return the certificate, even in the case that the certificate had already been imported.



#The softethervpn command to set the certificate wants an X.509-format certificate file and a base64-encoded private key file; evidently
# softethervpn server does not interact with the Windows certificate storage system.
# Therefore, we need to prepare these two files by exporting from the Windows certificate storage system.

# #install chocolatey:
# Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# #use chocolatey to install openssl:
# choco install OpenSSL.Light --confirm

#add openssl directory to system path
# Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value ((Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path + ";" + "C:\Program Files\OpenSSL\bin")
# refreshenv
# actually, it looks the installer already added openssl directory to system path.

# Install-Module -Name OpenSSL -Force -AllowClobber
# Import-Module openssl
# UnInstall-Module -Name OpenSSL -Force

#initially, to encrypt the softethervpn server password for storage in a  file:

# # # # ##   (ConvertTo-SecureString -String "TypeTheLiteralPlaintextServerPAsswordHere" -AsPlainText -Force) | convertfrom-securestring | out-file $pathOfFileContainingEncryptedSoftethervpnServerPassword
# # # # ( "pathOfFileContainingEncryptedSoftethervpnServerPassword: "                 + $pathOfFileContainingEncryptedSoftethervpnServerPassword               )  | Out-File $pathOfLogFile -Append

# # # # $encryptedSoftethervpnServerPassword = cat $pathOfFileContainingEncryptedSoftethervpnServerPassword
# # # # ( "encryptedSoftethervpnServerPassword: "                 + $encryptedSoftethervpnServerPassword               )  | Out-File $pathOfLogFile -Append

# # # # # $SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
# # # # # $secureSoftethervpnServerPassword = (cat $pathOfFileContainingEncryptedSoftethervpnServerPassword | convertto-securestring)
# # # # $secureSoftethervpnServerPassword = ($encryptedSoftethervpnServerPassword | convertto-securestring)
# # # # ( "secureSoftethervpnServerPassword: "                 + $secureSoftethervpnServerPassword               )  | Out-File $pathOfLogFile -Append
# # # # ("secureSoftethervpnServerPassword | convertfrom-securestring : " +  ($secureSoftethervpnServerPassword | convertfrom-securestring)) |  Out-File $pathOfLogFile -Append

# # # # ( "secureSoftethervpnServerPassword: "                 + $secureSoftethervpnServerPassword  | get-member             )  | Out-File $pathOfLogFile -Append
# # # # # $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSoftethervpnServerPassword)
# # # # # $softethervpnServerPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# # # # $softethervpnServerPassword = ConvertFrom-SecureString -SecureString $secureSoftethervpnServerPassword -AsPlainText 
## I give up:


if([string]::IsNullOrEmpty($softethervpnServerPassword)){
    ("softethervpnServerPassword seems not to have been passed as a parameter, so we will attempt to read it from the file. $pathOfFileContainingSoftethervpnServerPassword"     )  | Out-File $pathOfLogFile -Append
    $softethervpnServerPassword = (cat $pathOfFileContainingSoftethervpnServerPassword)
} else {
     ("softethervpnServerPassword was passed as a parameter, so we will not bother to try to read the password from a file."     )  | Out-File $pathOfLogFile -Append
}    

# ( "softethervpnServerPassword: "                 + $softethervpnServerPassword               )  | Out-File $pathOfLogFile -Append

# $certificate = (Get-ChildItem -Path $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored)[1]
# Export-PfxCertificate -FilePath $pathOfPfxFile -Cert $certificate -Password $securePassword


$temporaryFileContainingX509Certificate = New-TemporaryFile
$temporaryFileContainingPrivateKeyPasswordProtected = New-TemporaryFile
$temporaryFileContainingPrivateKeyNotPasswordProtected = New-TemporaryFile

# $temporaryFileContainingPrivateKeyNotPasswordProtected = New-Item (Join-Path $PSScriptRoot)

( "temporaryFileContainingX509Certificate: "                 + $temporaryFileContainingX509Certificate.FullName                 )  | Out-File $pathOfLogFile -Append
( "temporaryFileContainingPrivateKeyPasswordProtected: "     + $temporaryFileContainingPrivateKeyPasswordProtected.FullName     )  | Out-File $pathOfLogFile -Append
( "temporaryFileContainingPrivateKeyNotPasswordProtected: "  + $temporaryFileContainingPrivateKeyNotPasswordProtected.FullName  )  | Out-File $pathOfLogFile -Append

# Export-Certificate -Cert $certificate  -FilePath $temporaryFileContainingX509Certificate.FullName -Type CERT

#Extracts the private key from a PFX to a PEM file:
openssl pkcs12 -in $pathOfPfxFile -out $($temporaryFileContainingPrivateKeyPasswordProtected.FullName)  -nocerts -passin "pass:$passwordOfthePfxFile" -passout "pass:supersecretpassword" 2>&1
#the "2>&1" redirects stderror to stdout, and thereby prevents certify the web from thinking that an "error" has occured

("ErrorActionPreference: "                 + $ErrorActionPreference               )  | Out-File $pathOfLogFile -Append
$ErrorActionPreference = "SilentlyContinue"
#powershell seems to regard any output of the program to stderr as an exception, even though it is standard practice for programs to emit informational messages on stderr.
# To prevent powershell from getting hoo-hooed, and, in turn making certifyTheWeb think that a problem has occurred, we must set $ErrorActionPreference = "SilentlyContinue"
# there is probably a more elegant way of dealing with this situation, but it eludes me now.
# $resultOfOpenSslCommandToDecryptPrivateKey = openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:supersecretpassword"

$allOutput = & openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:supersecretpassword" 2>&1
$stderr = $allOutput | ?{ $_ -is [System.Management.Automation.ErrorRecord] }
$stdout = $allOutput | ?{ $_ -isnot [System.Management.Automation.ErrorRecord] }

("LastExitCode : "                 + $LastExitCode                )  | Out-File $pathOfLogFile -Append
# ("resultOfOpenSslCommandToExtractPRivateKey: "                 + $resultOfOpenSslCommandToDecryptPrivateKey               )  | Out-File $pathOfLogFile -Append
("contents of the  'error' variable: "                 + $error               )  | Out-File $pathOfLogFile -Append
("stderr: "                 + ($stderr  | Out-String)              )  | Out-File $pathOfLogFile -Append
("stdout: "                 + ($stdout  | Out-String)                 )  | Out-File $pathOfLogFile -Append

# #Removes the password (passphrase) from the extracted private key:
# try {
	# $command = {openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:supersecretpassword" }
	
	# "command: " | Out-File $pathOfLogFile -Append
	# $command | Out-File $pathOfLogFile -Append
	
# } catch {
	# "something went wrong " | Out-File $pathOfLogFile -Append
	# $_ | Out-File $pathOfLogFile -Append
# }

#Exports the certificate (includes the public key only):
openssl pkcs12 -in $pathOfPfxFile -out $($temporaryFileContainingX509Certificate.FullName) -clcerts -nokeys -passin "pass:$passwordOfthePfxFile" 


$resultOfVpnCmd = vpncmd localhost:5555 /SERVER /PASSWORD:$softethervpnServerPassword /CMD ServerCertSet /LOADCERT:$($temporaryFileContainingX509Certificate.FullName) /LOADKEY:$($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) |  Out-String 
$resultOfVpnCmd | Out-File $pathOfLogFile -Append

#delete the leftover temporary files:
Remove-Item $temporaryFileContainingX509Certificate.FullName
Remove-Item $temporaryFileContainingPrivateKeyPasswordProtected.FullName
Remove-Item $temporaryFileContainingPrivateKeyNotPasswordProtected.FullName
