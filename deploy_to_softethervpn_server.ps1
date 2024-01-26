<#  put me somewhere convenient, like "C:\ProgramData\custom_certify_the_web_scripts\deploy_to_softethervpn_server.ps1"



    command to update the tls certificate for softethervpn server:

    the script is provided the parameter $result, which contains status and details of the certificate renewal process performed by certify the web.

    # either $true or $false
    $result.IsSuccess

    # object containing all information Certify has about the saved Site
    $result.ManagedItem

    # the IIS (or other service) site ID
    $result.ManagedItem.ServerSiteId   # ex: 1, 2, 3, ...

    # the website root directory (if applicable)
    $result.ManagedItem.RequestConfig.WebsiteRootPath   # ex: "C:\inetpub\wwwroot"

    # the path to the created/renewed certificate PFX file
    $result.ManagedItem.CertificatePath   # ex: "C:\ProgramData\Certify\certes\assets\pfx\00f9e07e-83ca-4029-a173-4b704ee78996.pfx"

    # the certificate thumbprint
    $result.ManagedItem.CertificateThumbprintHash # ex: "78b1080a1bf5e7fc0bbb0c0614fc4a18932db5f9"

    # the previous certificate thumbprint
    $result.ManagedItem.CertificatePreviousThumbprintHash  # ex: "18c1060a1be5e6fc0bbb0c0614fc4a18932db5fa"

    # You can set $result.Abort to $true in a pre-request hook to prevent the certificate from
    # being requested (has no effect in post-request hooks)
    $result.Abort = $false
#>

param(
    $result,

    [String] $softethervpnServerPassword
)   

$pathOfLogFile = Join-Path $PSScriptRoot "log.txt"
$pathOfFileContainingSoftethervpnServerPassword = Join-Path $PSScriptRoot "softethervpnserverpassword.txt"

$passwordOfthePfxFile = ""
$pathOfPfxFile = $result.ManagedItem.CertificatePath

@(
    "====================================================="
    Get-Date
    "`$pathOfPfxFile: $pathOfPfxFile" 
    # $result | get-member 
    "`$result:"; $result 
    # $result.ManagedItem | get-member 
    "`$result.ManagedItem: "; $result.ManagedItem
    "`$((get-command openssl).Path: $((get-command openssl).Path)"
    "`$(openssl version): $(openssl version)"
) | Out-File $pathOfLogFile -Append



if([string]::IsNullOrEmpty($softethervpnServerPassword)){
    @(
        "softethervpnServerPassword seems not to have been "
        "passed as a parameter, so we will attempt to read "
        "it from the "
        "file: $pathOfFileContainingSoftethervpnServerPassword"     
    )  | Out-File $pathOfLogFile -Append
    $softethervpnServerPassword = get-content $pathOfFileContainingSoftethervpnServerPassword | select -first 1
} else {
     @(
        "softethervpnServerPassword was passed as a parameter, "
        "so we will not bother to try to read the password "
        "from a file." 
    )  | Out-File $pathOfLogFile -Append
}    
# $passwordOfThePemFile = "supersecretpassword"  
$passwordOfThePemFile = "$(Get-Random)"  
# "`$softethervpnServerPassword: $softethervpnServerPassword" | Out-File $pathOfLogFile -Append


$temporaryFileContainingX509Certificate = New-TemporaryFile
$temporaryFileContainingPrivateKeyPasswordProtected = New-TemporaryFile
$temporaryFileContainingPrivateKeyNotPasswordProtected = New-TemporaryFile

@(
    "`$temporaryFileContainingX509Certificate: $temporaryFileContainingX509Certificate"
    "`$temporaryFileContainingPrivateKeyPasswordProtected: $temporaryFileContainingPrivateKeyPasswordProtected"
    "`$temporaryFileContainingPrivateKeyNotPasswordProtected: $temporaryFileContainingPrivateKeyNotPasswordProtected"
) | Out-File $pathOfLogFile -Append


foreach($command in @(
    
    # Extracts the private key from a PFX to a PEM file:
    "openssl pkcs12 -provider legacy -provider default -in `"$pathOfPfxFile`" -out `"$temporaryFileContainingPrivateKeyPasswordProtected`"  -nocerts -passin `"pass:$passwordOfthePfxFile`" -passout `"pass:$passwordOfThePemFile`""
    
    # Removes the password (passphrase) from the extracted private key:
    "openssl rsa -in `"$temporaryFileContainingPrivateKeyPasswordProtected`" -out `"$temporaryFileContainingPrivateKeyNotPasswordProtected`" -passin `"pass:$passwordOfThePemFile`""
    
    #Exports the certificate (includes the public key only):
    "openssl pkcs12 -provider legacy -provider default -in `"$pathOfPfxFile`" -out `"$temporaryFileContainingX509Certificate`" -clcerts -nokeys -passin `"pass:$passwordOfthePfxFile`""
    
    <#
        regarding the "-provider legacy -provider default" arguments to openssl,
        see
        [https://stackoverflow.com/questions/76290230/parsing-pkcs-file-fails-after-upgrading-openssl-to-3-0-8].
    #>

    # installs the certificate, and private key, into the softethervpn server configuration:
    "vpncmd localhost:5555 /SERVER `"/PASSWORD:$softethervpnServerPassword`" /CMD ServerCertSet `"/LOADCERT:$temporaryFileContainingX509Certificate`" `"/LOADKEY:$temporaryFileContainingPrivateKeyNotPasswordProtected`""
)){
    @(
        "========================================================="
        "now invoking: $command" 
        #todo: mask the passwords in the log output
        Invoke-Expression $command 2>&1 | out-string 
        "`$LastExitCode : $LastExitCode"   
        "`$Error : $Error"   
    )  | Out-File $pathOfLogFile -Append
}

if($false){ #crap


    if($false){ #crap 
        # $certificate = (Get-ChildItem -Path $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored)[1]
        # Export-PfxCertificate -FilePath $pathOfPfxFile -Cert $certificate -Password $securePassword
    
    
        ## $temporaryFileContainingX509Certificate = New-TemporaryFile
        ## $temporaryFileContainingPrivateKeyPasswordProtected = New-TemporaryFile
        ## $temporaryFileContainingPrivateKeyNotPasswordProtected = New-TemporaryFile
        ## 
        ## @(
        ## 	$temporaryFileContainingX509Certificate
        ## 	$temporaryFileContainingPrivateKeyNotPasswordProtected
        ## 	$temporaryFileContainingPrivateKeyNotPasswordProtected
        ## ) | % {
        ## 	$acl = Get-Acl $_
        ## 	$acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")))
        ## 	Set-Acl -Path $_  -AclObject $acl    
        ## }
    
        # $pathOfTemporaryDirectory = (join-path $env:temp "$(new-guid)")
        # $pathOfTemporaryDirectory = (join-path $psScriptRoot "temp/$(new-guid)")
        $pathOfTemporaryDirectory = (join-path $psScriptRoot "temp/$(get-date -format "yyyyMMdd_HHmmss")--$(new-guid)")
        New-Item -ItemType Directory -Force $pathOfTemporaryDirectory | out-null
    
        $acl = Get-Acl $pathOfTemporaryDirectory
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")))
        Set-Acl -Path $pathOfTemporaryDirectory  -AclObject $acl   
    
        ## $temporaryFileContainingX509Certificate 					= (join-path $env:temp "$(new-guid)")
        ## $temporaryFileContainingPrivateKeyPasswordProtected 		= (join-path $env:temp "$(new-guid)")
        ## $temporaryFileContainingPrivateKeyNotPasswordProtected 		= (join-path $env:temp "$(new-guid)")
    
        ## $temporaryFileContainingX509Certificate 					= (join-path $pathOfTemporaryDirectory "$(new-guid)")
        ## $temporaryFileContainingPrivateKeyPasswordProtected 		= (join-path $pathOfTemporaryDirectory "$(new-guid)")
        ## $temporaryFileContainingPrivateKeyNotPasswordProtected 		= (join-path $pathOfTemporaryDirectory "$(new-guid)")
    
        $temporaryFileContainingX509Certificate 					= (join-path $pathOfTemporaryDirectory "x509Certifacte")
        $temporaryFileContainingPrivateKeyPasswordProtected 		= (join-path $pathOfTemporaryDirectory "privateKeyPasswordProtected")
        $temporaryFileContainingPrivateKeyNotPasswordProtected 		= (join-path $pathOfTemporaryDirectory "privateKeyNotPasswordProtected")
    
    
        # $temporaryFileContainingPrivateKeyNotPasswordProtected = New-Item (Join-Path $PSScriptRoot)
    
        ( "temporaryFileContainingX509Certificate: "                 + $temporaryFileContainingX509Certificate                 )  | Out-File $pathOfLogFile -Append
        ( "temporaryFileContainingPrivateKeyPasswordProtected: "     + $temporaryFileContainingPrivateKeyPasswordProtected     )  | Out-File $pathOfLogFile -Append
        ( "temporaryFileContainingPrivateKeyNotPasswordProtected: "  + $temporaryFileContainingPrivateKeyNotPasswordProtected  )  | Out-File $pathOfLogFile -Append
    
        # Export-Certificate -Cert $certificate  -FilePath $temporaryFileContainingX509Certificate.FullName -Type CERT
    
        # $env:OPENSSL_CONF = "C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"
    
    
        "`$((get-command openssl).Path: $((get-command openssl).Path)" | Out-File $pathOfLogFile -Append
    
    
        # openssl pkcs12 -in $pathOfPfxFile -out $($temporaryFileContainingPrivateKeyPasswordProtected.FullName)  -nocerts -passin "pass:$passwordOfthePfxFile" -passout "pass:$passwordOfThePemFile" 
        # openssl pkcs12 -in $pathOfPfxFile -out $temporaryFileContainingPrivateKeyPasswordProtected  -nocerts -passin "pass:$passwordOfthePfxFile" -passout "pass:$passwordOfThePemFile" 
    }
    
    

        # $pathWithinLocalCertificateStorageSystemWhereTheCertificateIsStored = "cert:\LocalMachine\My"
        # $pathOfFileContainingEncryptedSoftethervpnServerPassword = Join-Path $PSScriptRoot "softethervpnserverpassword-securestring.txt"
        # I give up on trying to secure the softethervpn server password.

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

        # #use chocoaltey to install openssl:
        # choco install OpenSSL.Light

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


    openssl pkcs12 -provider legacy -provider default -in $pathOfPfxFile -out $temporaryFileContainingPrivateKeyPasswordProtected  -nocerts -passin "pass:$passwordOfthePfxFile" -passout "pass:$passwordOfThePemFile" 2>&1 | out-string | Out-File $pathOfLogFile -Append


    # see [https://stackoverflow.com/questions/76290230/parsing-pkcs-file-fails-after-upgrading-openssl-to-3-0-8]


    ("ErrorActionPreference: "                 + $ErrorActionPreference               )  | Out-File $pathOfLogFile -Append
    $ErrorActionPreference = "SilentlyContinue"
    #powershell seems to regard any output of the program to stderr as an exception, even though it is standard practice for programs to emit informational messages on stderr.
    # To prevent powershell from getting hoo-hooed, and, in turn making certifyTheWeb think that a problem has occurred, we must set $ErrorActionPreference = "SilentlyContinue"
    # there is probably a more elegant way of dealing with this situation, but it eludes me now.
    # $resultOfOpenSslCommandToDecryptPrivateKey = openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:$passwordOfThePemFile"

    # $allOutput = & openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:$passwordOfThePemFile" 2>&1
    $allOutput =  openssl rsa -in $temporaryFileContainingPrivateKeyPasswordProtected -out $temporaryFileContainingPrivateKeyNotPasswordProtected -passin "pass:$passwordOfThePemFile" 2>&1 | out-string
    $stderr = $allOutput | ?{ $_ -is [System.Management.Automation.ErrorRecord] }
    $stdout = $allOutput | ?{ $_ -isnot [System.Management.Automation.ErrorRecord] }

    ("LastExitCode : "                 + $LastExitCode                )  | Out-File $pathOfLogFile -Append
    # ("resultOfOpenSslCommandToExtractPRivateKey: "                 + $resultOfOpenSslCommandToDecryptPrivateKey               )  | Out-File $pathOfLogFile -Append
    ("contents of the  'error' variable: "                 + $error               )  | Out-File $pathOfLogFile -Append
    ("stderr: "                 + ($stderr  | Out-String)              )  | Out-File $pathOfLogFile -Append
    ("stdout: "                 + ($stdout  | Out-String)                 )  | Out-File $pathOfLogFile -Append

    # #Removes the password (passphrase) from the extracted private key:
    # try {
        # $command = {openssl rsa -in $($temporaryFileContainingPrivateKeyPasswordProtected.FullName) -out $($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) -passin "pass:$passwordOfThePemFile" }
        
        # "command: " | Out-File $pathOfLogFile -Append
        # $command | Out-File $pathOfLogFile -Append
        
    # } catch {
        # "something went wrong " | Out-File $pathOfLogFile -Append
        # $_ | Out-File $pathOfLogFile -Append
    # }

    #Exports the certificate (includes the public key only):
    openssl pkcs12 -provider legacy -provider default -in $pathOfPfxFile -out $temporaryFileContainingX509Certificate -clcerts -nokeys -passin "pass:$passwordOfthePfxFile" 2>&1 | out-string | Out-File $pathOfLogFile -Append

    $vpnCmdCommand = "vpncmd localhost:5555 /SERVER `"/PASSWORD:$softethervpnServerPassword`" /CMD ServerCertSet `"/LOADCERT:$temporaryFileContainingX509Certificate`" `"/LOADKEY:$temporaryFileContainingPrivateKeyNotPasswordProtected`""
    "`$vpnCmdCommand: $vpnCmdCommand" | Out-File $pathOfLogFile -Append


    $stdoutDestination = New-TEmporaryFile
    $stderrDestination = New-TEmporaryFile
    @{
        FilePath = "powershell"
        ArgumentList = @(
            "-c"
            $vpnCmdCommand
        )
        RedirectStandardOutput = $stdoutDestination
        RedirectStandardError = $stderrDestination
        Wait=$True
    } |% { Start-Process  @_ } 
    Start-Sleep 1
    $resultOfVpnCmd = @(
        gc $stdoutDestination
        gc $stderrDestination
    ) -join "`n"





    # $resultOfVpnCmd = vpncmd localhost:5555 /SERVER /PASSWORD:$softethervpnServerPassword /CMD ServerCertSet /LOADCERT:$($temporaryFileContainingX509Certificate.FullName) /LOADKEY:$($temporaryFileContainingPrivateKeyNotPasswordProtected.FullName) 2>&1 |  Out-String 
    # $resultOfVpnCmd = Invoke-Expression $vpnCmdCommand 2>&1 |  Out-String 
    # $resultOfVpnCmd | Out-File $pathOfLogFile -Append
    "`$resultOfVpnCmd: $resultOfVpnCmd" | Out-File $pathOfLogFile -Append
}

#delete the leftover temporary files:
Remove-Item $temporaryFileContainingX509Certificate
Remove-Item $temporaryFileContainingPrivateKeyPasswordProtected
Remove-Item $temporaryFileContainingPrivateKeyNotPasswordProtected
