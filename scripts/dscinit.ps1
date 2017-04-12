param(
    [Parameter(Mandatory = $false)]
    [string] $NodeType = '0',

    [Parameter(Mandatory = $false)]
    [string] $HgsServerPrimaryIPAddress = "10.0.0.4",

    [Parameter(Mandatory = $false)]
    [string] $HgsServerPrimaryAdminUsername = "hgsadmin",

    [Parameter(Mandatory = $false)]
    [string] $HgsServerPrimaryAdminPassword = 'Password1234',

    [Parameter(Mandatory = $true)]
    [string] $SslCertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [string] $EncryptionCertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [string] $SigningCertificateThumbprint
)

### Install Windows Features and AutoReboot
Configuration xHGSCommon
{
    LocalConfigurationManager {
        RebootNodeIfNeeded = $true
        ConfigurationMode = "ApplyOnly"
    }

    WindowsFeature HostGuardianServiceRole {
        Name = "HostGuardianServiceRole"
        IncludeAllSubFeature = $true
        Ensure = "Present"
    }
    WindowsFeature WebMgmtConsole {
        Name = "Web-Mgmt-Console"
        Ensure = "Present"
    }
    WindowsFeature WebMgmtScripts{
        Name = "Web-Scripting-Tools"
        Ensure = "Present"
    }
    WindowsFeature RSATADTools {
        Name = "RSAT-AD-Tools"
        IncludeAllSubFeature = $true
        Ensure = "Present"
    }

    WindowsFeature RSATClustering {
        Name = "RSAT-Clustering"
        IncludeAllSubFeature = $true
        Ensure = "Present"
    }

    WindowsFeature SMB1 {
        Name = "FS-SMB1"
        Ensure = "Absent"
    }

    WindowsFeature PSV2 {
        Name = "PowerShell-V2"
        Ensure = "Absent"
    }

    Script InstallGuardedFabricTools {
        SetScript = {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name GuardedFabricTools -MinimumVersion 0.2.0 -Repository PSGallery -Force -Confirm:$false
        }

        TestScript = {
            return (Get-Module GuardedFabricTools) -ne $null
        }
        
        GetScript = {
            $module = Get-Module GuardedFabricTools -ErrorAction Ignore
            $result = "NotInstalled"
            if ($module -ne $null) {
                $result = "Installed"
            }

            return @{ Result = $result }
        }
    }
} #End of xHGSCommon

Configuration xHGS
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    ### Setup primary node
    Node $AllNodes.Where{$_.Role -eq "FirstNode"}.NodeName
    {
        xHGSCommon CommonActivityFirstNode {
        }

        Log CreatingNewDomain {
            Message = "Creating New Domain";
            DependsOn = '[xHGSCommon]CommonActivityFirstNode'
        }

        Script InstallHGSServer {
            SetScript = {
                start-transcript -path ($using:Node.LogFolder + "\install1sthgsserver.log") -Append -Force
                write-verbose "HgsDomainName: $($using:Node.HgsDomainName)";
                Install-HgsServer -HgsDomainName  $($using:Node.HgsDomainName) -SafeModeAdministratorPassword (ConvertTo-SecureString $($using:Node.SafeModeAdministratorPassword) -AsPlainText -Force -Verbose)
                ### request reboot machine
                $global:DSCMachineStatus = 1
            }

            TestScript = {
                $result = $null
                $retryAttempts = 0

                Write-Verbose "Attempting to retrive domain name"
                try {
                    $result = Get-ADDomain -Current LocalComputer -ErrorAction Ignore
                }
                catch { }

                while ($result -eq $null -and $retryAttempts -lt $using:Node.MaxRetries) {
                    Write-Verbose ("Could not retrieve domain name. Retrying in 5 seconds. (Attempt {0}/{1})" -f ++$retryAttempts, $using:Node.MaxRetries)
                    Start-Sleep -Seconds $using:Node.SleepTime
                    try {
                        $result = Get-ADDomain -Current LocalComputer -ErrorAction Ignore
                    }
                    catch { }
                }

                return ($result -ne $null)
            }

            GetScript = {
                $result = (Get-ADDomain -Current LocalComputer)
                return  @{
                    Result = $result
                }
            }
        } #End of InstallHgsServer

        Script InitializeHgsServer {
            DependsOn = '[Script]InstallHGSServer'

            SetScript = {
                start-transcript -path ($using:Node.LogFolder + "\initialize1sthgsserver.log") -Append -Force
                
                # Clear the configuration first in case any remnants from a previous initialization attempt exist
                Write-Verbose "Clearing the HGS configuration to ensure a clean state."
                Clear-HgsServer -Force -Confirm:$false


                write-verbose "Initializing HgsServer : $($using:Node.HgsDomainName)";

                if (-not (Get-PSDrive -Name AD -ErrorAction Ignore)) {
                    New-PSDrive -Name AD -PSProvider ActiveDirectory -Root //RootDSE/
                }

                Initialize-HgsServer   -HgsServiceName  $using:Node.HgsServiceName -TrustTpm `
                                        -EncryptionCertificateThumbprint  $using:Node.EncryptionCertificateThumbprint `
                                        -SigningCertificateThumbprint $using:Node.SigningCertificateThumbprint `
                                        -Verbose
                Set-HgsServer -Http -Https `
                                        -HttpsCertificateThumbprint $using:Node.HttpsCertificateThumbprint `
                                        -Confirm:$false -Verbose

                # Grant the gMSA rights to the certificate private keys
                $gmsa = Get-ADServiceAccount -Filter { Name -like "HGSSVC*" }
                Import-Module GuardedFabricTools

                $certThumbs = @( $using:Node.EncryptionCertificateThumbprint, $using:Node.SigningCertificateThumbprint)
                $certThumbs | ForEach-Object {
                    $cert = Get-Item (Join-Path Cert:\LocalMachine\My $_)
                    $cert.Acl = $cert.Acl | Add-AccessRule $gmsa.SamAccountName Read Allow
                }
            }

            TestScript = {
                $urls = @("http://localhost/Attestation/getinfo", "http://localhost/KeyProtection/service/metadata/2014-07/metadata.xml")

                # First, check if the KPS Web App is even registered
                if (-not (Get-WebApplication -Name KeyProtection -ErrorAction Ignore) -or -not (Get-WebApplication -Name Attestation -ErrorAction Ignore)) {
                    Write-Verbose "KPS Web App not registered, HGS is not initialized"
                    return $false
                }


                $result = $true
                $retryAttempts = 0

                Write-Verbose "Checking HGS web service availability"
                foreach ($url in $urls) {
                    try {
                        $response = [System.Net.WebRequest]::Create($url).GetResponse();
                        Write-verbose ($url + " - Response Status Code: " + $response.StatusCode)

                        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                            $result = $false
                        }
                    }
                    catch {
                        $result = $false
                    }
                }

                while ($result -eq $false -and $retryAttempts -lt $using:Node.MaxRetries) {
                    Write-Verbose ("Could not retrieve domain name. Retrying in 5 seconds. (Attempt {0}/{1})" -f ++$retryAttempts, $using:Node.MaxRetries)
                    Start-Sleep -Seconds $using:Node.SleepTime
                    
                    foreach ($url in $urls) {
                        try {
                            $response = [System.Net.WebRequest]::Create($url).GetResponse();
                            Write-verbose ($url + " - Response Status Code: " + $response.StatusCode)

                            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                                $result = $false
                            }
                        }
                        catch {
                            $result = $false
                        }
                    }
                }

                return $result
            }

            GetScript = {
                $result = $null
                [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Windows.HgsStore") | Out-Null
                $store = $null
                $result = [Microsoft.Windows.HgsStore.HgsReplicatedStore]::TryOpenStore("Attestation", [ref]$store)
                return  @{
                    Result = $result.ToString()
                }
            }

        } #End of Initialize-HgsServer

        Script ImportTrustedTpmCab
        {
            DependsOn = '[Script]InitializeHgsServer'

            SetScript = {
                if (-not (Test-Path C:\temp)) {
                    New-Item -ItemType Directory -Path "C:\temp" -Force
                }
                $cabFile = "C:\temp\tpm.cab"
                Invoke-WebRequest -Uri "http://tpmsec.microsoft.com/OnPremisesDHA/TrustedTPM.cab" -OutFile $cabFile

                # Validate the signature
                try {
                    $sig = Get-AuthenticodeSignature $cabFile

                    if ($sig.Status -ne 'Valid') {
                        throw 'Invalid signature on TPM cab file'
                    }
                }
                catch {
                    throw 'Invalid signature on TPM cab file'
                }

                # Expand the cab
                New-Item -ItemType Directory -Path "C:\temp\tpm" -Force
                expand.exe $cabFile "C:\temp\tpm" -F:*


                # Install the certificates
                # Requires changing working directory because path parameter does not work
                Set-Location "C:\temp\tpm"
                C:\temp\tpm\setup.ps1
            }

            TestScript = {
                return (Get-ChildItem -Path Cert:\LocalMachine\TrustedTpm_RootCA).Count -gt 0
            }

            GetScript = {
                return @{ Result = (Get-ChildItem -Path Cert:\LocalMachine\TrustedTpm_RootCA).Count.ToString() }
            }
        }

        Registry KpsCmdletProtocol
        {
            DependsOn = '[Script]InitializeHgsServer'
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\HGS\KPS"
            ValueName = "Protocol"
            ValueData = "Http"
            ValueType = "String"
            Force = $true
        }
    } #End of Node

    ### Setup Additional Node
    Node $AllNodes.Where{$_.Role -eq "SecondNode"}.NodeName
    {
        xHGSCommon CommonActivitySecondNode {
        }

        WaitForAny WaitForADOnPrimaryToReady {
            NodeName = $Node.HgsServerPrimaryIPAddress
            ResourceName = "[Script]InitializeHgsServer"
            RetryCount = 2 * 60
            RetryIntervalSec = 30
            DependsOn = '[xHGSCommon]CommonActivitySecondNode'
        }

        Log ADOnPrimaryReady {
            DependsOn = '[WaitForAny]WaitForADOnPrimaryToReady'
            Message = "AD Ready on : $Node.HgsServerPrimaryIPAddress "
        }

        Script ChangeDNSAddress {
            DependsOn = '[WaitForAny]WaitForADOnPrimaryToReady'
            SetScript = {
                write-verbose "HgsServerPrimaryIPAddress: $($using:Node.HgsServerPrimaryIPAddress)"
                $netipconfig = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
                $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $netipconfig.InterfaceIndex | Where-Object {$_.AddressFamily -eq "2"}
                Set-DnsClientServerAddress -InterfaceIndex $dnsclientAddress.InterfaceIndex -ServerAddresses "$($using:Node.HgsServerPrimaryIPAddress)"
            }

            TestScript = {
                $netipconfig = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
                $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $netipconfig.InterfaceIndex | Where-Object {$_.AddressFamily -eq "2"}
                return  $dnsclientAddress.ServerAddresses.Contains("$($using:Node.HgsServerPrimaryIPAddress)")
            }

            GetScript = {
                $netipconfig = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
                Write-Verbose $netipconfig
                $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $($netipconfig.InterfaceIndex) | Where-Object {$_.AddressFamily -eq "2"}
                return @{ Result = $dnsclientAddress.ToString() }
            }
        }

        Script InstallHGSServerSecondary {
            DependsOn = '[script]ChangeDNSAddress'

            SetScript = {
                start-transcript -path ($using:Node.LogFolder + "\install2ndhgsserver.log") -Append -Force
                write-verbose "HgsDomainName: $($using:Node.HgsDomainName)";
                Install-HgsServer  -HgsDomainName  $($using:Node.HgsDomainName)  `
                                        -SafeModeAdministratorPassword (ConvertTo-SecureString $($using:Node.SafeModeAdministratorPassword) -AsPlainText -Force) `
                                        -HgsDomainCredential (new-object -typename System.Management.Automation.PSCredential -argumentlist "$($using:Node.HgsDomainName)\$($using:Node.HgsServerPrimaryAdminUsername)", (ConvertTo-SecureString ($($using:Node.HgsServerPrimaryAdminPassword )) -AsPlainText -Force))
                ### request reboot machine
                $global:DSCMachineStatus = 1
            }

            TestScript = {
                $result = $null
                $retryAttempts = 0

                Write-Verbose "Attempting to retrive domain name"
                try {
                    $result = Get-ADDomain -Current LocalComputer -ErrorAction Ignore
                }
                catch { }

                while ($result -eq $null -and $retryAttempts -lt $using:Node.MaxRetries) {
                    Write-Verbose ("Could not retrieve domain name. Retrying in 5 seconds. (Attempt {0}/{1})" -f ++$retryAttempts, $using:Node.MaxRetries)
                    Start-Sleep -Seconds $using:Node.SleepTime
                    try {
                        $result = Get-ADDomain -Current LocalComputer -ErrorAction Ignore
                    }
                    catch { }
                }

                return ($result -ne $null)
            }

            GetScript = {
                $result = (Get-ADDomain -Current LocalComputer)
                return  @{
                    Result = $result.DistinguishedName
                }
            }
        } #End of Intall HgsServer

        Script InitializeHgsServerSecondary {
            DependsOn = '[Script]InstallHGSServerSecondary'
            SetScript = {
                start-transcript -path ($using:Node.LogFolder + "\initialize2ndhgsserver.log") -Append -Force

                # First, clear the node in case there was an incomplete install before
                Write-Verbose "Clearing the HGS configuration to ensure a clean state."
                Clear-HgsServer -Confirm:$false



                $cred = (new-object -typename System.Management.Automation.PSCredential -argumentlist "$($using:Node.HgsDomainName)\$($using:Node.HgsServerPrimaryAdminUsername)", (ConvertTo-SecureString ($($using:Node.HgsServerPrimaryAdminPassword )) -AsPlainText -Force))
                $sig = @'
                                [DllImport("advapi32.dll", SetLastError = true)]
                                public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
                                [DllImport("kernel32.dll")]
                                public static extern Boolean CloseHandle(IntPtr hObject);
'@

                $ImpersonateLib = Add-Type -PassThru -Namespace 'Lib.Impersonation' -Name ImpersonationLib -MemberDefinition $sig
                [IntPtr] $userToken = [Security.Principal.WindowsIdentity]::GetCurrent().Token
                $userToken
                $bLogin = $ImpersonateLib::LogonUser($cred.GetNetworkCredential().UserName, $cred.GetNetworkCredential().Domain, $cred.GetNetworkCredential().Password, 9, 0, [ref]$userToken)

                if ($bLogin) {
                    $Identity = New-Object Security.Principal.WindowsIdentity $userToken
                    $context = $Identity.Impersonate()
                }
                else {
                    throw "Can't get Impersonate Token from DSC toLogon as User $cred.GetNetworkCredential().UserName."
                }

                $_HttpsCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.HttpsCertificatePassword)" -Force
                $_EncryptionCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.EncryptionCertificatePassword)" -Force
                $_SigningCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.SigningCertificatePassword)" -Force
                if ([boolean]::Parse("$($using:Node.GenerateSelfSignedCertificate)")) {
                    if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | Where-Object {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null) {
                        ### https cert need be imported to root store
                        $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.HttpsCertificatePath))).replace(":", "$")) -Password $_HttpsCertificatePassword
                        $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\root -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.HttpsCertificatePath))).replace(":", "$")) -Password $_HttpsCertificatePassword
                    }
                }
                else {
                    if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | Where-Object {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null) {
                        ### https cert need be imported to root store
                        $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath $($using:Node.HttpsCertificatePath) -Password $_HttpsCertificatePassword
                        $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\root -FilePath $($using:Node.HttpsCertificatePath) -Password $_HttpsCertificatePassword
                    }
                }

                [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($httpsCert)
                [System.Security.Cryptography.CngKey] $key = $rsa.Key
                Write-Verbose "https Private key is located at $($key.UniqueName)"
                $httpsCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                $acl = Get-Acl -Path $httpsCertPath
                $permission = "Authenticated Users", "FullControl", "Allow"
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
                $acl.AddAccessRule($accessRule)
                Set-Acl $httpsCertPath $acl

                Initialize-HgsServer -HgsServerIPAddress $($using:Node.HgsServerPrimaryIPAddress) -Verbose -Confirm:$false

                Set-HgsServer -Http -Https -HttpPort $($using:Node.HttpPort ) `
                                                -HttpsPort $($using:Node.HttpsPort ) `
                                                -HttpsCertificateThumbprint $httpsCert.thumbprint `
                                                -Confirm:$false -Verbose

                if ([boolean]::Parse("$($using:Node.GenerateSelfSignedCertificate)")) {
                    if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | Where-Object {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null) {
                        $encryptionCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.EncryptionCertificatePath))).replace(":", "$")) -Password $_EncryptionCertificatePassword
                    }

                    if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | Where-Object {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null) {
                        $signingCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.SigningCertificatePath))).replace(":", "$")) -Password $_SigningCertificatePassword
                    }
                }
                else {
                    if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | Where-Object {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null) {
                        $encryptionCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.EncryptionCertificatePath)" -Password $_EncryptionCertificatePassword
                    }

                    if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | Where-Object {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null) {
                        $signingCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.SigningCertificatePath)" -Password $_SigningCertificatePassword
                    }
                }

                [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($encryptionCert)
                [System.Security.Cryptography.CngKey] $key = $rsa.Key
                Write-Verbose "encryptionCert Private key is located at $($key.UniqueName)"
                $encryptionCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                $acl = Get-Acl -Path $encryptionCertPath
                $permission = "Authenticated Users", "FullControl", "Allow"
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
                $acl.AddAccessRule($accessRule)
                Set-Acl $encryptionCertPath $acl

                [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($SigningCert)
                [System.Security.Cryptography.CngKey] $key = $rsa.Key
                Write-Verbose "SigningCert Private key is located at $($key.UniqueName)"
                $SigningCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                $acl = Get-Acl -Path $SigningCertPath
                $permission = "Authenticated Users", "FullControl", "Allow"
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
                $acl.AddAccessRule($accessRule)
                Set-Acl $SigningCertPath $acl
            }

            TestScript = {
                $urls = @("http://localhost/Attestation/getinfo", "http://localhost/KeyProtection/service/metadata/2014-07/metadata.xml")

                # First, check if the KPS Web App is even registered
                if (-not (Get-WebApplication -Name KeyProtection -ErrorAction Ignore) -or -not (Get-WebApplication -Name Attestation -ErrorAction Ignore)) {
                    Write-Verbose "KPS Web App not registered, HGS is not initialized"
                    return $false
                }

                # Next, check if Get-HgsServer succeeds
                try {
                    $null = Get-HgsServer -ErrorAction Ignore
                }
                catch {
                    return $false
                }

                # Finally, check if the web APIs respond
                $result = $true
                $retryAttempts = 0

                Write-Verbose "Checking HGS web service availability"
                foreach ($url in $urls) {
                    try {
                        $response = [System.Net.WebRequest]::Create($url).GetResponse();
                        Write-verbose ($url + " - Response Status Code: " + $response.StatusCode)

                        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                            $result = $false
                        }
                    }
                    catch {
                        $result = $false
                    }
                }

                while ($result -eq $false -and $retryAttempts -lt $using:Node.MaxRetries) {
                    Write-Verbose ("Could not retrieve domain name. Retrying in 5 seconds. (Attempt {0}/{1})" -f ++$retryAttempts, $using:Node.MaxRetries)
                    Start-Sleep -Seconds $using:Node.SleepTime
                    
                    foreach ($url in $urls) {
                        try {
                            $response = [System.Net.WebRequest]::Create($url).GetResponse();
                            Write-verbose ($url + " - Response Status Code: " + $response.StatusCode)

                            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                                $result = $false
                            }
                        }
                        catch {
                            $result = $false
                        }
                    }
                }

                return $result
            }

            GetScript = {
                $result = Get-HgsServer
                return @{ Result = $result.KeyProtectionUrl[0].DnsSafeHost }
            }
        } #End of Initialize-HgsServer

        Registry KpsCmdletProtocol
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\HGS\KPS"
            ValueName = "Protocol"
            ValueData = "Http"
            ValueType = "String"
            Force = $true
        }
    }#End of Node
} #End of Configuration

$ConfigData = @{
    AllNodes = 
    @(
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword = $true
            DebugMode = $true
            HgsDomainName = 'cloudhgs.local'
            SafeModeAdministratorPassword = $HgsServerPrimaryAdminPassword
            HgsServiceName = 'service'
            SslCertificateThumbprint = $SslCertificateThumbprint
            EncryptionCertificateThumbprint = $EncryptionCertificateThumbprint
            SigningCertificateThumbprint = $SigningCertificateThumbprint
            HgsServerPrimaryIPAddress = $HgsServerPrimaryIPAddress
            HgsServerPrimaryAdminUsername = $HgsServerPrimaryAdminUsername
            HgsServerPrimaryAdminPassword = $HgsServerPrimaryAdminPassword
            SleepTime = 5
            MaxRetries = 60
            LogFolder = (Join-Path (Get-CimInstance Win32_OperatingSystem).WindowsDirectory "\Logs\HgsServer")
        }
    );
    NonNodeData = ""
}

if ($NodeType -eq '0') {
    $_firstnode = @{
        NodeName = $env:COMPUTERNAME
        Role = "FirstNode"
    }
    $ConfigData.AllNodes += $_firstnode
}

if ($NodeType -ne '0') {
    $_secondnode = @{
        NodeName = $env:COMPUTERNAME
        Role = "SecondNode"
    }
    $ConfigData.AllNodes += $_secondnode
}

xHGS -ConfigurationData $ConfigData

### Force refresh local machine configuration
Set-DscLocalConfigurationManager -Path .\xHGS  -Force -Verbose -ComputerName $env:COMPUTERNAME

Start-DscConfiguration -Verbose -wait -Path .\xHGS -Force -ComputerName $env:COMPUTERNAME