## install nuget provider
install-packageprovider -name nuget -minimumversion 2.8.5.201 -force

## trust the psgallery
set-psrepository -name "psgallery" -installationpolicy trusted

## installed required packages (note that these must be available int he psgallery)
install-module xstorage
install-module xwebadministration
install-module xnetworking
install-module cntfsaccesscontrol
install-module xPSDesiredStateConfiguration
install-module PsDesiredStateConfiguration
install-module NetworkingDsc

## Parameters
$admWebsite = "admin.bootshearingcare.com"
$mvcWebsite = "mvc.bootshearingcare.com"


Configuration ConfigureDisk
{
    param
    (       
        [String[]]$NodeName = 'localhost',
        [String]$Drive = 'F',
        [Int]$DiskNumber = 2
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xStorage

    Node $NodeName
    {
        # Initialize disks
        xWaitforDisk Disk2
        {
            DiskId = "$DiskNumber"
            DiskIdType = 'Number'
            RetryCount = 60
            RetryIntervalSec = 60
        }

        xDisk FVolume
        {
            DiskId = "$DiskNumber"
            DriveLetter = "$Drive"
            DiskIdType = 'Number'
            FSLabel = 'Data'
        }
    }
}

Configuration ConfigureIIS
{
    param
    (       
        [String[]]$NodeName = 'localhost',
        [String]$InetpubRoot   = 'F:\inetpub'
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration, xWebAdministration, cNtfsAccessControl

    Node $NodeName
    {
        # Install features
        WindowsFeature WebServer
        {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        WindowsFeature MgmtConsole
        {
            Ensure = "Present"
            Name   = "Web-Mgmt-Console"
        }

        WindowsFeature AspNet45
        { 
            Ensure = "Present"
            Name   = "Web-Asp-Net45"
        }

        WindowsFeature HttpRedirect
        { 
            Ensure = "Present"
            Name   = "Web-Http-Redirect"
        }

        WindowsFeature DynamicCompression
        { 
            Ensure = "Present"
            Name   = "Web-Dyn-Compression"
        }

        WindowsFeature IpSecurity 
        { 
            Ensure = "Present"
            Name   = "Web-IP-Security"
        }

        WindowsFeature BasicAuth
        { 
            Ensure = "Present"
            Name   = "Web-Basic-Auth"
        }

        WindowsFeature UrlAuth
        { 
            Ensure = "Present"
            Name   = "Web-Url-Auth"
        }

        WindowsFeature WCF
        { 
            Ensure               = "Present"
            Name                 = "NET-WCF-Services45"
            IncludeAllSubFeature = $true
        }
        
        WindowsFeature WAS
        { 
            Ensure               = "Present"
            Name                 = "WAS"
            IncludeAllSubFeature = $true
        }

        # Create IIS Logs folder
        File IISLogs
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($InetpubRoot)\IISLogs"
        }

        # Grant the IIS_USRS group access to Logs
        cNtfsPermissionEntry IISLogs
        {
            Ensure    = 'Present'
            Principal = 'IIS_IUSRS'
            Path      = "$($InetpubRoot)\IISLogs"
            ItemType  = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Modify'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = '[File]IISLogs'
        }

        #Stop the default website
        xWebsite DefaultSite 
        {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            State           = 'Stopped'
            PhysicalPath    = 'C:\inetpub\wwwroot'
            DependsOn       = '[WindowsFeature]WebServer'
        }

        # Setup IIS Logs
        xIisLogging Logging
        {
            LogPath = "$($InetpubRoot)\IISLogs"
            Logflags = @('Date','Time','ClientIP','UserName','ServerIP')
            LoglocalTimeRollover = $True
            LogTruncateSize = '2097152'
            LogFormat = 'W3C'
            DependsOn = '[File]IISLogs'
        }
    }
}

Configuration CreateKenticoAdminWebsite
{
    param
    (       
        [String[]]$NodeName = 'localhost',
        [String]$WwwRoot = 'f:\inetpub\wwwroot',
        [String]$Website = 'admin-kentico.com'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xWebAdministration, cNtfsAccessControl

    $junctionlinks = "$($WwwRoot)\JunctionLinks\Admin"

    Node $NodeName
    {
        File Website
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$WwwRoot\$Website\v1.00"
        }

        File JunctionLinks
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$junctionlinks"
        }

        File AzureCache
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\AzureCache"
        }

        File AureTemp
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\AzureTemp"
        }

        File CMSFiles
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\CMSFiles"
        }

        File Media
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\Media"
        }

        File SiteAttachments
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\SiteAttachments"
        }

        File SmartSearch
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\SmartSearch"
        }

        # Create apppool
        xWebAppPool AppPool
        {
            Name                  = "$Website"
            managedRuntimeVersion = 'v4.0'
            identityType          = 'ApplicationPoolIdentity'
            Ensure                = 'Present'
            State                 = 'Started'
        }

        # Create website
        xWebsite Website
        {
            Name = "$Website"
            PhysicalPath = "$WwwRoot\$Website\v1.00"
            ApplicationPool = "$Website"
            BindingInfo = @(
                MSFT_xWebBindingInformation
                {
                    Protocol  = 'HTTP' 
                    Port      = '80'
                    IPAddress = '*'
                    HostName  = "$Website"

                }
            )
            Ensure = 'Present'
            State = 'Started'

            DependsOn = '[xWebAppPool]AppPool'
        }
        
        # Update folder permission
        cNtfsPermissionEntry Website
        {
            Ensure    = 'Present'
            Principal = 'IIS_IUSRS'
            Path      = "$WwwRoot\$Website"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Modify'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = '[File]Website'
        }

        cNtfsPermissionEntry JunctionLinks
        {
            Ensure    = 'Present'
            Principal = 'IIS_IUSRS'
            Path      = "$junctionlinks"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Modify'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = '[File]JunctionLinks'
        }
    }
}

Configuration CreateKenticoMvcWebsite
{
    param
    (       
        [String[]]$NodeName = 'localhost',
        [String]$WwwRoot = 'f:\inetpub\wwwroot',
        [String]$Website = 'mvc-kentico.com'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xWebAdministration, cNtfsAccessControl

    $junctionlinks = "$($WwwRoot)\JunctionLinks\MVC"

    Node $NodeName
    {
        File Website
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$WwwRoot\$Website\v1.00"
        }

        File JunctionLinks
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$junctionlinks"
        }

        File Media
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\Media"
        }

        File SiteAttachments
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\SiteAttachments"
        }

        File SmartSearch
        {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = "$($junctionlinks)\SmartSearch"
        }

        # Create apppool
        xWebAppPool AppPool
        {
            Name                  = "$Website"
            managedRuntimeVersion = 'v4.0'
            identityType          = 'ApplicationPoolIdentity'
            Ensure                = 'Present'
            State                 = 'Started'
        }

        # Create website
        xWebsite Website
        {
            Name = "$Website"
            PhysicalPath = "$WwwRoot\$Website\v1.00"
            ApplicationPool = "$Website"
            BindingInfo = @(
                MSFT_xWebBindingInformation
                {
                    Protocol  = 'HTTP' 
                    Port      = '80'
                    IPAddress = '*'
                    HostName  = "$Website"

                }
            )
            Ensure = 'Present'
            State = 'Started'

            DependsOn = '[xWebAppPool]AppPool'
        }
        
        # Update folder permission
        cNtfsPermissionEntry Website
        {
            Ensure    = 'Present'
            Principal = 'IIS_IUSRS'
            Path      = "$WwwRoot\$Website"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Modify'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = '[File]Website'
        }

        cNtfsPermissionEntry JunctionLinks
        {
            Ensure    = 'Present'
            Principal = 'IIS_IUSRS'
            Path      = "$junctionlinks"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Modify'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = '[File]JunctionLinks'
        }
    }
}

Configuration InboundRules
{
    Import-DSCResource -ModuleName NetworkingDsc

    Node localhost
    {
        Firewall AllowIISRemoteManagement
        {
            Name                  = 'AllowIISRemoteManagement'
            DisplayName           = 'Allow IIS Remote Management from Bastion'
            Ensure                = 'Present'
            Enabled               = 'True'
            Direction             = 'Inbound'
            LocalPort             = '8172'
            Protocol              = 'TCP'
            Description           = 'Allow IIS Remote Management from Bastion'
            RemoteAddress         = '10.0.1.0/24'
            Action                = 'Allow'
        }

        Firewall AllowWinrmBastion
        {
            Name                  = 'AllowWinrmBastion'
            DisplayName           = 'Allow Winrm from Bastion'
            Ensure                = 'Present'
            Enabled               = 'True'
            Direction             = 'Inbound'
            LocalPort             = ('5985','5986')
            Protocol              = 'TCP'
            Description           = 'Allow Winrm from Bastion'
            RemoteAddress         = '10.0.1.0/24'
            Action                = 'Allow'
        }
    }
}

Configuration WebConfig
{
  Import-DscResource -ModuleName PsDesiredStateConfiguration
  
  Node localhost
  {
    Registry IISConfig
    {
        Ensure = "Present"
        Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\InetStp\Configuration"
        ValueName = "MaxWebConfigFileSizeInKB"
        ValueData = "2000"
        ValueType = "Dword"
        Force = $true
        Hex = $false
    }
    Registry IISConfig2
    {
        Ensure = "Present"
        Key = "HKLM:\SOFTWARE\Microsoft\InetStp\Configuration"
        ValueName = "MaxWebConfigFileSizeInKB"
        ValueData = "2000"
        ValueType = "Dword"
        Force = $true
        Hex = $false
    }
  }
}

function chocoInstall 
{
    $chocoExePath = 'C:\ProgramData\Chocolatey\bin'

    if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower())) {
      echo "Chocolatey found in PATH, skipping install..."
      Exit
    }

    # Add to system PATH
    $systemPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::Machine)
    $systemPath += ';' + $chocoExePath
    [Environment]::SetEnvironmentVariable("PATH", $systemPath, [System.EnvironmentVariableTarget]::Machine)

    # Update local process' path
    $userPath = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::User)
    if($userPath) {
      $env:Path = $systemPath + ";" + $userPath
    } else {
      $env:Path = $systemPath
    }

    # Run the installer
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))

}

function choco
{

    choco install urlrewrite /y
    choco install dotnet4.7.2 /y
    #choco install dotnetcore-windowshosting /y

}

function sslHardening
{ 
    Write-Host 'Configuring IIS with SSL/TLS Deployment Best Practices...'
    Write-Host '--------------------------------------------------------------------------------'
 
    # Disable Multi-Protocol Unified Hello
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'Multi-Protocol Unified Hello has been disabled.'
 
    # Disable PCT 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'PCT 1.0 has been disabled.'
 
    # Disable SSL 2.0 (PCI Compliance)
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'SSL 2.0 has been disabled.'
 
    # NOTE: If you disable SSL 3.0 the you may lock out some people still using
    # Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
    # for these people to fall back. Safer shopping certifications may require that
    # you disable SSLv3.
    #
    # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'SSL 3.0 has been disabled.'
 
    # Disable TLS 1.0 for client and server SCHANNEL communications
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.0 has been disabled.'
 
    # Add and Disable TLS 1.1 for client and server SCHANNEL communications
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.1 has been disabled.'
 
    # Add and Enable TLS 1.2 for client and server SCHANNEL communications
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.2 has been enabled.'
 
    # Re-create the ciphers key.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
 
    # Disable insecure/weak ciphers.
    $insecureCiphers = @(
      'DES 56/56',
      'NULL',
      'RC2 128/128',
      'RC2 40/128',
      'RC2 56/128',
      'RC4 40/128',
      'RC4 56/128',
      'RC4 64/128',
      'RC4 128/128',
      'Triple DES 168'
    )
    Foreach ($insecureCipher in $insecureCiphers) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
      $key.SetValue('Enabled', 0, 'DWord')
      $key.close()
      Write-Host "Weak cipher $insecureCipher has been disabled."
    }
 
    # Enable new secure ciphers.
    # - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
    # - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
    # - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
    $secureCiphers = @(
      'AES 128/128',
      'AES 256/256'
    )
    Foreach ($secureCipher in $secureCiphers) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
      $key.close()
      Write-Host "Strong cipher $secureCipher has been enabled."
    }
 
    # Set hashes configuration.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
    $secureHashes = @(
      'SHA',
      'SHA256',
      'SHA384',
      'SHA512'
    )
    Foreach ($secureHash in $secureHashes) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
      $key.close()
      Write-Host "Hash $secureHash has been enabled."
    }
 
    # Set KeyExchangeAlgorithms configuration.
    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
    $secureKeyExchangeAlgorithms = @(
      'Diffie-Hellman',
      'ECDH',
      'PKCS'
    )
    Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
      $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
      New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
      $key.close()
      Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
    }
 
    # Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
    # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
    Write-Host 'Configure longer DHE key shares for TLS servers.'
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
    # https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
    # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
    $os = Get-WmiObject -class Win32_OperatingSystem
    if ([System.Version]$os.Version -lt [System.Version]'10.0') {
      Write-Host 'Use cipher suites order for Windows 2008/2008R2/2012/2012R2.'
      $cipherSuitesOrder = @(
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
        # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
        # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
        # - We get penalty for not using AEAD suites with RSA certificates.
        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_AES_128_CBC_SHA'
      )
    } else {
      Write-Host 'Use cipher suites order for Windows 10/2016 and later.'
      $cipherSuitesOrder = @(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
      )
    }
    $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
    # One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
    New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
    # Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
    # https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
    # New IIS functionality to help identify weak TLS usage
    # https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
    Write-Host 'Enable TLS 1.2 for .NET 3.5 and .NET 4.x'
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
      New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
      New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
      New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
      New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    }
 
    # DefaultSecureProtocols Value	Decimal value  Protocol enabled
    # 0x00000008                                8  Enable SSL 2.0 by default
    # 0x00000020                               32  Enable SSL 3.0 by default
    # 0x00000080                              128  Enable TLS 1.0 by default
    # 0x00000200                              512  Enable TLS 1.1 by default
    # 0x00000800                             2048  Enable TLS 1.2 by default
    $defaultSecureProtocols = @(
      '2048'  # TLS 1.2
    )
    $defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum
 
    # Update to enable TLS 1.2 as a default secure protocols in WinHTTP in Windows
    # https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in
 
    # Verify if hotfix KB3140245 is installed.
    $file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
    $file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
    if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
      Write-Host 'WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements.'
    } else {
      Write-Host 'WinHTTP: Minimum system requirements are met.'
      Write-Host 'WinHTTP: Activate TLS 1.2 only.'
      New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
      if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
        # WinHttp key seems missing in Windows 2019 for unknown reasons.
        New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
      }
    }
 
    Write-Host 'Windows Internet Explorer: Activate TLS 1.2 only.'
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
 
    Write-Host '--------------------------------------------------------------------------------'
    Write-Host 'NOTE: After the system has been rebooted you can verify your server'
    Write-Host '      configuration at https://www.ssllabs.com/ssltest/'
    Write-Host "--------------------------------------------------------------------------------`n"
 
    Write-Host -ForegroundColor Red 'A computer restart is required to apply settings. Restart computer now?'
    Restart-Computer -Force 
 }

ConfigureDisk -NodeName 'localhost' -Drive 'F' -DiskNumber 2
ConfigureIIS -NodeName 'localhost' -InetpubRoot 'F:\inetpub'
CreateKenticoAdminWebsite -NodeName 'localhost' -WwwRoot 'F:\inetpub\wwwroot' -Website $admWebsite 
CreateKenticoMvcWebsite -NodeName 'localhost' -WwwRoot 'F:\inetpub\wwwroot' -Website $mvcWebsite 
InboundRules
WebConfig

Start-DSCConfiguration -Path .\ConfigureDisk -Wait -Verbose -Force
Start-DSCConfiguration -Path .\ConfigureIIS -Wait -Verbose -Force
Start-DSCConfiguration -Path .\CreateKenticoAdminWebsite -Wait -Verbose -Force
Start-DSCConfiguration -Path .\CreateKenticoMvcWebsite -Wait -Verbose -Force
Start-DSCConfiguration -Path .\InboundRules -Wait -Verbose -Force
Start-DSCConfiguration -Path .\WebConfig -Wait -Verbose -Force
chocoInstall;
choco;
sslHardening;
