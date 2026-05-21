<#
.SYNOPSIS
    Validates Microsoft 365, Microsoft Intune, and Microsoft admin portal network access.

.DESCRIPTION
    Builds a reference list from:
    - Microsoft 365 Endpoint Web Service: https://endpoints.office.com
    - Microsoft Intune consolidated endpoint list from Microsoft Learn
    - Common Microsoft admin portals

    Validates:
    - DNS resolution
    - Direct TCP connectivity
    - TLS handshake for TCP/443
    - HTTP/HTTPS reachability when applicable
    - UDP/123 NTP test for time.windows.com

    Wildcards (*.domain.com), CIDR subnets, and placeholder URLs are exported as allowlist reference records
    but are not tested as concrete endpoints.

.NOTES
    PowerShell 5.1+ recommended.
    Run from the affected network/device.
    For proxy-only networks, DirectTcp may fail by design. Review HttpProbe/HTTPS result as well.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:TEMP\MicrosoftEndpointConnectivity",

    [ValidateSet("Worldwide", "USGovDoD", "USGovGCCHigh", "China", "Germany")]
    [string]$M365Instance = "Worldwide",

    [ValidateSet("NorthAmerica", "Europe", "AsiaPacific", "All")]
    [string]$IntuneRegion = "NorthAmerica",

    [ValidateSet("Optimize", "Allow", "Default")]
    [string[]]$M365Categories = @("Optimize", "Allow", "Default"),

    [switch]$M365RequiredOnly,

    [int]$TimeoutSeconds = 10,

    [string]$Proxy,

    [switch]$UseDefaultCredentials,

    [switch]$SkipM365,

    [switch]$SkipIntune,

    [switch]$SkipPortals,

    [switch]$SkipHttpProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$referencePath = Join-Path $OutputDirectory "MicrosoftEndpoint-AllowlistReference-$timestamp.csv"
$resultsPath   = Join-Path $OutputDirectory "MicrosoftEndpoint-ConnectivityResults-$timestamp.csv"
$jsonPath      = Join-Path $OutputDirectory "MicrosoftEndpoint-ConnectivityResults-$timestamp.json"

function ConvertTo-CleanAddress {
    param([Parameter(Mandatory)][string]$Address)

    $clean = $Address.Trim()
    $clean = $clean -replace "^https://", ""
    $clean = $clean -replace "^http://", ""
    $clean = $clean.Trim("/")
    if ($clean -match "/") {
        $clean = $clean.Split("/")[0]
    }
    return $clean.Trim()
}

function Get-EndpointKind {
    param([Parameter(Mandatory)][string]$Address)

    if ($Address -match "<.*>") { return "Placeholder" }
    if ($Address -match "\*") { return "Wildcard" }
    if ($Address -match "^[0-9a-fA-F:]+/[0-9]+$") { return "CIDR" }
    if ($Address -match "^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$") { return "CIDR" }
    if ($Address -match "^\d{1,3}(\.\d{1,3}){3}$") { return "IPAddress" }
    if ($Address -match "^[0-9a-fA-F:]+$" -and $Address -match ":") { return "IPAddress" }
    return "FQDN"
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function New-EndpointRecord {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Source,
        [string]$Category = "Required",
        [bool]$Required = $true,
        [Parameter(Mandatory)][string]$Address,
        [ValidateSet("TCP", "UDP", "Reference")]
        [string]$Protocol = "TCP",
        [int]$Port = 443,
        [string]$Notes = ""
    )

    $clean = ConvertTo-CleanAddress -Address $Address
    if ([string]::IsNullOrWhiteSpace($clean)) { return }

    [PSCustomObject]@{
        Service  = $Service
        Source   = $Source
        Category = $Category
        Required = $Required
        Address  = $clean
        Kind     = Get-EndpointKind -Address $clean
        Protocol = $Protocol
        Port     = $Port
        Notes    = $Notes
    }
}

function Get-PortsFromMicrosoft365PortString {
    param(
        [string]$PortString,
        [ValidateSet("TCP", "UDP")]
        [string]$Protocol
    )

    $ports = New-Object System.Collections.Generic.List[int]

    if ([string]::IsNullOrWhiteSpace($PortString)) {
        if ($Protocol -eq "TCP") { return @(443) }
        return @()
    }

    $pattern = "$Protocol\s*:\s*([0-9,\s]+)"
    $match = [regex]::Match($PortString, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($match.Success) {
        $match.Groups[1].Value.Split(",") | ForEach-Object {
            $item = $_.Trim()
            if ($item -match "^\d+$") {
                $ports.Add([int]$item)
            }
        }
    }

    return @($ports | Sort-Object -Unique)
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 10000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $wait) {
            return [PSCustomObject]@{ Status = "Failed"; Detail = "TCP timeout" }
        }

        $client.EndConnect($async)
        return [PSCustomObject]@{ Status = "Success"; Detail = "TCP connected" }
    }
    catch {
        return [PSCustomObject]@{ Status = "Failed"; Detail = $_.Exception.Message }
    }
    finally {
        $client.Close()
    }
}

function Test-TlsHandshake {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$TimeoutMs = 10000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $ssl = $null
    try {
        $async = $client.BeginConnect($HostName, 443, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $wait) {
            return [PSCustomObject]@{ Status = "Failed"; Detail = "TLS TCP timeout" }
        }

        $client.EndConnect($async)
        $stream = $client.GetStream()
        $ssl = New-Object System.Net.Security.SslStream($stream, $false)
        $ssl.AuthenticateAsClient($HostName)

        return [PSCustomObject]@{
            Status = "Success"
            Detail = "TLS handshake succeeded; Protocol=$($ssl.SslProtocol); Cipher=$($ssl.CipherAlgorithm)"
        }
    }
    catch {
        return [PSCustomObject]@{ Status = "Failed"; Detail = $_.Exception.Message }
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        $client.Close()
    }
}

function Invoke-EndpointWebProbe {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutSec = 10,
        [string]$ProxyUrl,
        [switch]$UseProxyDefaultCredentials
    )

    $scheme = if ($Port -eq 80) { "http" } else { "https" }
    $uri = if (($scheme -eq "https" -and $Port -eq 443) -or ($scheme -eq "http" -and $Port -eq 80)) {
        "$scheme`://$HostName/"
    } else {
        "$scheme`://$HostName`:$Port/"
    }

    $params = @{
        Uri = $uri
        Method = "Head"
        TimeoutSec = $TimeoutSec
        UseBasicParsing = $true
        ErrorAction = "Stop"
    }

    if (-not [string]::IsNullOrWhiteSpace($ProxyUrl)) {
        $params.Proxy = $ProxyUrl
        if ($UseProxyDefaultCredentials) {
            $params.ProxyUseDefaultCredentials = $true
        }
    }

    try {
        $response = Invoke-WebRequest @params
        return [PSCustomObject]@{
            Status = "Success"
            Detail = "HTTP status $($response.StatusCode)"
        }
    }
    catch {
        $response = $_.Exception.Response
        if ($response -and $response.StatusCode) {
            return [PSCustomObject]@{
                Status = "ReachableHttpError"
                Detail = "Endpoint responded with HTTP status $([int]$response.StatusCode) $($response.StatusCode)"
            }
        }

        try {
            $params.Method = "Get"
            $response = Invoke-WebRequest @params
            return [PSCustomObject]@{
                Status = "Success"
                Detail = "HTTP GET status $($response.StatusCode)"
            }
        }
        catch {
            $response = $_.Exception.Response
            if ($response -and $response.StatusCode) {
                return [PSCustomObject]@{
                    Status = "ReachableHttpError"
                    Detail = "Endpoint responded with HTTP status $([int]$response.StatusCode) $($response.StatusCode)"
                }
            }

            return [PSCustomObject]@{
                Status = "Failed"
                Detail = $_.Exception.Message
            }
        }
    }
}

function Test-NtpUdp123 {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$TimeoutMs = 10000
    )

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
        if (-not $addresses -or $addresses.Count -eq 0) {
            return [PSCustomObject]@{ Status = "Failed"; Detail = "No IP address resolved for UDP test" }
        }

        $endpoint = New-Object System.Net.IPEndPoint($addresses[0], 123)
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs

        $packet = New-Object byte[] 48
        $packet[0] = 0x1B

        [void]$udp.Send($packet, $packet.Length, $endpoint)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $reply = $udp.Receive([ref]$remote)

        if ($reply.Length -ge 48) {
            return [PSCustomObject]@{ Status = "Success"; Detail = "NTP response received from $($remote.Address)" }
        }

        return [PSCustomObject]@{ Status = "Failed"; Detail = "Unexpected NTP response length" }
    }
    catch {
        return [PSCustomObject]@{ Status = "Failed"; Detail = $_.Exception.Message }
    }
    finally {
        if ($udp) { $udp.Close() }
    }
}

function Add-EndpointRange {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Service,
        [string]$Source,
        [string]$Category,
        [bool]$Required,
        [string[]]$Addresses,
        [int[]]$TcpPorts = @(443),
        [int[]]$UdpPorts = @(),
        [string]$Notes = ""
    )

    foreach ($address in $Addresses) {
        foreach ($port in $TcpPorts) {
            $record = New-EndpointRecord -Service $Service -Source $Source -Category $Category -Required:$Required -Address $address -Protocol TCP -Port $port -Notes $Notes
            if ($record) { $List.Add($record) }
        }

        foreach ($port in $UdpPorts) {
            $record = New-EndpointRecord -Service $Service -Source $Source -Category $Category -Required:$Required -Address $address -Protocol UDP -Port $port -Notes $Notes
            if ($record) { $List.Add($record) }
        }
    }
}

$reference = New-Object System.Collections.Generic.List[object]

if (-not $SkipM365) {
    Write-Host "Collecting Microsoft 365 endpoints from endpoints.office.com..." -ForegroundColor Cyan

    $clientRequestId = [guid]::NewGuid().Guid
    $m365EndpointUri = "https://endpoints.office.com/endpoints/$M365Instance`?clientrequestid=$clientRequestId"
    $m365Data = Invoke-RestMethod -Uri $m365EndpointUri -Method Get -TimeoutSec $TimeoutSeconds

    foreach ($item in $m365Data) {
        $itemCategory = Get-ObjectPropertyValue -InputObject $item -PropertyName "category"
        if ([string]::IsNullOrWhiteSpace($itemCategory)) { continue }
        if ($itemCategory -notin $M365Categories) { continue }

        $required = $false
        $requiredRaw = Get-ObjectPropertyValue -InputObject $item -PropertyName "required"
        if ($null -ne $requiredRaw) { $required = [bool]$requiredRaw }

        if ($M365RequiredOnly -and -not $required) { continue }

        $serviceArea = Get-ObjectPropertyValue -InputObject $item -PropertyName "serviceArea"
        if ([string]::IsNullOrWhiteSpace($serviceArea)) { $serviceArea = "Unknown" }

        $service = "Microsoft 365 - $serviceArea"
        $category = $itemCategory
        $source = "Microsoft 365 Endpoint Web Service"

        $urls = Get-ObjectPropertyValue -InputObject $item -PropertyName "urls"
        $ips = Get-ObjectPropertyValue -InputObject $item -PropertyName "ips"
        $tcpPortsRaw = Get-ObjectPropertyValue -InputObject $item -PropertyName "tcpPorts"
        $udpPortsRaw = Get-ObjectPropertyValue -InputObject $item -PropertyName "udpPorts"
        $portsRaw = Get-ObjectPropertyValue -InputObject $item -PropertyName "ports"

        if ($urls) {
            $tcpPorts = Get-PortsFromMicrosoft365PortString -PortString $tcpPortsRaw -Protocol TCP
            if (-not $tcpPorts -or $tcpPorts.Count -eq 0) {
                $tcpPorts = Get-PortsFromMicrosoft365PortString -PortString $portsRaw -Protocol TCP
            }
            if (-not $tcpPorts -or $tcpPorts.Count -eq 0) { $tcpPorts = @(443) }

            $udpPorts = Get-PortsFromMicrosoft365PortString -PortString $udpPortsRaw -Protocol UDP
            if (-not $udpPorts -or $udpPorts.Count -eq 0) {
                $udpPorts = Get-PortsFromMicrosoft365PortString -PortString $portsRaw -Protocol UDP
            }

            Add-EndpointRange -List $reference -Service $service -Source $source -Category $category -Required:$required -Addresses $urls -TcpPorts $tcpPorts -UdpPorts $udpPorts
        }

        if ($ips) {
            $tcpPorts = Get-PortsFromMicrosoft365PortString -PortString $tcpPortsRaw -Protocol TCP
            if (-not $tcpPorts -or $tcpPorts.Count -eq 0) {
                $tcpPorts = Get-PortsFromMicrosoft365PortString -PortString $portsRaw -Protocol TCP
            }
            if (-not $tcpPorts -or $tcpPorts.Count -eq 0) { $tcpPorts = @(443) }

            foreach ($ip in $ips) {
                foreach ($port in $tcpPorts) {
                    $record = New-EndpointRecord -Service $service -Source $source -Category $category -Required:$required -Address $ip -Protocol Reference -Port $port -Notes "IP/CIDR reference from Microsoft 365 endpoint web service. Not tested as FQDN."
                    if ($record) { $reference.Add($record) }
                }
            }
        }
    }

    Add-EndpointRange -List $reference -Service "Microsoft 365 - Unified Domains" -Source "Microsoft Learn - Microsoft 365 URLs and IP ranges" -Category "Required" -Required:$true -Addresses @(
        "*.cloud.microsoft",
        "*.static.microsoft",
        "*.usercontent.microsoft"
    ) -TcpPorts @(443) -UdpPorts @(443) -Notes "Wildcard allowlist requirement. Not tested as concrete FQDN."
}

if (-not $SkipIntune) {
    Write-Host "Adding Microsoft Intune consolidated endpoints..." -ForegroundColor Cyan

    Add-EndpointRange -List $reference -Service "Intune - Core service" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "*.manage.microsoft.com",
        "manage.microsoft.com",
        "*.dm.microsoft.com",
        "EnterpriseEnrollment.manage.microsoft.com"
    ) -TcpPorts @(80, 443) -Notes "SSL inspection is not supported for selected Intune service endpoints."

    Add-EndpointRange -List $reference -Service "Intune - Delivery Optimization" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "*.do.dsp.mp.microsoft.com",
        "*.dl.delivery.mp.microsoft.com",
        "dl.delivery.mp.microsoft.com",
        "*.delivery.mp.microsoft.com",
        "*.prod.do.dsp.mp.microsoft.com",
        "tsfe.trafficshaping.dsp.mp.microsoft.com"
    ) -TcpPorts @(80, 443) -Notes "Allow HTTP partial response / byte range requests where applicable."

    Add-EndpointRange -List $reference -Service "Intune - Win32 app content CDN" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "swda01-mscdn.manage.microsoft.com",
        "swda02-mscdn.manage.microsoft.com",
        "swdb01-mscdn.manage.microsoft.com",
        "swdb02-mscdn.manage.microsoft.com",
        "swdc01-mscdn.manage.microsoft.com",
        "swdc02-mscdn.manage.microsoft.com",
        "swdd01-mscdn.manage.microsoft.com",
        "swdd02-mscdn.manage.microsoft.com",
        "swdin01-mscdn.manage.microsoft.com",
        "swdin02-mscdn.manage.microsoft.com"
    ) -TcpPorts @(80, 443)

    Add-EndpointRange -List $reference -Service "Intune - Microsoft account / device auth dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "account.live.com",
        "login.live.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Endpoint discovery" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "go.microsoft.com",
        "aka.ms"
    ) -TcpPorts @(80, 443)

    Add-EndpointRange -List $reference -Service "Intune - Android AOSP dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "intunecdnpeasd.azureedge.net",
        "intunecdnpeasd.manage.microsoft.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Windows Update / Autopilot dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "*.windowsupdate.com",
        "*.update.microsoft.com",
        "adl.windows.com"
    ) -TcpPorts @(80, 443)

    Add-EndpointRange -List $reference -Service "Intune - Autopilot NTP" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "time.windows.com"
    ) -TcpPorts @() -UdpPorts @(123)

    Add-EndpointRange -List $reference -Service "Intune - Autopilot WNS dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "clientconfig.passport.net",
        "windowsphone.com",
        "*.s-microsoft.com",
        "c.s-microsoft.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Autopilot third-party attestation dependencies" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "ekop.intel.com",
        "ekcert.spserv.microsoft.com",
        "ftpm.amd.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - WNS dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "*.notify.windows.com",
        "*.wns.windows.com",
        "sinwns1011421.wns.windows.com",
        "sin.notify.windows.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Remote Help" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "*.support.services.microsoft.com",
        "remoteassistance.support.services.microsoft.com",
        "teams.microsoft.com",
        "remoteassistanceprodacs.communication.azure.com",
        "remoteassistanceprodacseu.communication.azure.com",
        "edge.skype.com",
        "aadcdn.msftauth.net",
        "aadcdn.msauth.net",
        "alcdn.msauth.net",
        "wcpstatic.microsoft.com",
        "*.aria.microsoft.com",
        "browser.pipe.aria.microsoft.com",
        "*.events.data.microsoft.com",
        "v10c.events.data.microsoft.com",
        "*.monitor.azure.com",
        "js.monitor.azure.com",
        "edge.microsoft.com",
        "*.trouter.communication.microsoft.com",
        "*.trouter.teams.microsoft.com",
        "*.trouter.communications.svc.cloud.microsoft",
        "go-amer.trouter.communications.svc.cloud.microsoft",
        "go-apac.trouter.communications.svc.cloud.microsoft",
        "go-eu.trouter.communications.svc.cloud.microsoft",
        "api.flightproxy.skype.com",
        "ecs.communication.microsoft.com",
        "remotehelp.microsoft.com",
        "*.webpubsub.azure.com",
        "AMSUA0101-RemoteAssistService-pubsub.webpubsub.azure.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Store app management" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "displaycatalog.mp.microsoft.com",
        "purchase.md.mp.microsoft.com",
        "licensing.mp.microsoft.com",
        "storeedgefd.dsx.mp.microsoft.com",
        "cdn.storeedgefd.dsx.mp.microsoft.com"
    ) -TcpPorts @(80, 443)

    Add-EndpointRange -List $reference -Service "Intune - Microsoft Entra / Graph dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "enterpriseregistration.windows.net",
        "certauth.enterpriseregistration.windows.net",
        "login.microsoftonline.com",
        "device.login.microsoftonline.com",
        "graph.microsoft.com",
        "graph.windows.net",
        "config.office.com",
        "ecs.office.com"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - PowerShell dependency" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required when using PowerShell/script scenarios" -Required:$true -Addresses @(
        "*.powershellgallery.com",
        "cdn.oneget.org"
    ) -TcpPorts @(443)

    Add-EndpointRange -List $reference -Service "Intune - Diagnostics upload" -Source "Microsoft Learn - Intune consolidated endpoint list" -Category "Required" -Required:$true -Addresses @(
        "lgmsapeweu.blob.core.windows.net",
        "lgmsapewus2.blob.core.windows.net",
        "lgmsapesea.blob.core.windows.net",
        "lgmsapeaus.blob.core.windows.net",
        "lgmsapeind.blob.core.windows.net",
        "lgmsapeswiss.blob.core.windows.net"
    ) -TcpPorts @(443)

    $maaNorthAmerica = @(
        "intunemaape1.eus.attest.azure.net",
        "intunemaape2.eus2.attest.azure.net",
        "intunemaape3.cus.attest.azure.net",
        "intunemaape4.wus.attest.azure.net",
        "intunemaape5.scus.attest.azure.net",
        "intunemaape6.ncus.attest.azure.net"
    )

    $maaEurope = @(
        "intunemaape7.neu.attest.azure.net",
        "intunemaape8.neu.attest.azure.net",
        "intunemaape9.neu.attest.azure.net",
        "intunemaape10.weu.attest.azure.net",
        "intunemaape11.weu.attest.azure.net",
        "intunemaape12.weu.attest.azure.net"
    )

    $maaAsiaPacific = @(
        "intunemaape13.jpe.attest.azure.net",
        "intunemaape17.jpe.attest.azure.net",
        "intunemaape18.jpe.attest.azure.net",
        "intunemaape19.jpe.attest.azure.net"
    )

    $maaSelected = switch ($IntuneRegion) {
        "NorthAmerica" { $maaNorthAmerica }
        "Europe"       { $maaEurope }
        "AsiaPacific"  { $maaAsiaPacific }
        "All"          { $maaNorthAmerica + $maaEurope + $maaAsiaPacific }
    }

    Add-EndpointRange -List $reference -Service "Intune - Microsoft Azure Attestation for Windows 11 compliance" -Source "Microsoft Learn - Intune endpoint list by tenant region" -Category "Required when using Windows 11 device health compliance settings" -Required:$true -Addresses $maaSelected -TcpPorts @(443) -Notes "Selected by Intune tenant location: $IntuneRegion"

    $macNorthAmerica = @("macsidecar.manage.microsoft.com", "macsidecarprod.azureedge.net")
    $macEurope       = @("macsidecareu.manage.microsoft.com", "macsidecarprodeu.azureedge.net")
    $macAsiaPacific  = @("macsidecarap.manage.microsoft.com", "macsidecarprodap.azureedge.net")

    $macSelected = switch ($IntuneRegion) {
        "NorthAmerica" { $macNorthAmerica }
        "Europe"       { $macEurope }
        "AsiaPacific"  { $macAsiaPacific }
        "All"          { $macNorthAmerica + $macEurope + $macAsiaPacific }
    }

    Add-EndpointRange -List $reference -Service "Intune - macOS app and script deployment" -Source "Microsoft Learn - Intune endpoint list by tenant region" -Category "Required for macOS app/script deployment" -Required:$true -Addresses $macSelected -TcpPorts @(443) -Notes "Selected by Intune tenant location: $IntuneRegion"

    $imeNorthAmerica = @(
        "naprodimedatapri.azureedge.net",
        "naprodimedatasec.azureedge.net",
        "naprodimedatahotfix.azureedge.net",
        "imeswda-afd-primary.manage.microsoft.com",
        "imeswda-afd-secondary.manage.microsoft.com",
        "imeswda-afd-hotfix.manage.microsoft.com"
    )

    $imeEurope = @(
        "euprodimedatapri.azureedge.net",
        "euprodimedatasec.azureedge.net",
        "euprodimedatahotfix.azureedge.net",
        "imeswdb-afd-primary.manage.microsoft.com",
        "imeswdb-afd-secondary.manage.microsoft.com",
        "imeswdb-afd-hotfix.manage.microsoft.com"
    )

    $imeAsiaPacific = @(
        "approdimedatapri.azureedge.net",
        "approdimedatasec.azureedge.net",
        "approdimedatahotfix.azureedge.net",
        "imeswdc-afd-primary.manage.microsoft.com",
        "imeswdc-afd-secondary.manage.microsoft.com",
        "imeswdc-afd-hotfix.manage.microsoft.com"
    )

    $imeSelected = switch ($IntuneRegion) {
        "NorthAmerica" { $imeNorthAmerica }
        "Europe"       { $imeEurope }
        "AsiaPacific"  { $imeAsiaPacific }
        "All"          { $imeNorthAmerica + $imeEurope + $imeAsiaPacific }
    }

    Add-EndpointRange -List $reference -Service "Intune - Intune Management Extension / Win32 apps / scripts" -Source "Microsoft Learn - Intune endpoint list by tenant region" -Category "Required for IME scenarios" -Required:$true -Addresses $imeSelected -TcpPorts @(443) -Notes "HTTP partial response is required for Scripts and Win32 Apps endpoints. Selected region: $IntuneRegion"
}

if (-not $SkipPortals) {
    Write-Host "Adding Microsoft admin portals..." -ForegroundColor Cyan

    Add-EndpointRange -List $reference -Service "Microsoft Admin Portals" -Source "Curated portal validation list" -Category "Portal" -Required:$true -Addresses @(
        "admin.microsoft.com",
        "intune.microsoft.com",
        "endpoint.microsoft.com",
        "entra.microsoft.com",
        "portal.azure.com",
        "security.microsoft.com",
        "defender.microsoft.com",
        "compliance.microsoft.com",
        "purview.microsoft.com",
        "admin.exchange.microsoft.com",
        "admin.teams.microsoft.com",
        "config.office.com",
        "cloud.microsoft",
        "office.com",
        "www.office.com"
    ) -TcpPorts @(443)
}

$referenceUnique = $reference |
    Sort-Object Service, Address, Protocol, Port -Unique

Write-Host "Testing concrete FQDN endpoints..." -ForegroundColor Cyan

$testable = $referenceUnique | Where-Object {
    $_.Kind -eq "FQDN" -and
    $_.Protocol -in @("TCP", "UDP") -and
    $_.Address -notmatch "<.*>"
}

$results = foreach ($endpoint in $testable) {
    $dnsStatus = "NotTested"
    $dnsDetail = $null
    $ipAddresses = $null
    $tcpStatus = "NotTested"
    $tcpDetail = $null
    $tlsStatus = "NotTested"
    $tlsDetail = $null
    $httpStatus = "Skipped"
    $httpDetail = $null
    $udpStatus = "NotTested"
    $udpDetail = $null

    try {
        $dns = Resolve-DnsName -Name $endpoint.Address -ErrorAction Stop
        $ipAddresses = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique) -join ", "
        if ([string]::IsNullOrWhiteSpace($ipAddresses)) {
            $dnsStatus = "ResolvedNoIP"
            $dnsDetail = "DNS resolved, but no IPAddress record was returned."
        } else {
            $dnsStatus = "Success"
            $dnsDetail = "DNS resolved."
        }
    }
    catch {
        $dnsStatus = "Failed"
        $dnsDetail = $_.Exception.Message
    }

    if ($endpoint.Protocol -eq "TCP") {
        $tcp = Test-TcpPort -HostName $endpoint.Address -Port $endpoint.Port -TimeoutMs ($TimeoutSeconds * 1000)
        $tcpStatus = $tcp.Status
        $tcpDetail = $tcp.Detail

        if ($endpoint.Port -eq 443) {
            $tls = Test-TlsHandshake -HostName $endpoint.Address -TimeoutMs ($TimeoutSeconds * 1000)
            $tlsStatus = $tls.Status
            $tlsDetail = $tls.Detail
        }

        if (-not $SkipHttpProbe -and $endpoint.Port -in @(80, 443)) {
            $http = Invoke-EndpointWebProbe -HostName $endpoint.Address -Port $endpoint.Port -TimeoutSec $TimeoutSeconds -ProxyUrl $Proxy -UseProxyDefaultCredentials:$UseDefaultCredentials
            $httpStatus = $http.Status
            $httpDetail = $http.Detail
        }
    }

    if ($endpoint.Protocol -eq "UDP" -and $endpoint.Port -eq 123) {
        $udp = Test-NtpUdp123 -HostName $endpoint.Address -TimeoutMs ($TimeoutSeconds * 1000)
        $udpStatus = $udp.Status
        $udpDetail = $udp.Detail
    }

    [PSCustomObject]@{
        Service     = $endpoint.Service
        Source      = $endpoint.Source
        Category    = $endpoint.Category
        Required    = $endpoint.Required
        Address     = $endpoint.Address
        Protocol    = $endpoint.Protocol
        Port        = $endpoint.Port
        DNS         = $dnsStatus
        DNSDetail   = $dnsDetail
        IPAddresses = $ipAddresses
        DirectTcp   = $tcpStatus
        TcpDetail   = $tcpDetail
        TLS         = $tlsStatus
        TlsDetail   = $tlsDetail
        HttpProbe   = $httpStatus
        HttpDetail  = $httpDetail
        UDP         = $udpStatus
        UdpDetail   = $udpDetail
        Notes       = $endpoint.Notes
    }
}

$failed = $results | Where-Object {
    $_.DNS -eq "Failed" -or
    $_.DirectTcp -eq "Failed" -or
    $_.TLS -eq "Failed" -or
    $_.HttpProbe -eq "Failed" -or
    $_.UDP -eq "Failed"
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "Reference records: $($referenceUnique.Count)"
Write-Host "Tested FQDN records: $($results.Count)"
Write-Host "Records with one or more failures: $($failed.Count)"

Write-Host ""
Write-Host "Connectivity Results:" -ForegroundColor Cyan

$results |
    Sort-Object Service, Address, Protocol, Port |
    Format-Table Service, Address, Protocol, Port, DNS, DirectTcp, TLS, HttpProbe, UDP -AutoSize

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Top failures:" -ForegroundColor Yellow

    $failed |
        Select-Object Service, Address, Protocol, Port, DNS, DirectTcp, TLS, HttpProbe, UDP |
        Sort-Object Service, Address, Port |
        Select-Object -First 25 |
        Format-Table -AutoSize
} else {
    Write-Host ""
    Write-Host "No failures detected in tested concrete FQDN records." -ForegroundColor Green
}

Write-Host ""
$exportChoice = Read-Host "Do you want to export the results to CSV and JSON files? (Y/N) [Default: N]"

if ($exportChoice -match '^(Y|y)$') {
    $referenceUnique | Export-Csv -Path $referencePath -NoTypeInformation -Encoding UTF8

    $results | Export-Csv -Path $resultsPath -NoTypeInformation -Encoding UTF8

    $results |
        ConvertTo-Json -Depth 5 |
        Out-File -FilePath $jsonPath -Encoding UTF8

    Write-Host ""
    Write-Host "Files exported successfully:" -ForegroundColor Green
    Write-Host "Reference CSV : $referencePath"
    Write-Host "Results CSV   : $resultsPath"
    Write-Host "Results JSON  : $jsonPath"
}
else {
    Write-Host ""
    Write-Host "Export skipped." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Important:" -ForegroundColor Yellow
Write-Host "Wildcards, placeholders, and CIDR/IP subnet records are allowlist references and are not tested as concrete FQDNs."
