#requires -Version 5.1

<#
.SYNOPSIS
    Read-only health check for Forcepoint DLP (Security Manager).

.DESCRIPTION
    This script checks the hardware/service health of the Windows server it runs on
    (typically the Forcepoint Security Manager / Content Manager server) AND, optionally,
    the Microsoft SQL Server database behind Forcepoint DLP (wbsn-data-security) -
    READ-ONLY. It prints a summary to the console and produces a graphical HTML report
    on the desktop.

    Only sends SELECT queries to SQL Server (NO INSERT/UPDATE/DELETE/DDL).
    Uses sqlcmd.exe (must be on PATH).

    Author: FIRAT AYDIN

.EXAMPLE
    .\ForcepointDlpHealth.ps1

.EXAMPLE
    .\ForcepointDlpHealth.ps1 -CustomerName "Example Inc." -SqlServerInstance "SQL"

.EXAMPLE
    .\ForcepointDlpHealth.ps1 -SkipDatabaseCheck

.NOTES
    v1 - 2026-09-22. Built against a schema validated through discovery sessions on the
    SQL Server side (see NOTES.md). Live/full end-to-end testing has NOT been done yet -
    on first run, compare the console/HTML output against the FSM console.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$CpuWarningPercent = 70,

    [ValidateRange(1, 100)]
    [int]$CpuCriticalPercent = 85,

    [ValidateRange(1, 100)]
    [int]$MemoryWarningUsedPercent = 80,

    [ValidateRange(1, 100)]
    [int]$MemoryCriticalUsedPercent = 90,

    [ValidateRange(0.1, 100)]
    [double]$DiskWarningFreePercent = 20,

    [ValidateRange(0.1, 100)]
    [double]$DiskCriticalFreePercent = 10,

    [ValidateRange(1, 60)]
    [int]$CpuSampleCount = 5,

    [ValidateRange(1, 30)]
    [int]$CpuSampleIntervalSeconds = 1,

    # SQL Server / Forcepoint DLP veritabani baglantisi
    [string]$SqlServerInstance = '',

    [string]$SqlDatabaseName = 'wbsn-data-security',

    [ValidateSet('Windows', 'SqlLogin')]
    [string]$SqlAuthMode = 'Windows',

    [string]$SqlUserName = '',

    [ValidateRange(1, 3650)]
    [int]$IncidentLookbackDays = 30,

    [ValidateRange(1, 3650)]
    [int]$LicenseWarningDays = 60,

    [ValidateRange(1, 365)]
    [int]$EventLogLookbackDays = 7,

    [string]$CustomerName = '',

    [switch]$SkipDatabaseCheck,

    [switch]$KeepTempSqlFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ------------------------------------------------------------------------------------
# Yardimci fonksiyonlar (HTML motoru - Symantec DLP HC scriptiyle ayni desen)
# ------------------------------------------------------------------------------------

function Convert-BytesToGB {
    param([double]$Bytes)
    [math]::Round(($Bytes / 1GB), 2)
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return '' }
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function ConvertFrom-EpochMs {
    param([string]$Ms)
    if (-not $Ms -or $Ms -notmatch '^\d+$') { return $null }
    try { [DateTimeOffset]::FromUnixTimeMilliseconds([long]$Ms).LocalDateTime } catch { return $null }
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Critical' { '#dc2626' }
        'Warning'  { '#d97706' }
        'Normal'   { '#16a34a' }
        'Error'    { '#dc2626' }
        default    { '#6b7280' }
    }
}

function Get-GenericTableHtml {
    param(
        [object[]]$Items,
        [System.Collections.Specialized.OrderedDictionary]$Columns,
        [scriptblock]$RowColorSelector
    )
    $rows = @($Items)
    if ($rows.Count -eq 0) { return '<p class="muted">No data.</p>' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="report-table"><thead><tr>')
    foreach ($header in $Columns.Keys) { [void]$sb.Append("<th>$(ConvertTo-HtmlSafe $header)</th>") }
    [void]$sb.AppendLine('</tr></thead><tbody>')

    foreach ($item in $rows) {
        $style = ''
        if ($RowColorSelector) {
            $color = & $RowColorSelector $item
            if ($color) { $style = " style='border-left:4px solid $color'" }
        }
        [void]$sb.Append("<tr$style>")
        foreach ($propName in $Columns.Values) {
            [void]$sb.Append("<td>$(ConvertTo-HtmlSafe ([string]$item.$propName))</td>")
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function Get-FindingsTableHtml {
    param([object[]]$Findings)
    $rows = @($Findings)
    if ($rows.Count -eq 0) { return '<p class="muted">No findings.</p>' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<table class="report-table"><thead><tr><th>Status</th><th>Category</th><th>Metric</th><th>Value</th><th>Note</th></tr></thead><tbody>')
    foreach ($f in $rows) {
        $color = Get-StatusColor -Status $f.Status
        $noteHtml = if ($f.PSObject.Properties['NoteIsHtml'] -and $f.NoteIsHtml) { $f.Note } else { ConvertTo-HtmlSafe $f.Note }
        [void]$sb.AppendLine("<tr><td><span class='badge' style='background:$color'>$(ConvertTo-HtmlSafe $f.Status)</span></td><td>$(ConvertTo-HtmlSafe $f.Category)</td><td>$(ConvertTo-HtmlSafe $f.Metric)</td><td>$(ConvertTo-HtmlSafe $f.Value)</td><td>$noteHtml</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function Get-KpiCardHtml {
    param([string]$Label, [string]$Value, [string]$Color = '#111827')
    "<div class='kpi-card'><div class='kpi-value' style='color:$Color'>$(ConvertTo-HtmlSafe $Value)</div><div class='kpi-label'>$(ConvertTo-HtmlSafe $Label)</div></div>"
}

function Get-BarChartHtml {
    # Yatay bar-chart (ornek: En Cok Ihlal Edilen Politikalar). $Items her biri Label+Value
    # property'sine sahip nesneler; en buyuk deger %100 genislikte, digerleri orantili.
    param([object[]]$Items, [string]$LabelProp = 'Label', [string]$ValueProp = 'Value', [string]$Color = '#db2777', [int]$MaxItems = 10, [int]$FontSizePx = 13)
    $rows = @($Items | Select-Object -First $MaxItems)
    if ($rows.Count -eq 0) { return '<p class="muted">No data.</p>' }
    $maxVal = ($rows | ForEach-Object { $n = 0; [void][long]::TryParse([string]($_.$ValueProp), [ref]$n); $n } | Measure-Object -Maximum).Maximum
    if ($maxVal -le 0) { $maxVal = 1 }
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $rows) {
        $n = 0; [void][long]::TryParse([string]($r.$ValueProp), [ref]$n)
        $pct = [math]::Round(($n / $maxVal) * 100)
        if ($pct -lt 3) { $pct = 3 }
        [void]$sb.AppendLine("<div class='bar-row' style='font-size:${FontSizePx}px'><div class='bar-label'>$(ConvertTo-HtmlSafe ([string]($r.$LabelProp)))</div><div class='bar-track'><div class='bar-fill' style='width:$pct%;background:$Color'></div></div><div class='bar-value'>$n</div></div>")
    }
    $sb.ToString()
}

function Get-FpComponentRowHtml {
    # Tek bir bilesen satirini render eder. Son dagitim SUCCESS/bos ise duz satir; degilse
    # (WARNING/FAILURE) tiklaninca hata aciklamasini (DEPLOYMENT_RESULT_DESC) gosteren
    # <details>/<summary> (yerlesik HTML, JS gerekmez) kullanilir.
    param([object]$Component, [switch]$Indent, [string]$InheritedVersion = '')

    $c = $Component
    $hasProblem = [bool]($c.DeployResult -and $c.DeployResult -ne 'SUCCESS')
    $badgeColor = if (-not $hasProblem) { '#16a34a' } elseif ($c.DeployResult -eq 'FAILURE') { '#dc2626' } else { '#d97706' }
    $badgeText = if ($hasProblem) { $c.DeployResult } else { 'OK' }
    $versionText = if ($c.Version) {
        " <span class='module-version'>(v$(ConvertTo-HtmlSafe $c.Version))</span>"
    } elseif ($InheritedVersion) {
        " <span class='module-version muted'>(v$(ConvertTo-HtmlSafe $InheritedVersion), from parent component)</span>"
    } else { '' }
    $metaText = "$(ConvertTo-HtmlSafe $c.ElementType) · $(ConvertTo-HtmlSafe $c.HostName)"
    $indentClass = if ($Indent) { ' module-child' } else { '' }
    $headerHtml = "<span class='badge' style='background:$badgeColor'>$(ConvertTo-HtmlSafe $badgeText)</span> $(ConvertTo-HtmlSafe $c.Name)$versionText <span class='muted'>· $metaText</span>"

    if ($hasProblem) {
        $desc = if ($c.ResultDesc) { ConvertTo-HtmlSafe $c.ResultDesc } else { 'No detailed description was recorded for this deployment.' }
        return "<details class='module-item$indentClass'><summary>$headerHtml</summary><div class='module-error-detail'>$desc</div></details>"
    }
    return "<div class='module-item$indentClass'>$headerHtml</div>"
}

function Get-FpComponentTreeHtml {
    # WS_SM_SITE_ELEMENTS icindeki PARENT_ID iliskisini kullanarak FSM konsolundaki
    # "System Modules" agac gorunumune benzer bir hiyerarsi olusturur.
    param([object[]]$Components)

    $comps = @($Components)
    if ($comps.Count -eq 0) { return '<p class="muted">No data.</p>' }

    $compById = @{}
    foreach ($c in $comps) { if ($c.Id) { $compById[$c.Id] = $c } }

    $byParent = @{}
    foreach ($c in $comps) {
        $key = if ($c.ParentId) { $c.ParentId } else { '' }
        if (-not $byParent.ContainsKey($key)) { $byParent[$key] = New-Object System.Collections.Generic.List[object] }
        [void]$byParent[$key].Add($c)
    }

    # Kok: ParentId bos olan YA DA parent'i (DUMMY filtresiyle) listede olmayan bilesenler.
    $roots = @($comps | Where-Object { -not $_.ParentId -or -not $compById.ContainsKey($_.ParentId) } | Sort-Object Name)

    $sb = New-Object System.Text.StringBuilder
    foreach ($root in $roots) {
        [void]$sb.Append((Get-FpComponentRowHtml -Component $root))
        $children = @($byParent[$root.Id] | Sort-Object Name)
        if ($children.Count -gt 0) {
            [void]$sb.Append("<div class='module-children'>")
            foreach ($child in $children) {
                [void]$sb.Append((Get-FpComponentRowHtml -Component $child -Indent -InheritedVersion $root.Version))
            }
            [void]$sb.Append('</div>')
        }
    }
    return $sb.ToString()
}

function Get-Status {
    param(
        [double]$Value, [double]$WarningThreshold, [double]$CriticalThreshold,
        [ValidateSet('HigherIsWorse', 'LowerIsWorse')] [string]$Direction = 'HigherIsWorse'
    )
    if ($Direction -eq 'HigherIsWorse') {
        if ($Value -ge $CriticalThreshold) { return 'Critical' }
        if ($Value -ge $WarningThreshold)  { return 'Warning' }
    } else {
        if ($Value -le $CriticalThreshold) { return 'Critical' }
        if ($Value -le $WarningThreshold)  { return 'Warning' }
    }
    return 'Normal'
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Category, [string]$Metric, [string]$Value,
        [ValidateSet('Normal', 'Warning', 'Critical', 'Unknown')] [string]$Status,
        [string]$Note,
        [switch]$NoteIsHtml
    )
    $List.Add([pscustomobject]@{ Category = $Category; Metric = $Metric; Value = $Value; Status = $Status; Note = $Note; NoteIsHtml = [bool]$NoteIsHtml })
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

function Get-FpProductDisplayName {
    param([string]$ProductId)
    # Forcepoint Security Manager > Subscription sayfasindaki gorunen adlarla eslesecek sekilde
    # dogrulanmistir (2026-09-22, gercek test ortami ekran goruntusu).
    switch ($ProductId) {
        'wbsn.dss.agents.image.analyzer' { 'Image Analysis' }
        'subscription.protector.api'     { 'Forcepoint Protector API' }
        'subscription.apx.data.cloud'    { 'Forcepoint DLP Cloud Applications / Forcepoint ONE CASB' }
        'subscription.csg'               { 'Forcepoint Web Security Cloud / Forcepoint ONE Security Web Gateway' }
        'subscription.apx.data.discover' { 'Forcepoint Data Discovery' }
        'subscription.apx.data.gateway'  { 'Forcepoint DLP Network' }
        'subscription.apx.data.endpoint' { 'Forcepoint DLP Endpoint' }
        default                          { $ProductId }
    }
}

# ------------------------------------------------------------------------------------
# Yerel: Forcepoint/Websense Windows servisleri
# ------------------------------------------------------------------------------------

function Get-FpServices {
    $allServices = Get-CimInstance -ClassName Win32_Service
    @($allServices |
        Where-Object {
            $_.Name -match 'Websense|Forcepoint|DSS|EIP|PAFPREP|WorkScheduler|EsgManager|mgmtd|pgsqlEIP|BPServer|DsSvc' -or
            $_.DisplayName -match 'Websense|Forcepoint|Data Security|TRITON'
        } |
        Sort-Object DisplayName |
        Select-Object Name, DisplayName, State, StartMode)
}

function Get-FpHardwareRequirementTable {
    # "Forcepoint DLP server hardware requirements" tablosu - her surum icin resmi
    # help.forcepoint.com/dlp/<surum>/deployctr/CF20D089-F1F4-437E-B222-BF9864236061.html
    # sayfasindan TEK TEK DOGRULANDI (2026-09-23): 10.1, 10.2, 10.3, 10.4 - DORDU DE AYNI
    # degerleri veriyor (CPU 4/8 core, RAM 16/16 GB, Disk 146/400 GB, RAID 1/1+0, NIC 1/2).
    # Yine de musteri bazinda surum farkli olabilecegi ve Forcepoint ileride bu tabloyu
    # surume gore degistirebilecegi icin YAPI surum-bazli tutuluyor (tek bir sabit degil).
    $tables = [ordered]@{
        '10.1' = @{ MinCpu = 4; RecCpu = 8; MinRam = 16; RecRam = 16; MinDisk = 146; RecDisk = 400
                     SourceUrl = 'https://help.forcepoint.com/dlp/10.1.0/deployctr/CF20D089-F1F4-437E-B222-BF9864236061.html' }
        '10.2' = @{ MinCpu = 4; RecCpu = 8; MinRam = 16; RecRam = 16; MinDisk = 146; RecDisk = 400
                     SourceUrl = 'https://help.forcepoint.com/dlp/10.2.0/deployctr/CF20D089-F1F4-437E-B222-BF9864236061.html' }
        '10.3' = @{ MinCpu = 4; RecCpu = 8; MinRam = 16; RecRam = 16; MinDisk = 146; RecDisk = 400
                     SourceUrl = 'https://help.forcepoint.com/dlp/10.3.0/deployctr/CF20D089-F1F4-437E-B222-BF9864236061.html' }
        '10.4' = @{ MinCpu = 4; RecCpu = 8; MinRam = 16; RecRam = 16; MinDisk = 146; RecDisk = 400
                     SourceUrl = 'https://help.forcepoint.com/dlp/10.4.0/deployctr/CF20D089-F1F4-437E-B222-BF9864236061.html' }
    }
    return $tables
}

function Get-FpHardwareAssessment {
    # Bu tablo Management Server / FSM (DLP Server) icin gecerlidir - bu script'in calistigi
    # sunucunun tipik olarak bu rol oldugu varsayilir.
    param([int]$LogicalCpu, [double]$RamGB, [double]$TotalDiskGB, [string]$FpVersion)

    $tables = Get-FpHardwareRequirementTable
    $versionKey = $null
    if ($FpVersion -and $FpVersion -match '^(\d+\.\d+)') { $versionKey = $Matches[1] }

    $matched = $false
    if ($versionKey -and $tables.Contains($versionKey)) {
        $t = $tables[$versionKey]
        $matched = $true
    }
    else {
        # Surum tespit edilemedi ya da bilinen tabloda yok: en guncel bilinen (10.4) tabloyu
        # kullan, ama raporda bunun bir varsayim oldugu ACIKCA belirtilir.
        $t = $tables['10.4']
        if (-not $versionKey) { $versionKey = 'unknown' }
    }

    $rows = @(
        [pscustomobject]@{ Metric = 'CPU (logical/vCPU)'; Current = $LogicalCpu; Min = $t.MinCpu; Recommended = $t.RecCpu; Unit = 'core' }
        [pscustomobject]@{ Metric = 'RAM (GB)'; Current = $RamGB; Min = $t.MinRam; Recommended = $t.RecRam; Unit = 'GB' }
        [pscustomobject]@{ Metric = 'Total Disk (GB)'; Current = $TotalDiskGB; Min = $t.MinDisk; Recommended = $t.RecDisk; Unit = 'GB' }
    )

    $belowMinimum = @($rows | Where-Object { $_.Current -lt $_.Min }).Count -gt 0
    $meetsRecommended = @($rows | Where-Object { $_.Current -lt $_.Recommended }).Count -eq 0

    $level = if ($belowMinimum) { 'Below minimum' } elseif ($meetsRecommended) { 'Recommended' } else { 'Minimum' }
    $status = if ($belowMinimum) { 'Critical' } elseif ($meetsRecommended) { 'Normal' } else { 'Warning' }

    $versionNote = if ($matched) {
        "Official table for version $versionKey was used."
    } else {
        "Version could not be detected or is not in the known table ($versionKey), so the most recent known table (10.4) was used - actual values may differ for a different version."
    }

    [pscustomobject]@{
        Rows        = $rows
        Level       = $level
        Status      = $status
        VersionKey  = $versionKey
        Matched     = $matched
        SourceUrl   = $t.SourceUrl
        Note        = "$versionNote Source: official Forcepoint DLP hardware requirements (Management/DLP Server, help.forcepoint.com). Actual needs vary based on daily transaction volume, number of endpoints/policies, and retention period."
    }
}

# ------------------------------------------------------------------------------------
# Yerel: lisans (subscription.xml) - Uninstall registry uzerinden kurulum yolu bulunur
# ------------------------------------------------------------------------------------

function Get-FpEventLogFindings {
    # Windows Event Log'da (Application + System) Forcepoint/Websense kaynakli Warning/Error
    # kayitlarini arar. Symantec scriptindeki "System Event" bolumunun Forcepoint karsiligi -
    # daha once FP scriptine hic tasinmamisti.
    param([int]$LookbackDays = 7, [int]$MaxDisplay = 20)

    $result = [ordered]@{ Status = 'Not tested'; Events = @(); TotalCount = 0; Error = $null }
    try {
        $startTime = (Get-Date).AddDays(-$LookbackDays)
        $filter = @{ LogName = 'Application', 'System'; Level = 2, 3; StartTime = $startTime }
        $allEvents = @()
        try {
            $allEvents = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') { throw }
        }
        $fpEvents = @($allEvents | Where-Object { $_.ProviderName -match 'Websense|Forcepoint|DSS|EIP' })
        $result.TotalCount = $fpEvents.Count
        $result.Events = @($fpEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxDisplay | ForEach-Object {
            [pscustomobject]@{
                Time    = $_.TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')
                Level   = $_.LevelDisplayName
                Source  = $_.ProviderName
                Id      = $_.Id
                Message = (($_.Message -split "`r?`n")[0])
            }
        })
        $result.Status = 'Successful'
    }
    catch {
        $result.Status = 'Failed'
        $result.Error = $_.Exception.Message
    }
    return [pscustomobject]$result
}

function Get-FpLocalVersion {
    # Uninstall registry'sinden Forcepoint DLP surumunu okur (DB kontrolu yapilmasa/basarisiz
    # olsa bile calisir - yerel, salt-okunur). Kesif oturumlarinda DB'deki
    # WS_SM_SITE_ELEMENTS.NETWORK_ELEMENT_VERSION ile CAPRAZ DOGRULANMISTIR (2026-09-22, ikisi
    # de 10.4.0.525 verdi).
    try {
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $entry = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match '^Forcepoint DLP$'
            } |
            Select-Object -First 1
        if ($entry -and $entry.PSObject.Properties['DisplayVersion']) { return $entry.DisplayVersion }
    } catch {}
    return $null
}

function Get-FpLicenseInfo {
    param([int]$WarningDays = 60)

    $info = [ordered]@{
        Status          = 'NotFound'
        FilePath        = ''
        CompanyName     = ''
        MaskedKey       = ''
        ValidSince      = $null
        ExpiresOn       = $null
        DaysRemaining   = $null
        Products        = @()
        Error           = $null
    }

    try {
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $entry = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PSObject.Properties['DisplayName'] -and $_.PSObject.Properties['InstallLocation'] -and
                $_.DisplayName -match 'Forcepoint DLP|Websense Data Security|^Data Security$' -and $_.InstallLocation
            } |
            Select-Object -First 1

        if (-not $entry -or -not $entry.InstallLocation) {
            $info.Error = 'Install path (InstallLocation) could not be found in the registry.'
            return [pscustomobject]$info
        }

        $subscriptionPath = Join-Path $entry.InstallLocation 'tomcat\wbsnData\subscription.xml'
        if (-not (Test-Path -LiteralPath $subscriptionPath)) {
            $info.Error = "subscription.xml not found: $subscriptionPath"
            return [pscustomobject]$info
        }
        $info.FilePath = $subscriptionPath

        [xml]$xmlDoc = Get-Content -LiteralPath $subscriptionPath -Raw
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $ns.AddNamespace('s', 'http://www.websense.com/java/fw/subscription/1.0')
        $subNs = 'http://www.websense.com/java/fw/subscription/1.0'

        # ONEMLI: subscription.xml'deki key/validSince/expiresOn/productId/usageLimit hep
        # NAMESPACE'Ll ATTRIBUTE'lardir (ornek: s:expiresOn="..."). Bunlara PowerShell'in
        # nokta-notasyonuyla ($node.expiresOn) erismek StrictMode altinda "The property 'X'
        # cannot be found on this object" hatasi verir (gercek ortamda goruldu, 2026-09-23).
        # Bu yuzden HER YERDE .GetAttribute(ad, namespace) kullanilir - bu metot ozellik yoksa
        # ASLA hata vermez, sadece bos string doner.
        $companyNode = $xmlDoc.SelectSingleNode('//s:subscription/s:customer/s:companyName', $ns)
        if ($companyNode) { $info.CompanyName = $companyNode.InnerText }

        $subInfoNode = $xmlDoc.SelectSingleNode('//s:subscription/s:subscriptionInfo', $ns)
        if ($subInfoNode) {
            $rawKey = $subInfoNode.GetAttribute('key', $subNs)
            if ($rawKey -and $rawKey.Length -gt 8) {
                $info.MaskedKey = $rawKey.Substring(0, 4) + ('*' * ($rawKey.Length - 8)) + $rawKey.Substring($rawKey.Length - 4)
            } else { $info.MaskedKey = $rawKey }

            $validSinceRaw = $subInfoNode.GetAttribute('validSince', $subNs)
            if ($validSinceRaw) { try { $info.ValidSince = [datetimeoffset]::Parse($validSinceRaw) } catch {} }
            $expiresOnRaw = $subInfoNode.GetAttribute('expiresOn', $subNs)
            if ($expiresOnRaw) { try { $info.ExpiresOn = [datetimeoffset]::Parse($expiresOnRaw) } catch {} }
        }

        $products = New-Object System.Collections.Generic.List[object]
        foreach ($p in $xmlDoc.SelectNodes('//s:subscription/s:usageLimitProducts/s:usageLimitProduct', $ns)) {
            $prodExpires = $info.ExpiresOn
            $prodExpiresRaw = $p.GetAttribute('expiresOn', $subNs)
            if ($prodExpiresRaw) { try { $prodExpires = [datetimeoffset]::Parse($prodExpiresRaw) } catch {} }
            $productId = $p.GetAttribute('productId', $subNs)
            [void]$products.Add([pscustomobject]@{
                ProductId   = $productId
                DisplayName = Get-FpProductDisplayName -ProductId $productId
                UsageLimit  = $p.GetAttribute('usageLimit', $subNs)
                ExpiresOn   = $prodExpires
            })
        }
        $info.Products = $products.ToArray()

        if ($null -eq $info.ExpiresOn) {
            $info.Status = 'Unknown'
        }
        else {
            $daysRemaining = [math]::Floor((New-TimeSpan -Start (Get-Date) -End $info.ExpiresOn.LocalDateTime).TotalDays)
            $info.DaysRemaining = $daysRemaining
            if ($daysRemaining -lt 0) { $info.Status = 'Expired' }
            elseif ($daysRemaining -le $WarningDays) { $info.Status = 'Expiring soon' }
            else { $info.Status = 'OK' }
        }
    }
    catch {
        $info.Error = $_.Exception.Message
    }

    return [pscustomobject]$info
}

# ------------------------------------------------------------------------------------
# SQL Server: Forcepoint DLP veritabani kontrolu (sqlcmd ile, SADECE SELECT)
# ------------------------------------------------------------------------------------

function Invoke-FpDatabaseCheck {
    param(
        [string]$ServerInstance,
        [string]$DatabaseName,
        [ValidateSet('Windows', 'SqlLogin')] [string]$AuthMode,
        [string]$UserName,
        [int]$LookbackDays,
        [switch]$KeepTempFiles
    )

    $result = [ordered]@{
        DatabaseLogin       = 'Not tested'
        SqlServerVersion    = 'N/A'
        ConnectedAuth       = 'N/A'
        FpVersionStatus     = 'Not tested'
        FpVersion           = 'N/A'
        ComponentsStatus    = 'Not tested'
        Components          = @()
        ChannelsStatus      = 'Not tested'
        Channels            = @()
        PolicyStatus        = 'Not tested'
        PolicyTotal         = 'N/A'
        PolicyEnabled       = 'N/A'
        PolicyDisabled      = 'N/A'
        DisabledPolicies    = @()
        PolicyByType        = @()
        IncidentStatus      = 'Not tested'
        IncidentTotal       = 'N/A'
        IncidentRecent      = 'N/A'
        IncidentByStatus    = @()
        IncidentPartitions  = @()
        AdminStatus         = 'Not tested'
        Admins              = @()
        Roles               = @()
        LdapStatus          = 'Not tested'
        LdapQueryCount      = 'N/A'
        EndpointKnownStatus = 'Not tested'
        EndpointKnownCount  = 'N/A'
        IncidentLast7Days  = 'N/A'
        TopPolicies        = @()
        TopPoliciesAllTime = @()
        PolicyDistinctIncidents       = 'N/A'
        PolicyDistinctIncidentsRecent = 'N/A'
        AdSync             = @()
        SyslogHostname      = ''
        SyslogPort          = ''
        SyslogFacility      = ''
        SyslogPrintFacility = ''
        SyslogAdditivity    = ''
        SyslogStatus        = 'Not tested'
        OcrEnabled          = ''
        MipEnabled          = ''
        RmsEnabled          = ''
        IntegrationsStatus  = 'Not tested'
        FileLabeling        = @()
        IncidentType        = @()
        IncidentByServer    = @()
        UnusedPolicies      = @()
        EndpointUsers       = @()
        NetworkSenders      = @()
        EndpointStatus      = @()
        EndpointBypassLog   = @()
        ArchiveConf        = @()
        DiscoveryTasks     = @()
        PolicyLevelCount   = 'N/A'
        SqlDiskStatus      = 'Not tested'
        SqlDisks           = @()
        ErrorMessage        = $null
        SqlWarnings         = $null
    }

    $sqlCmdExe = Get-Command 'sqlcmd.exe' -ErrorAction SilentlyContinue
    if (-not $sqlCmdExe) {
        $result.ErrorMessage = 'sqlcmd.exe not found on PATH (SQL Server Command Line Utilities or SSMS is required).'
        return [pscustomobject]$result
    }

  try {

    $tempDir = Join-Path $env:ProgramData 'FpDlpHealthTemp'
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $sqlFile = Join-Path $tempDir 'fp_health_query.sql'
    $outFile = Join-Path $tempDir 'fp_health_result.txt'
    Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue

    $sqlContent = @'
SET NOCOUNT ON;

PRINT '###CONN###';
SELECT @@VERSION AS v;

PRINT '###FPVERSION###';
SELECT TOP 1 NETWORK_ELEMENT_VERSION
FROM WS_SM_SITE_ELEMENTS
WHERE ELEMENT_TYPE = 'CNTNT_MNG_SRV' AND NETWORK_ELEMENT_VERSION IS NOT NULL;

PRINT '###COMPONENTS###';
SELECT ISNULL(CAST(ID AS NVARCHAR(20)),'') + '|' + ISNULL(REPLACE(NAME,'|','/'),'') + '|' + ISNULL(ELEMENT_TYPE,'') + '|' +
       ISNULL(HOSTNAME,'') + '|' + ISNULL(IP,'') + '|' + ISNULL(ELEMENT_STATUS,'') + '|' +
       ISNULL(DEPLOYMENT_RESULT_TYPE,'') + '|' + ISNULL(CONVERT(NVARCHAR(19),DEPLOYMENT_DATE,120),'') + '|' +
       ISNULL(NETWORK_ELEMENT_VERSION,'') + '|' + ISNULL(CAST(PARENT_ID AS NVARCHAR(20)),'') + '|' +
       ISNULL(REPLACE(REPLACE(REPLACE(DEPLOYMENT_RESULT_DESC,'|','/'),CHAR(13),' '),CHAR(10),' '),'')
FROM WS_SM_SITE_ELEMENTS
WHERE ELEMENT_TYPE NOT LIKE '%DUMMY%'
ORDER BY ISNULL(CAST(PARENT_ID AS NVARCHAR(20)), CAST(ID AS NVARCHAR(20))), NAME;

PRINT '###CHANNELS###';
SELECT ISNULL(e.NAME,'(bilinmeyen bilesen)') + '|' + ISNULL(s.NAME,'') + '|' + ISNULL(s.SERVICE_MODE,'') + '|' +
       ISNULL(s.OPERATION_MODE,'') + '|' + CASE WHEN s.IS_ENABLE=1 THEN '1' ELSE '0' END
FROM WS_SM_SERVICE_SETTINGS s
LEFT JOIN WS_SM_SITE_ELEMENTS e ON e.ID = s.PARENT_ID
WHERE (e.ELEMENT_TYPE IS NULL OR e.ELEMENT_TYPE NOT LIKE '%DUMMY%') AND s.IS_ENABLE = 1
ORDER BY e.NAME, s.NAME;

-- ONEMLI: WS_PLC_POLICIES, musterinin kendi olusturdugu politikalarin (DEFINITION_TYPE=
-- 'C_USER_DEFINE') YANINDA Forcepoint'in HAZIR/KUTUPHANE sablon politikalarini da
-- (DEFINITION_TYPE='A_PREDEFINE', "Policy__..." on ekli, YUZLERCE satir, musteri tarafindan HIC
-- KULLANILMIYOR) icerir. Sadece C_USER_DEFINE saymazsak "Toplam Politika" 500+ cikip FSM konsolundaki
-- "Manage DLP Policies" ekranindaki gercek sayidan (test ortaminda 7) COK farkli gorunur -
-- GERCEK musteri ortaminda dogrulandi (2026-09-24, kesif9).
PRINT '###POLICY_SUMMARY###';
SELECT CAST(COUNT(*) AS NVARCHAR(20)) + '|' + CAST(SUM(CASE WHEN IS_ENABLED=1 THEN 1 ELSE 0 END) AS NVARCHAR(20))
FROM WS_PLC_POLICIES
WHERE DEFINITION_TYPE = 'C_USER_DEFINE';

-- Forcepoint politikalari DATA_TYPE'a gore 2 AYRI konsol ekraninda yonetilir: 'NETWORKING'
-- (Manage DLP Policies) ve 'DISCOVERY' (Manage Discovery Policies). Bir DATA_TYPE=DISCOVERY
-- politika NETWORK ekraninda GORUNMEZ - bu NORMAL, hata degil (gercek ortamda dogrulandi,
-- 2026-09-24, kesif11: "Bunuyakala" DISCOVERY oldugu icin Network ekraninda gorunmuyordu).
PRINT '###POLICY_BY_TYPE###';
SELECT ISNULL(DATA_TYPE,'(bilinmeyen)') + '|' + CAST(COUNT(*) AS NVARCHAR(20)) + '|' + CAST(SUM(CASE WHEN IS_ENABLED=1 THEN 1 ELSE 0 END) AS NVARCHAR(20))
FROM WS_PLC_POLICIES
WHERE DEFINITION_TYPE = 'C_USER_DEFINE'
GROUP BY DATA_TYPE
ORDER BY DATA_TYPE;

PRINT '###POLICY_DISABLED###';
-- Not: POLICY_ENTITY_STATUS kolonu KASITLI OLARAK gosterilmiyor - devre disi (IS_ENABLED=0)
-- politikalarda da genelde 'ACTIVE' degeri tasiyor (silinmemis/arsivlenmemis anlaminda), bu da
-- "Devre Dışı" basligi altinda "ACTIVE" yazip kafa karistiriyordu (gercek ortamda goruldu).
SELECT ISNULL(REPLACE(NAME,'|','/'),'') + '|' + ISNULL(CONVERT(NVARCHAR(19),UPDATE_DATE,120),'')
FROM WS_PLC_POLICIES
WHERE IS_ENABLED = 0 AND DEFINITION_TYPE = 'C_USER_DEFINE'
ORDER BY NAME;

-- Incident (event) tablolari tarihe gore parcalanmis (PA_EVENTS_<tarih>); tablo adlari
-- once bulunur, sonra dinamik UNION ALL ile toplam/son donem/sayimlar hesaplanir.
DECLARE @union NVARCHAR(MAX);
SELECT @union = STUFF((
    SELECT ' UNION ALL SELECT INSERT_DATE, STATUS FROM ' + QUOTENAME(name)
    FROM sys.tables
    WHERE name LIKE 'PA[_]EVENTS[_]%'
      AND name NOT LIKE 'PA[_]EVENTS[_]DEST%'
      AND name NOT LIKE 'PA[_]EVENTS[_]PARAMS%'
    FOR XML PATH('')), 1, 11, '');

-- ONEMLI: "Zaman Parcalari" tablosu ARTIK PA_EVENT_PARTITION_CATALOG'a DEGIL, GERCEKTEN BULUNAN
-- PA_EVENTS_<suffix> tablolarina dayanir (asagidaki toplamla HER ZAMAN eslesir - eskiden sadece
-- kataloga bakiliyordu, katalogda olmayan eski/varsayilan bir tablo (ornek: PA_EVENTS_110000)
-- toplami yukseltip kataloglanan parca toplamiyla UYUMSUZ gorunmesine sebep oluyordu - 2026-09-24
-- gercek calistirmada fark edildi, boyle duzeltildi). Katalogdaki tarih araligi VARSA eklenir.
DECLARE @unionCounts NVARCHAR(MAX);
SELECT @unionCounts = STUFF((
    SELECT ' UNION ALL SELECT ''' + name + ''' AS TBL, ''' + REPLACE(name, 'PA_EVENTS_', '') + ''' AS SFX, COUNT(*) AS CNT FROM ' + QUOTENAME(name)
    FROM sys.tables
    WHERE name LIKE 'PA[_]EVENTS[_]%'
      AND name NOT LIKE 'PA[_]EVENTS[_]DEST%'
      AND name NOT LIKE 'PA[_]EVENTS[_]PARAMS%'
    FOR XML PATH('')), 1, 11, '');

PRINT '###INCIDENT_BY_TABLE###';
IF @unionCounts IS NOT NULL
BEGIN
    DECLARE @sqlByTable NVARCHAR(MAX) = N'
        SELECT t.TBL + ''|'' + CAST(t.CNT AS NVARCHAR(20)) + ''|'' +
               ISNULL(CONVERT(NVARCHAR(19), c.FROM_DATE, 120), '''') + ''|'' +
               ISNULL(CONVERT(NVARCHAR(19), c.TO_DATE, 120), '''') + ''|'' +
               ISNULL(c.STATUS, '''')
        FROM (' + @unionCounts + N') t
        LEFT JOIN PA_EVENT_PARTITION_CATALOG c ON CAST(c.PARTITION_INDEX AS NVARCHAR(20)) = t.SFX
        ORDER BY t.SFX DESC;';
    EXEC sp_executesql @sqlByTable;
END

PRINT '###INCIDENT_TOTAL###';
IF @union IS NOT NULL
BEGIN
    DECLARE @sqlTotal NVARCHAR(MAX) = N'SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM (' + @union + N') u;';
    EXEC sp_executesql @sqlTotal;
END
ELSE SELECT '0';

PRINT '###INCIDENT_RECENT###';
IF @union IS NOT NULL
BEGIN
    DECLARE @sqlRecent NVARCHAR(MAX) = N'SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM (' + @union + N') u WHERE INSERT_DATE >= DATEADD(day,-{0},GETDATE());';
    SET @sqlRecent = REPLACE(@sqlRecent, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlRecent;
END
ELSE SELECT '0';

PRINT '###INCIDENT_7DAYS###';
IF @union IS NOT NULL
BEGIN
    DECLARE @sql7 NVARCHAR(MAX) = N'SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM (' + @union + N') u WHERE INSERT_DATE >= DATEADD(day,-7,GETDATE());';
    EXEC sp_executesql @sql7;
END
ELSE SELECT '0';

-- STATUS kodu -> isim eslemesi PA_RP_STATUS ile DOGRULANMISTIR (2026-09-24, kesif13: 1=New,
-- 3=In Process, 5=Closed, 7=False positive, 9=Escalated - PA_RP_POLICY_NAMES ile ayni desende
-- bir "reporting" eslesme tablosu). LEFT JOIN kullanilir; eslesmeyen/bilinmeyen bir kod gelirse
-- isim bos doner, PowerShell tarafinda ham kod fallback olarak gosterilir.
PRINT '###INCIDENT_BY_STATUS###';
IF @union IS NOT NULL
BEGIN
    DECLARE @sqlStatus NVARCHAR(MAX) = N'
        SELECT CAST(ISNULL(u.STATUS,-1) AS NVARCHAR(20)) + ''|'' + CAST(COUNT(*) AS NVARCHAR(20)) + ''|'' + ISNULL(s.NAME, '''')
        FROM (' + @union + N') u
        LEFT JOIN PA_RP_STATUS s ON s.ID = u.STATUS
        GROUP BY u.STATUS, s.NAME
        ORDER BY COUNT(*) DESC;';
    EXEC sp_executesql @sqlStatus;
END

-- Incident -> Politika/Kural adi kirilimi. PA_EVENT_POLICIES_<suffix>.POLICY_NAME_ID ->
-- PA_RP_POLICY_NAMES.ID eslemesi GERCEK VERIYLE DOGRULANMISTIR (2026-09-24, kesif7). Her
-- PA_EVENT_POLICIES_<suffix> tablosu, kendi INSERT_DATE'i icin ayni suffix'li PA_EVENTS_<suffix>
-- tablosuyla ID uzerinden eslestirilir (sadece her IKI tablo da varsa dahil edilir).
DECLARE @unionPolicy NVARCHAR(MAX);
SELECT @unionPolicy = STUFF((
    SELECT ' UNION ALL SELECT ep.POLICY_NAME_ID AS PNID, ev.INSERT_DATE AS IDT, ep.EVENT_ID AS EID FROM ' + QUOTENAME(pe.name) + ' ep JOIN ' + QUOTENAME(ev.name) + ' ev ON ev.ID = ep.EVENT_ID'
    FROM sys.tables pe
    JOIN sys.tables ev ON ev.name = 'PA_EVENTS_' + REPLACE(pe.name, 'PA_EVENT_POLICIES_', '')
    WHERE pe.name LIKE 'PA[_]EVENT[_]POLICIES[_]%'
    FOR XML PATH('')), 1, 11, '');

-- COUNT(DISTINCT EID) kullanilir (COUNT(*) DEGIL): PA_EVENT_POLICIES ayni event icin birden fazla
-- satir uretebilir (ornek: bir olay hem ust politikada hem alt kuralda eslesirse, veya bir kuralda
-- birden fazla metin eslesmesi olursa) - COUNT(*) ayni incident'i BIRDEN FAZLA sayardi. DISTINCT
-- EVENT_ID ile "bu politikayi/kurali kac FARKLI incident tetikledi" dogru sekilde hesaplanir. Yine
-- de bir incident BIRDEN FAZLA FARKLI politika/kurali tetikleyebildigi icin (ornek: hem ust politika
-- hem alt kural PNID'si ayri satir olarak duser) TUM politikalarin toplami yine de toplam incident
-- sayisindan YUKSEK OLABILIR - bu artik cift-sayim degil, gercek/beklenen bir durum.
PRINT '###TOP_POLICIES###';
IF @unionPolicy IS NOT NULL
BEGIN
    DECLARE @sqlTopPol NVARCHAR(MAX) = N'
        SELECT TOP 10 ISNULL(REPLACE(pn.NAME,''|'',''/''),''(bilinmeyen: '' + CAST(u.PNID AS NVARCHAR(20)) + '')'') + ''|'' + CAST(COUNT(DISTINCT u.EID) AS NVARCHAR(20))
        FROM (' + @unionPolicy + N') u
        LEFT JOIN PA_RP_POLICY_NAMES pn ON pn.ID = u.PNID
        WHERE u.IDT >= DATEADD(day,-{0},GETDATE())
        GROUP BY pn.NAME, u.PNID
        ORDER BY COUNT(DISTINCT u.EID) DESC;';
    SET @sqlTopPol = REPLACE(@sqlTopPol, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlTopPol;
END

-- Secili gun araliginda hic incident yoksa (ornek: uzun suredir sakin bir ortam) yukaridaki
-- bolum bombos gorunur ve kullanissiz olur. Bu yuzden TUM ZAMANLARIN en cok ihlal edilen
-- politikalarini da ayrica hesapliyoruz - rapor, lookback bos ciktiysa buna duser.
PRINT '###TOP_POLICIES_ALLTIME###';
IF @unionPolicy IS NOT NULL
BEGIN
    DECLARE @sqlTopPolAll NVARCHAR(MAX) = N'
        SELECT TOP 10 ISNULL(REPLACE(pn.NAME,''|'',''/''),''(bilinmeyen: '' + CAST(u.PNID AS NVARCHAR(20)) + '')'') + ''|'' + CAST(COUNT(DISTINCT u.EID) AS NVARCHAR(20))
        FROM (' + @unionPolicy + N') u
        LEFT JOIN PA_RP_POLICY_NAMES pn ON pn.ID = u.PNID
        GROUP BY pn.NAME, u.PNID
        ORDER BY COUNT(DISTINCT u.EID) DESC;';
    EXEC sp_executesql @sqlTopPolAll;
END

-- Ust tablodaki satirlarin toplami neden "Toplam Incident"i asabiliyor sorusunu NETLESTIRMEK icin:
-- en az bir politika/kural ile eslesen FARKLI incident sayisini AYRICA hesapliyoruz. Bu deger HER
-- ZAMAN Toplam Incident'e esit veya kucuktur (bir alt kumesi) - tablo satirlarinin toplami ise
-- (bir incident birden fazla politikayla eslesebildigi icin) bundan da BUYUK olabilir.
PRINT '###POLICY_DISTINCT_INCIDENTS###';
IF @unionPolicy IS NOT NULL
BEGIN
    DECLARE @sqlDistAll NVARCHAR(MAX) = N'SELECT CAST(COUNT(DISTINCT u.EID) AS NVARCHAR(20)) FROM (' + @unionPolicy + N') u;';
    EXEC sp_executesql @sqlDistAll;
END
ELSE SELECT '0';

PRINT '###POLICY_DISTINCT_INCIDENTS_RECENT###';
IF @unionPolicy IS NOT NULL
BEGIN
    DECLARE @sqlDistRecent NVARCHAR(MAX) = N'SELECT CAST(COUNT(DISTINCT u.EID) AS NVARCHAR(20)) FROM (' + @unionPolicy + N') u WHERE u.IDT >= DATEADD(day,-{0},GETDATE());';
    SET @sqlDistRecent = REPLACE(@sqlDistRecent, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlDistRecent;
END
ELSE SELECT '0';

-- Son N gunde HIC incident uretmeyen etkin/kullanici-tanimli politikalar - Symantec DLP HC'deki
-- "unusedPolicyFile" (NOT EXISTS) mantiginin karsiligi. PA_RP_POLICY_NAMES.NAME uzerinden esleme
-- yapilir (PA_EVENT_POLICIES.POLICY_NAME_ID -> PA_RP_POLICY_NAMES.ID DOGRULANMISTI, kesif7;
-- WS_PLC_POLICIES.ID ile PA_RP_POLICY_NAMES.ID FARKLI ID uzaylari oldugu icin isim eslemesi
-- kullanilir).
PRINT '###UNUSED_POLICIES###';
IF @unionPolicy IS NOT NULL AND OBJECT_ID('PA_RP_POLICY_NAMES','U') IS NOT NULL
BEGIN
    DECLARE @sqlUnused NVARCHAR(MAX) = N'
        SELECT REPLACE(p.NAME,''|'',''/'') + ''|'' + ISNULL(REPLACE(p.DATA_TYPE,''|'',''/''),'''')
        FROM WS_PLC_POLICIES p
        WHERE p.DEFINITION_TYPE = ''C_USER_DEFINE'' AND p.IS_ENABLED = 1
          AND NOT EXISTS (
              SELECT 1 FROM (' + @unionPolicy + N') u
              JOIN PA_RP_POLICY_NAMES pn ON pn.ID = u.PNID
              WHERE pn.NAME = p.NAME AND u.IDT >= DATEADD(day,-{0},GETDATE())
          )
        ORDER BY p.NAME;';
    SET @sqlUnused = REPLACE(@sqlUnused, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlUnused;
END

-- Kanal (channel) dagilimi + Network gonderici / Endpoint kullanici kirilimi - PA_RP_SERVICES ve
-- PA_MNG_USERS ile DOGRULANMISTIR (2026-09-24, kesif17). PA_EVENTS.SERVICE_ID, PA_RP_SERVICES.ID'ye
-- esitlenir (PA_RP_SERVICES.SERVICE_ID kolonu DEGIL - farkli/dahili bir protokol ID'si, kafa
-- karistirici ama gercek veriyle DOGRULANDI: SERVICE_ID=20458 -> PA_RP_SERVICES.ID=20458 ->
-- CHANNEL_NAME='Endpoint HTTPS'). CHANNEL_TYPE 'ENDPOINT_%' ile baslayanlar Endpoint ajani
-- kanallari, digerleri (HTTP/HTTPS/SMTP/CASB/DISCOVERY vb.) Network/harici kanallar - Symantec
-- HC'deki "Network gonderici" / "Endpoint kullanici" ayrimini bu sekilde yansitiyoruz.
DECLARE @unionChannel NVARCHAR(MAX);
SELECT @unionChannel = STUFF((
    SELECT ' UNION ALL SELECT INSERT_DATE, SERVICE_ID, RUN_AS_USER, SOURCE_ID FROM ' + QUOTENAME(name)
    FROM sys.tables
    WHERE name LIKE 'PA[_]EVENTS[_]%'
      AND name NOT LIKE 'PA[_]EVENTS[_]DEST%'
      AND name NOT LIKE 'PA[_]EVENTS[_]PARAMS%'
    FOR XML PATH('')), 1, 11, '');

-- Incident Tur Dagilimi (Endpoint/Network/Discovery) + Detection Server Bazinda Incident Dagilimi -
-- Symantec DLP HC'deki "IncidentsByType"/"IncidentsByServer" karsiligi, TUM ZAMANLAR (lookback
-- filtresi YOK - Symantec'teki orijinal sorgu da filtresiz, Toplam Incident kartinin hemen altinda
-- gosterilir). CHANNEL_TYPE 'ENDPOINT_DISCOVERY' -> Discovery, diger 'ENDPOINT_%' -> Endpoint,
-- DISCOVERY (Crawler) -> Discovery, digerleri (HTTP/HTTPS/SMTP/CASB vb.) -> Network.
PRINT '###INCIDENT_TYPE###';
IF @unionChannel IS NOT NULL AND OBJECT_ID('PA_RP_SERVICES','U') IS NOT NULL
BEGIN
    DECLARE @sqlIncType NVARCHAR(MAX) = N'
        SELECT CASE
                 WHEN s.CHANNEL_TYPE LIKE ''ENDPOINT[_]DISCOVERY%'' THEN ''Discovery''
                 WHEN s.CHANNEL_TYPE LIKE ''ENDPOINT[_]%'' THEN ''Endpoint''
                 WHEN s.CHANNEL_TYPE = ''DISCOVERY'' THEN ''Discovery''
                 WHEN s.CHANNEL_TYPE IS NULL THEN ''Bilinmeyen''
                 ELSE ''Network''
               END + ''|'' + CAST(COUNT(*) AS NVARCHAR(20))
        FROM (' + @unionChannel + N') u
        LEFT JOIN PA_RP_SERVICES s ON s.ID = u.SERVICE_ID
        GROUP BY CASE
                 WHEN s.CHANNEL_TYPE LIKE ''ENDPOINT[_]DISCOVERY%'' THEN ''Discovery''
                 WHEN s.CHANNEL_TYPE LIKE ''ENDPOINT[_]%'' THEN ''Endpoint''
                 WHEN s.CHANNEL_TYPE = ''DISCOVERY'' THEN ''Discovery''
                 WHEN s.CHANNEL_TYPE IS NULL THEN ''Bilinmeyen''
                 ELSE ''Network''
               END
        ORDER BY COUNT(*) DESC;';
    EXEC sp_executesql @sqlIncType;
END

-- Detection Server Bazinda Incident Dagilimi - PA_RP_SERVICES.AGENT_NAME TEK BASINA yeterli DEGIL
-- (butun Endpoint kanallari icin AYNI "Endpoint Agent" degerini tasiyor, 2026-09-25'te kullanici
-- BUNU fark etti - 4 satirin hepsi ayni etiketle geliyordu). AGENT_NAME + CHANNEL_NAME BIRLESTIRILIR
-- (orn. "Endpoint Agent (Endpoint HTTPS)") - her PA_RP_SERVICES.ID icin ESSIZ, anlamli bir etiket
-- garanti eder (Network taraftaki servisler zaten kendi basina essiz AGENT_NAME tasiyor: "Forcepoint
-- Email Security on...", "Protector API Agent" vb. - onlarda CHANNEL_NAME eklenmesi zarar vermez).
PRINT '###INCIDENT_BY_SERVER###';
IF @unionChannel IS NOT NULL AND OBJECT_ID('PA_RP_SERVICES','U') IS NOT NULL
BEGIN
    DECLARE @sqlIncServer NVARCHAR(MAX) = N'
        SELECT ISNULL(REPLACE(s.AGENT_NAME + '' ('' + s.CHANNEL_NAME + '')'',''|'',''/''),''(bilinmeyen: '' + CAST(u.SERVICE_ID AS NVARCHAR(20)) + '')'') + ''|'' + CAST(COUNT(*) AS NVARCHAR(20))
        FROM (' + @unionChannel + N') u
        LEFT JOIN PA_RP_SERVICES s ON s.ID = u.SERVICE_ID
        GROUP BY s.AGENT_NAME, s.CHANNEL_NAME, u.SERVICE_ID
        ORDER BY COUNT(*) DESC;';
    EXEC sp_executesql @sqlIncServer;
END

PRINT '###ENDPOINT_USERS###';
IF @unionChannel IS NOT NULL AND OBJECT_ID('PA_RP_SERVICES','U') IS NOT NULL
BEGIN
    DECLARE @sqlEpUsers NVARCHAR(MAX) = N'
        SELECT TOP 10 ISNULL(REPLACE(u.RUN_AS_USER,''|'',''/''),''(bilinmiyor)'') + ''|'' + CAST(COUNT(*) AS NVARCHAR(20))
        FROM (' + @unionChannel + N') u
        JOIN PA_RP_SERVICES s ON s.ID = u.SERVICE_ID
        WHERE u.INSERT_DATE >= DATEADD(day,-{0},GETDATE()) AND s.CHANNEL_TYPE LIKE ''ENDPOINT[_]%''
        GROUP BY u.RUN_AS_USER
        ORDER BY COUNT(*) DESC;';
    SET @sqlEpUsers = REPLACE(@sqlEpUsers, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlEpUsers;
END

PRINT '###NETWORK_SENDERS###';
IF @unionChannel IS NOT NULL AND OBJECT_ID('PA_RP_SERVICES','U') IS NOT NULL AND OBJECT_ID('PA_MNG_USERS','U') IS NOT NULL
BEGIN
    DECLARE @sqlNetSenders NVARCHAR(MAX) = N'
        SELECT TOP 10 REPLACE(ISNULL(m.LOGIN_NAME, ISNULL(m.EMAIL, ISNULL(m.HOSTNAME, ISNULL(m.IP, ''(bilinmiyor)'')))),''|'',''/'') + ''|'' + CAST(COUNT(*) AS NVARCHAR(20))
        FROM (' + @unionChannel + N') u
        JOIN PA_RP_SERVICES s ON s.ID = u.SERVICE_ID
        LEFT JOIN PA_MNG_USERS m ON m.ID = u.SOURCE_ID
        WHERE u.INSERT_DATE >= DATEADD(day,-{0},GETDATE()) AND s.CHANNEL_TYPE NOT LIKE ''ENDPOINT[_]%''
        GROUP BY ISNULL(m.LOGIN_NAME, ISNULL(m.EMAIL, ISNULL(m.HOSTNAME, ISNULL(m.IP, ''(bilinmiyor)''))))
        ORDER BY COUNT(*) DESC;';
    SET @sqlNetSenders = REPLACE(@sqlNetSenders, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlNetSenders;
END

PRINT '###ADMINS###';
SELECT ISNULL(REPLACE(NAME,'|','/'),'') + '|' + ISNULL(EMAIL,'') + '|' + ISNULL(ADMIN_TYPE,'') + '|' +
       ISNULL(ACCOUNT_TYPE,'') + '|' + CASE WHEN ACCOUNT_IS_DISABLED=1 THEN '1' ELSE '0' END + '|' +
       ISNULL(CAST(ROLE_ID AS NVARCHAR(20)),'') + '|' + CASE WHEN EXTERNAL_USER_DN IS NOT NULL THEN '1' ELSE '0' END
FROM PA_ADMINS
WHERE ADMIN_TYPE <> 'PREDEFINED_NOT_VISBLE'
ORDER BY NAME;

PRINT '###ROLES###';
SELECT ISNULL(REPLACE(NAME,'|','/'),'') + '|' + ISNULL(REPLACE(DESCRIPTION,'|','/'),'') + '|' + ISNULL(ROLE_TYPE,'')
FROM PA_ROLES
WHERE ROLE_TYPE <> 'PREDEFINED_NOT_VISBLE'
ORDER BY NAME;

PRINT '###LDAP_COUNT###';
SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM PA_REPO_LDAP_QUERY;

PRINT '###ENDPOINT_KNOWN_COUNT###';
SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM PA_REPO_COMPUTERS WHERE SOURCE_TYPE = 'EXTERNAL';

PRINT '###AD_SYNC###';
IF OBJECT_ID('PA_REPO_COMPUTERS','U') IS NOT NULL AND OBJECT_ID('PA_REPO_USERS','U') IS NOT NULL
BEGIN
    SELECT 'Computers|' + ISNULL(CAST(COUNT(*) AS NVARCHAR(20)),'0') + '|' +
           ISNULL(CAST(SUM(CASE WHEN SYNCH_STATUS='SYNCHRONIZED' THEN 1 ELSE 0 END) AS NVARCHAR(20)),'0')
    FROM PA_REPO_COMPUTERS WHERE SOURCE_TYPE='EXTERNAL'
    UNION ALL
    SELECT 'Users|' + ISNULL(CAST(COUNT(*) AS NVARCHAR(20)),'0') + '|' +
           ISNULL(CAST(SUM(CASE WHEN SYNCH_STATUS='SYNCHRONIZED' THEN 1 ELSE 0 END) AS NVARCHAR(20)),'0')
    FROM PA_REPO_USERS WHERE SOURCE_TYPE='EXTERNAL';
END

PRINT '###ARCHIVE_CONF###';
IF OBJECT_ID('PA_EVENT_ARCHIVE_CONF','U') IS NOT NULL
BEGIN
    SELECT TOP 5
        CASE WHEN IS_SERVER_LOCAL=1 THEN 'Yerel' ELSE 'Uzak' END + '|' +
        ISNULL(REPLACE(LOCAL_DIRECTORY,'|','/'),'') + '|' + ISNULL(REPLACE(ARCHIVE_TEMP_DIR,'|','/'),'') + '|' +
        ISNULL(CAST(MAX_ONLINE AS NVARCHAR(20)),'') + '|' + ISNULL(CAST(MAX_OFFLINE AS NVARCHAR(20)),'') + '|' +
        ISNULL(CAST(MAX_ONLINE_INCIDENTS AS NVARCHAR(20)),'') + '|' + ISNULL(CAST(MAX_OFFLINE_DISK_SPACE AS NVARCHAR(20)),'')
    FROM PA_EVENT_ARCHIVE_CONF;
END

-- Endpoint Status - FSM konsolundaki "Status > Endpoint Status" ekraniyla BIREBIR ayni (kesif19,
-- 2026-09-25 DOGRULANDI - konsol ekran goruntusu ile PA_DYNAMIC_STATUS_PROPS icerigi birebir
-- eslesti). Bu bir ALARM/UYARI listesi DEGIL (Symantec'teki "Agent Uyarıları" severity/kritiklik
-- kavraminin Forcepoint'te NET bir karsiligi yok - arastirildi, KAPANDI), sadece canli durum panosu.
-- eps_os_OperationStatus (2026-09-25, kullanicinin kendi sorgusuyla DOGRULANDI): "Bypass Endpoint..."
-- ONCESI degeri OPERATION_NORMAL, SONRASI degeri OPERATION_REMOTE_BYPASS_ACTIVE olarak GOZLENDI -
-- bu, FSM konsolundaki "Client status: Disabled" alaninin GERCEK, CANLI karsiligi. NOT: su ana kadar
-- SADECE bu iki deger GOZLEMLENDI - baska durum degerleri (orn. yerel bypass, farkli bir arizali
-- durum) olabilir, bu yuzden HTML tarafinda deger OLDUGU GIBI gosterilir, bilinmeyen degerler
-- UYDURULARAK yorumlanmaz.
PRINT '###ENDPOINT_STATUS###';
IF OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NOT NULL AND OBJECT_ID('PA_DYNAMIC_STATUS_PROPS','U') IS NOT NULL
BEGIN
    SELECT
        ISNULL(REPLACE(s.[KEY],'|','/'),'') + '|' +
        ISNULL(CONVERT(NVARCHAR(19), s.UPDATE_DATE, 120),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_IPAddress' THEN p.STR_VALUE END),'|','/'),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_LoggedInUsers' THEN p.STR_VALUE END),'|','/'),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_ProfileName' THEN p.STR_VALUE END),'|','/'),'') + '|' +
        ISNULL(CAST(MAX(CASE WHEN p.NAME='eps_os_Synced' THEN p.INT_VALUE END) AS NVARCHAR(5)),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_DiscoveryStatus' THEN p.STR_VALUE END),'|','/'),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_AgentInstallationVersion' THEN p.STR_VALUE END),'|','/'),'') + '|' +
        ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_OperationStatus' THEN p.STR_VALUE END),'|','/'),'')
    FROM PA_DYNAMIC_STATUS s
    LEFT JOIN PA_DYNAMIC_STATUS_PROPS p ON p.DYNAMIC_STATUS_ID = s.ID
    GROUP BY s.ID, s.[KEY], s.UPDATE_DATE
    ORDER BY s.[KEY];
END

-- Endpoint Bypass Code uretim kaydi - PA_AUDIT_INFO ile DOGRULANMISTIR (2026-09-25, kesif22+
-- kesif23: deger-bazli tam veritabani taramasi PA_AUDIT_INFO.MESSAGE'i buldu, icerik "Endpoint
-- Bypass Code: Generated for host <hostname>" formatinda DOGRULANDI). NOT: Bu bir OLAY KAYDIDIR
-- (audit log) - "su an hala aktif/bypass edilmis mi" GARANTI ETMEZ, sadece "ne zaman kod uretildi"yi
-- gosterir; kodun gecerlilik suresi/hala aktif olup olmadigi bu tablodan ANLASILAMAZ - rapor
-- bunu ACIKCA belirtir, "su an disabled" diye IDDIA ETMEZ.
PRINT '###ENDPOINT_BYPASS_LOG###';
IF OBJECT_ID('PA_AUDIT_INFO','U') IS NOT NULL AND OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NOT NULL
BEGIN
    DECLARE @sqlBypassLog NVARCHAR(MAX) = N'
        SELECT REPLACE(s.[KEY],''|'',''/'') + ''|'' + ISNULL(CONVERT(NVARCHAR(19), MAX(a.GENERATION_TIME_TS), 120),'''')
        FROM PA_DYNAMIC_STATUS s
        LEFT JOIN PA_AUDIT_INFO a ON a.MESSAGE LIKE ''Endpoint Bypass Code%'' AND a.MESSAGE LIKE ''%'' + s.[KEY] + ''%''
            AND a.GENERATION_TIME_TS >= DATEADD(day,-{0},GETDATE())
        GROUP BY s.[KEY];';
    SET @sqlBypassLog = REPLACE(@sqlBypassLog, '{0}', CAST(__LOOKBACK_DAYS__ AS NVARCHAR(10)));
    EXEC sp_executesql @sqlBypassLog;
END

-- Syslog ayarlari PA_CONFIG_PROPERTIES tablosunda NAME/VALUE olarak tutulur - Forcepoint'in resmi
-- destek makalesiyle DOGRULANMISTIR (support.forcepoint.com/s/article/000018697, "Enable/Disable
-- Forcepoint DLP Local Syslog Logging"). 2026-09-22'deki ilk arastirma YANLIS tabloda (WS_SM_
-- CONFIGURATION_PROPERTIES) aramisti, sifir sonuc almisti - gercek tablo bu.
PRINT '###SYSLOG###';
IF OBJECT_ID('PA_CONFIG_PROPERTIES','U') IS NOT NULL
BEGIN
    SELECT ISNULL(REPLACE(NAME,'|','/'),'') + '|' + ISNULL(REPLACE(VALUE,'|','/'),'')
    FROM PA_CONFIG_PROPERTIES
    WHERE NAME IN ('INCIDENTS_SYSLOG-HOSTNAME','INCIDENTS_SYSLOG-PORT','INCIDENTS_SYSLOG-FACILITY','INCIDENTS_SYSLOG-PRINT-FACILITY','INCIDENTS_SYSLOG-ADDITIVITY');
END

-- OCR/MIP/RMS ozellik bayraklari - PA_CONFIG_PROPERTIES icinde DOGRULANMISTIR (2026-09-24, kesif15).
-- AD/LDAP baglanti detayi (DC adresi/port/SSL) veritabaninda TUTULMUYOR (genis kolon taramasi
-- SIFIR sonuc verdi - PA_REPO_LDAP_QUERY sadece KAYITLI SORGU tanimini tutuyor, sunucu baglanti
-- bilgisini DEGIL); bu yuzden Entegrasyon Durumu tablosunda o satir icin DB disi bir not gosterilecek.
PRINT '###INTEGRATIONS###';
IF OBJECT_ID('PA_CONFIG_PROPERTIES','U') IS NOT NULL
BEGIN
    SELECT ISNULL(NAME,'') + '|' + ISNULL(GROUP_NAME,'') + '|' + ISNULL(REPLACE(VALUE,'|','/'),'')
    FROM PA_CONFIG_PROPERTIES
    WHERE (NAME = 'FSMEnableOCR' AND GROUP_NAME IN ('DPS_OCR_CONFIGURATIONS','GLOBAL_OCR_CONFIGURATIONS'))
       OR (NAME = 'IS_MIP_FEATURE_ENABLED' AND GROUP_NAME = 'MIP_GENERAL_SETTINGS')
       OR (NAME = 'IS_RMS_FEATURE_ENABLED' AND GROUP_NAME = 'RMS_GENERAL_SETTINGS');
END

-- File Labeling (Boldon James / MIP) import durumu - FP_CLASSIFICATION_TAGS_INFO tablosunda
-- DOGRULANMISTIR (2026-09-24, kesif16). FSM konsolundaki "Services > Decryption and File Labeling"
-- ekranindaki "File Labeling System / Usage / Label Import Status / Last Successful Import"
-- tablosunun BIREBIR karsiligi.
PRINT '###FILE_LABELING###';
IF OBJECT_ID('FP_CLASSIFICATION_TAGS_INFO','U') IS NOT NULL
BEGIN
    SELECT ISNULL(SYSTEM_TYPE,'') + '|' + ISNULL(CAST(IMPORT_DATE AS NVARCHAR(30)),'') + '|' +
           ISNULL(CAST(TAGS_COUNT AS NVARCHAR(20)),'') + '|' + ISNULL(CAST(ENABLE_APPLY_LABELS AS NVARCHAR(5)),'') + '|' +
           ISNULL(REPLACE(USER_NAME,'|','/'),'') + '|' + ISNULL(LAST_IMPORT_STATUS,'')
    FROM FP_CLASSIFICATION_TAGS_INFO;
END

PRINT '###DISCOVERY_TASKS###';
IF OBJECT_ID('WS_PLC_DISCOVERY_TASKS','U') IS NOT NULL
BEGIN
    SELECT ISNULL(REPLACE(NAME,'|','/'),'') + '|' + CASE WHEN IS_ENABLED=1 THEN '1' ELSE '0' END + '|' +
           ISNULL(DISCOVERY_TASK_TYPE,'') + '|' + ISNULL(OPERATION_STATUS,'')
    FROM WS_PLC_DISCOVERY_TASKS
    ORDER BY NAME;
END

PRINT '###POLICY_LEVELS###';
IF OBJECT_ID('WS_PLC_POLICY_LEVELS','U') IS NOT NULL
BEGIN
    SELECT CAST(COUNT(*) AS NVARCHAR(20)) FROM WS_PLC_POLICY_LEVELS;
END
ELSE SELECT '0';

PRINT '###SQL_DISK###';
BEGIN TRY
    CREATE TABLE #fpfixeddrives (drive CHAR(1), mb_free INT);
    INSERT INTO #fpfixeddrives EXEC xp_fixeddrives;
    SELECT drive + '|' + CAST(mb_free AS NVARCHAR(20)) FROM #fpfixeddrives ORDER BY drive;
    DROP TABLE #fpfixeddrives;
END TRY
BEGIN CATCH
    SELECT 'ERROR|' + ERROR_MESSAGE();
END CATCH

PRINT '###END###';
'@
    $sqlContent = $sqlContent.Replace('__LOOKBACK_DAYS__', [string]$LookbackDays)
    Set-Content -LiteralPath $sqlFile -Value $sqlContent -Encoding UTF8

    $sqlArgs = [System.Collections.Generic.List[string]]::new()
    [void]$sqlArgs.AddRange([string[]]@('-S', $ServerInstance, '-d', $DatabaseName, '-i', $sqlFile, '-o', $outFile, '-h', '-1', '-W', '-s', '|', '-f', '65001'))

    $securePassword = $null
    $plainPassword = $null
    $passwordPointer = [IntPtr]::Zero
    try {
        if ($AuthMode -eq 'Windows') {
            [void]$sqlArgs.Add('-E')
            $result.ConnectedAuth = 'Windows (current session)'
        }
        else {
            $securePassword = Read-Host -Prompt "SQL Server password ($UserName)" -AsSecureString
            $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
            [void]$sqlArgs.Add('-U'); [void]$sqlArgs.Add($UserName)
            [void]$sqlArgs.Add('-P'); [void]$sqlArgs.Add($plainPassword)
            $result.ConnectedAuth = "SQL Login ($UserName)"
        }

        $sqlArgsArray = $sqlArgs.ToArray()
        $sqlStdErr = & $sqlCmdExe.Source $sqlArgsArray 2>&1
        $exitCode = $LASTEXITCODE
        $sqlErrorLines = @($sqlStdErr | Where-Object { $_ -match 'Msg \d+|Login failed|Cannot open|Error:' })
        if ($sqlErrorLines.Count -gt 0) {
            $result.SqlWarnings = ($sqlErrorLines -join ' | ')
        }
    }
    catch {
        $result.DatabaseLogin = 'Failed'
        $result.ErrorMessage = "Unexpected error (sqlcmd call): $($_.Exception.GetType().FullName): $($_.Exception.Message) [line: $($_.InvocationInfo.ScriptLineNumber)]"
        return [pscustomobject]$result
    }
    finally {
        $plainPassword = $null
        $securePassword = $null
        if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    }

    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $outFile)) {
        $result.DatabaseLogin = 'Failed'
        $result.ErrorMessage = "sqlcmd failed with exit code $exitCode. Check the server name, database name, and authentication details."
        return [pscustomobject]$result
    }

    $allLines = Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue
    if (-not $allLines -or ($allLines -join '') -notmatch '###END###') {
        $result.DatabaseLogin = 'Failed'
        $result.ErrorMessage = 'sqlcmd ran but the expected output was not received (this could be a connection or permission issue).'
        $errLines = @($allLines | Where-Object { $_ -match 'Msg \d+|Login failed|Cannot open' })
        if ($errLines.Count -gt 0) { $result.ErrorMessage += ' Detail: ' + ($errLines -join ' | ') }
        return [pscustomobject]$result
    }

    $result.DatabaseLogin = 'Successful'

    # Ciktiyi ###MARKER### satirlarina gore bolumlere ayir
    $sections = [ordered]@{}
    $currentKey = $null
    $buffer = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $allLines) {
        if ($line -match '^###([A-Z0-9_]+)###$') {
            if ($null -ne $currentKey) { $sections[$currentKey] = $buffer.ToArray() }
            $currentKey = $Matches[1]
            $buffer = [System.Collections.Generic.List[string]]::new()
        }
        elseif ($null -ne $currentKey -and $line.Trim() -ne '') {
            [void]$buffer.Add($line)
        }
    }
    if ($null -ne $currentKey) { $sections[$currentKey] = $buffer.ToArray() }

    if ($sections.Contains('CONN') -and $sections['CONN'].Count -gt 0) {
        $result.SqlServerVersion = ($sections['CONN'][0]).Trim()
    }

    if ($sections.Contains('FPVERSION') -and $sections['FPVERSION'].Count -gt 0) {
        $result.FpVersion = $sections['FPVERSION'][0].Trim()
        $result.FpVersionStatus = 'Successful'
    } else { $result.FpVersionStatus = 'No data' }

    if ($sections.Contains('COMPONENTS')) {
        $comp = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['COMPONENTS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 11) {
                [void]$comp.Add([pscustomobject]@{
                    Id = $p[0]; Name = $p[1]; ElementType = $p[2]; HostName = $p[3]; Ip = $p[4]
                    ElementStatus = $p[5]; DeployResult = $p[6]; DeployDate = $p[7]; Version = $p[8]
                    ParentId = $p[9]; ResultDesc = $p[10]
                })
            }
        }
        $result.Components = $comp.ToArray()
        $result.ComponentsStatus = if ($comp.Count -gt 0) { 'Successful' } else { 'No data' }
    }

    if ($sections.Contains('CHANNELS')) {
        $ch = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['CHANNELS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 5) {
                [void]$ch.Add([pscustomobject]@{ Component = $p[0]; Name = $p[1]; ServiceMode = $p[2]; OperationMode = $p[3]; Enabled = $p[4] })
            }
        }
        $result.Channels = $ch.ToArray()
        $result.ChannelsStatus = if ($ch.Count -gt 0) { 'Successful' } else { 'No data' }
    }

    if ($sections.Contains('POLICY_SUMMARY') -and $sections['POLICY_SUMMARY'].Count -gt 0) {
        $p = $sections['POLICY_SUMMARY'][0] -split '\|'
        if ($p.Count -ge 2) {
            $result.PolicyTotal = $p[0].Trim()
            $result.PolicyEnabled = $p[1].Trim()
            if ($p[0].Trim() -match '^\d+$' -and $p[1].Trim() -match '^\d+$') {
                $result.PolicyDisabled = [string]([int]$p[0].Trim() - [int]$p[1].Trim())
            }
            $result.PolicyStatus = 'Successful'
        }
    }
    if (-not $result.PolicyStatus -or $result.PolicyStatus -eq 'Not tested') { $result.PolicyStatus = 'No data' }

    if ($sections.Contains('POLICY_BY_TYPE')) {
        $pbt = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['POLICY_BY_TYPE']) {
            $p = $l -split '\|'
            if ($p.Count -ge 3) { [void]$pbt.Add([pscustomobject]@{ DataType = $p[0]; Total = $p[1]; Enabled = $p[2] }) }
        }
        $result.PolicyByType = $pbt.ToArray()
    }

    if ($sections.Contains('POLICY_DISABLED')) {
        $dp = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['POLICY_DISABLED']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$dp.Add([pscustomobject]@{ Name = $p[0]; UpdateDate = $p[1] }) }
        }
        $result.DisabledPolicies = $dp.ToArray()
    }

    if ($sections.Contains('INCIDENT_BY_TABLE')) {
        $partitionStatusMap = @{
            'ONLINE_ACTIVE' = 'Online-Active'
            'ONLINE'        = 'Online'
            'ARCHIVING'     = 'Archiving'
            'ARCHIVED'      = 'Archived'
            'OFFLINE'       = 'Offline'
        }
        $parts = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['INCIDENT_BY_TABLE']) {
            $p = $l -split '\|'
            if ($p.Count -ge 5) {
                $rawState = $p[4]
                $partitionId = $p[0] -replace '^PA_EVENTS_', ''
                [void]$parts.Add([pscustomobject]@{
                    Table = $p[0]; PartitionId = $partitionId; EventCount = $p[1]; FromDate = $p[2]; ToDate = $p[3]
                    CatalogState = if ($rawState) { $rawState } else { 'Not in catalog' }
                    StatusDisplay = if (-not $rawState) { 'Not in catalog' } elseif ($partitionStatusMap.ContainsKey($rawState)) { $partitionStatusMap[$rawState] } else { $rawState }
                })
            }
        }
        $result.IncidentPartitions = $parts.ToArray()
    }

    if ($sections.Contains('INCIDENT_TOTAL') -and $sections['INCIDENT_TOTAL'].Count -gt 0) {
        $result.IncidentTotal = $sections['INCIDENT_TOTAL'][0].Trim()
        $result.IncidentStatus = 'Successful'
    } else { $result.IncidentStatus = 'No data' }

    if ($sections.Contains('INCIDENT_RECENT') -and $sections['INCIDENT_RECENT'].Count -gt 0) {
        $result.IncidentRecent = $sections['INCIDENT_RECENT'][0].Trim()
    }

    if ($sections.Contains('INCIDENT_7DAYS') -and $sections['INCIDENT_7DAYS'].Count -gt 0) {
        $result.IncidentLast7Days = $sections['INCIDENT_7DAYS'][0].Trim()
    }

    if ($sections.Contains('INCIDENT_BY_STATUS')) {
        $st = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['INCIDENT_BY_STATUS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) {
                $statusName = if ($p.Count -ge 3 -and $p[2]) { $p[2] } else { "Kod $($p[0])" }
                [void]$st.Add([pscustomobject]@{ StatusCode = $p[0]; Count = $p[1]; StatusName = $statusName })
            }
        }
        $result.IncidentByStatus = $st.ToArray()
    }

    if ($sections.Contains('TOP_POLICIES')) {
        $tp = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['TOP_POLICIES']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$tp.Add([pscustomobject]@{ PolicyName = $p[0]; MatchCount = $p[1] }) }
        }
        $result.TopPolicies = $tp.ToArray()
    }

    if ($sections.Contains('TOP_POLICIES_ALLTIME')) {
        $tpa = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['TOP_POLICIES_ALLTIME']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$tpa.Add([pscustomobject]@{ PolicyName = $p[0]; MatchCount = $p[1] }) }
        }
        $result.TopPoliciesAllTime = $tpa.ToArray()
    }

    if ($sections.Contains('INCIDENT_TYPE')) {
        $it = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['INCIDENT_TYPE']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$it.Add([pscustomobject]@{ IncidentType = $p[0]; Count = $p[1] }) }
        }
        $result.IncidentType = $it.ToArray()
    }

    if ($sections.Contains('INCIDENT_BY_SERVER')) {
        $ibs = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['INCIDENT_BY_SERVER']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$ibs.Add([pscustomobject]@{ ServerName = $p[0]; Count = $p[1] }) }
        }
        $result.IncidentByServer = $ibs.ToArray()
    }

    if ($sections.Contains('UNUSED_POLICIES')) {
        $up = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['UNUSED_POLICIES']) {
            $p = $l -split '\|'
            if ($p.Count -ge 1 -and $p[0]) { [void]$up.Add([pscustomobject]@{ PolicyName = $p[0]; DataType = if ($p.Count -ge 2) { $p[1] } else { '' } }) }
        }
        $result.UnusedPolicies = $up.ToArray()
    }

    if ($sections.Contains('ENDPOINT_USERS')) {
        $eu = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ENDPOINT_USERS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$eu.Add([pscustomobject]@{ UserName = $p[0]; Count = $p[1] }) }
        }
        $result.EndpointUsers = $eu.ToArray()
    }

    if ($sections.Contains('NETWORK_SENDERS')) {
        $ns = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['NETWORK_SENDERS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) { [void]$ns.Add([pscustomobject]@{ SenderName = $p[0]; Count = $p[1] }) }
        }
        $result.NetworkSenders = $ns.ToArray()
    }

    if ($sections.Contains('POLICY_DISTINCT_INCIDENTS') -and $sections['POLICY_DISTINCT_INCIDENTS'].Count -gt 0) {
        $result.PolicyDistinctIncidents = $sections['POLICY_DISTINCT_INCIDENTS'][0].Trim()
    }
    if ($sections.Contains('POLICY_DISTINCT_INCIDENTS_RECENT') -and $sections['POLICY_DISTINCT_INCIDENTS_RECENT'].Count -gt 0) {
        $result.PolicyDistinctIncidentsRecent = $sections['POLICY_DISTINCT_INCIDENTS_RECENT'][0].Trim()
    }

    if ($sections.Contains('ADMINS')) {
        $ad = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ADMINS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 7) {
                [void]$ad.Add([pscustomobject]@{
                    Name = $p[0]; Email = $p[1]; AdminType = $p[2]; AccountType = $p[3]
                    Disabled = ($p[4] -eq '1'); RoleId = $p[5]; IsExternal = ($p[6] -eq '1')
                })
            }
        }
        $result.Admins = $ad.ToArray()
        $result.AdminStatus = if ($ad.Count -gt 0) { 'Successful' } else { 'No data' }
    }

    if ($sections.Contains('ROLES')) {
        $rl = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ROLES']) {
            $p = $l -split '\|'
            if ($p.Count -ge 3) { [void]$rl.Add([pscustomobject]@{ Name = $p[0]; Description = $p[1]; RoleType = $p[2] }) }
        }
        $result.Roles = $rl.ToArray()
    }

    if ($sections.Contains('LDAP_COUNT') -and $sections['LDAP_COUNT'].Count -gt 0) {
        $result.LdapQueryCount = $sections['LDAP_COUNT'][0].Trim()
        $result.LdapStatus = 'Successful'
    } else { $result.LdapStatus = 'No data' }

    if ($sections.Contains('ENDPOINT_KNOWN_COUNT') -and $sections['ENDPOINT_KNOWN_COUNT'].Count -gt 0) {
        $result.EndpointKnownCount = $sections['ENDPOINT_KNOWN_COUNT'][0].Trim()
        $result.EndpointKnownStatus = 'Successful'
    } else { $result.EndpointKnownStatus = 'No data' }

    if ($sections.Contains('AD_SYNC')) {
        $adSync = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['AD_SYNC']) {
            $p = $l -split '\|'
            if ($p.Count -ge 3) { [void]$adSync.Add([pscustomobject]@{ Repo = $p[0]; Total = $p[1]; Synced = $p[2] }) }
        }
        $result.AdSync = $adSync.ToArray()
    }

    if ($sections.Contains('SYSLOG')) {
        $syslogMap = @{}
        foreach ($l in $sections['SYSLOG']) {
            $p = $l -split '\|', 2
            if ($p.Count -ge 1) { $syslogMap[$p[0]] = if ($p.Count -ge 2) { $p[1] } else { '' } }
        }
        $result.SyslogHostname = $syslogMap['INCIDENTS_SYSLOG-HOSTNAME']
        $result.SyslogPort = $syslogMap['INCIDENTS_SYSLOG-PORT']
        $result.SyslogFacility = $syslogMap['INCIDENTS_SYSLOG-FACILITY']
        $result.SyslogPrintFacility = $syslogMap['INCIDENTS_SYSLOG-PRINT-FACILITY']
        $result.SyslogAdditivity = $syslogMap['INCIDENTS_SYSLOG-ADDITIVITY']
        $result.SyslogStatus = 'Successful'
    } else { $result.SyslogStatus = 'No data' }

    if ($sections.Contains('INTEGRATIONS')) {
        foreach ($l in $sections['INTEGRATIONS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 3) {
                switch ("$($p[0])/$($p[1])") {
                    'FSMEnableOCR/DPS_OCR_CONFIGURATIONS' { $result.OcrEnabled = $p[2] }
                    'FSMEnableOCR/GLOBAL_OCR_CONFIGURATIONS' { if ($p[2] -eq 'true') { $result.OcrEnabled = 'true' } elseif (-not $result.OcrEnabled) { $result.OcrEnabled = $p[2] } }
                    'IS_MIP_FEATURE_ENABLED/MIP_GENERAL_SETTINGS' { $result.MipEnabled = $p[2] }
                    'IS_RMS_FEATURE_ENABLED/RMS_GENERAL_SETTINGS' { $result.RmsEnabled = $p[2] }
                }
            }
        }
        $result.IntegrationsStatus = 'Successful'
    } else { $result.IntegrationsStatus = 'No data' }

    if ($sections.Contains('FILE_LABELING')) {
        $fl = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['FILE_LABELING']) {
            $p = $l -split '\|'
            if ($p.Count -ge 6) {
                [void]$fl.Add([pscustomobject]@{
                    SystemType = $p[0]; ImportDateEpochMs = $p[1]; TagsCount = $p[2]
                    EnableApplyLabels = $p[3]; UserName = $p[4]; LastImportStatus = $p[5]
                })
            }
        }
        $result.FileLabeling = $fl.ToArray()
    }

    if ($sections.Contains('ARCHIVE_CONF')) {
        $arc = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ARCHIVE_CONF']) {
            $p = $l -split '\|'
            if ($p.Count -ge 7) {
                [void]$arc.Add([pscustomobject]@{
                    Location = $p[0]; LocalDirectory = $p[1]; ArchiveTempDir = $p[2]
                    MaxOnline = $p[3]; MaxOffline = $p[4]; MaxOnlineIncidents = $p[5]; MaxOfflineDiskSpace = $p[6]
                })
            }
        }
        $result.ArchiveConf = $arc.ToArray()
    }

    if ($sections.Contains('ENDPOINT_STATUS')) {
        $es = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ENDPOINT_STATUS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 7) {
                [void]$es.Add([pscustomobject]@{
                    Hostname = $p[0]; LastUpdate = $p[1]; IpAddress = $p[2]; LoggedInUsers = $p[3]
                    ProfileName = $p[4]; Synced = $p[5]; DiscoveryStatus = $p[6]
                    Version = if ($p.Count -ge 8 -and $p[7]) { $p[7] } else { 'Unknown' }
                    OperationStatus = if ($p.Count -ge 9 -and $p[8]) { $p[8] } else { '' }
                })
            }
        }
        $result.EndpointStatus = $es.ToArray()
    }

    if ($sections.Contains('ENDPOINT_BYPASS_LOG')) {
        $ebl = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['ENDPOINT_BYPASS_LOG']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2 -and $p[1]) { [void]$ebl.Add([pscustomobject]@{ Hostname = $p[0]; LastBypassCodeTime = $p[1] }) }
        }
        $result.EndpointBypassLog = $ebl.ToArray()
    }

    if ($sections.Contains('DISCOVERY_TASKS')) {
        $dt = New-Object System.Collections.Generic.List[object]
        foreach ($l in $sections['DISCOVERY_TASKS']) {
            $p = $l -split '\|'
            if ($p.Count -ge 4) {
                [void]$dt.Add([pscustomobject]@{ Name = $p[0]; Enabled = ($p[1] -eq '1'); TaskType = $p[2]; OperationStatus = $p[3] })
            }
        }
        $result.DiscoveryTasks = $dt.ToArray()
    }

    if ($sections.Contains('POLICY_LEVELS') -and $sections['POLICY_LEVELS'].Count -gt 0) {
        $result.PolicyLevelCount = $sections['POLICY_LEVELS'][0].Trim()
    }

    if ($sections.Contains('SQL_DISK')) {
        $sd = New-Object System.Collections.Generic.List[object]
        $sqlDiskError = $null
        foreach ($l in $sections['SQL_DISK']) {
            $p = $l -split '\|'
            if ($p.Count -ge 2) {
                if ($p[0] -eq 'ERROR') { $sqlDiskError = $p[1] }
                else { [void]$sd.Add([pscustomobject]@{ Drive = $p[0]; FreeMB = $p[1] }) }
            }
        }
        $result.SqlDisks = $sd.ToArray()
        if ($sqlDiskError) { $result.SqlDiskStatus = "Failed: $sqlDiskError" }
        elseif ($sd.Count -gt 0) { $result.SqlDiskStatus = 'Successful' }
        else { $result.SqlDiskStatus = 'No data' }
    }

    if (-not $KeepTempFiles) {
        Remove-Item -Path $sqlFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    }
    else {
        $desktopCopyNote = ''
        try {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $desktopSqlCopy = Join-Path $desktopPath 'fp_health_query_DEBUG.sql'
            $desktopOutCopy = Join-Path $desktopPath 'fp_health_result_DEBUG.txt'
            Copy-Item -Path $sqlFile -Destination $desktopSqlCopy -Force -ErrorAction Stop
            Copy-Item -Path $outFile -Destination $desktopOutCopy -Force -ErrorAction Stop
            $desktopCopyNote = " Also COPIED to the Desktop: $desktopSqlCopy , $desktopOutCopy"
        } catch {}
        Write-Host "Temporary files KEPT (-KeepTempSqlFiles): $sqlFile , $outFile.$desktopCopyNote" -ForegroundColor DarkYellow
    }

    return [pscustomobject]$result

  }
  catch {
      $result.DatabaseLogin = 'Failed'
      $result.ErrorMessage = "Unexpected error (Invoke-FpDatabaseCheck): $($_.Exception.GetType().FullName): $($_.Exception.Message) [line: $($_.InvocationInfo.ScriptLineNumber), command: $($_.InvocationInfo.Line.Trim())]"
      return [pscustomobject]$result
  }
}

# ------------------------------------------------------------------------------------
# HTML rapor
# ------------------------------------------------------------------------------------

function New-FpHtmlReport {
    param([Parameter(Mandatory)] [object]$ReportData, [string]$CustomerName = '')

    $findings = @($ReportData.Findings)
    $normalCount = @($findings | Where-Object Status -eq 'Normal').Count
    $warningCount = @($findings | Where-Object Status -eq 'Warning').Count
    $criticalCount = @($findings | Where-Object Status -eq 'Critical').Count
    $unknownCount = @($findings | Where-Object Status -eq 'Unknown').Count

    $db = $ReportData.Database
    $hasDb = [bool]$ReportData.DatabaseChecked -and $null -ne $db -and $db.DatabaseLogin -eq 'Successful'

    $diskRowsHtml = New-Object System.Text.StringBuilder
    foreach ($disk in @($ReportData.Disks)) {
        $freePct = [double]$disk.FreePercent
        $color = if ($freePct -le 10) { '#dc2626' } elseif ($freePct -le 20) { '#d97706' } else { '#16a34a' }
        [void]$diskRowsHtml.AppendLine("<div class='bar-row'><div class='bar-label'>$(ConvertTo-HtmlSafe $disk.Drive) ($($disk.SizeGB) GB capacity)</div><div class='bar-track'><div class='bar-fill' style='width:$freePct%;background:$color'></div></div><div class='bar-value wide'>$($disk.FreeGB) GB / $freePct% free</div></div>")
    }

    $cpuVal = $ReportData.Hardware.CpuAveragePct
    $cpuColor = if ($null -eq $cpuVal) { '#6b7280' } elseif ($cpuVal -ge 85) { '#dc2626' } elseif ($cpuVal -ge 70) { '#d97706' } else { '#16a34a' }
    $memVal = $ReportData.Hardware.MemoryUsedPct
    $memColor = if ($null -eq $memVal) { '#6b7280' } elseif ($memVal -ge 90) { '#dc2626' } elseif ($memVal -ge 80) { '#d97706' } else { '#16a34a' }

    $serviceColumns = [ordered]@{ 'Service Name' = 'DisplayName'; 'State' = 'State'; 'Start Mode' = 'StartMode' }

    $componentsHtml = ''
    $channelsHtml = ''
    $policyHtml = ''
    $incidentHtml = ''
    $adminHtml = ''
    $licenseHtml = ''

    if ($hasDb) {
        $componentsHtml = Get-FpComponentTreeHtml -Components $db.Components

        $chanColumns = [ordered]@{ 'Component' = 'Component'; 'Service/Channel' = 'Name'; 'Mode' = 'ServiceMode'; 'Operation Mode' = 'OperationMode' }
        $channelsHtml = Get-GenericTableHtml -Items $db.Channels -Columns $chanColumns

        $unusedPolicyCount = @($db.UnusedPolicies).Count
        $policyCards = (Get-KpiCardHtml -Label 'Total Policies' -Value ([string]$db.PolicyTotal)) +
            (Get-KpiCardHtml -Label 'Enabled Policies' -Value ([string]$db.PolicyEnabled) -Color '#16a34a') +
            (Get-KpiCardHtml -Label 'Disabled Policies' -Value ([string]$db.PolicyDisabled) -Color $(if ($db.PolicyDisabled -match '^\d+$' -and [int]$db.PolicyDisabled -gt 0) { '#d97706' } else { '#16a34a' })) +
            (Get-KpiCardHtml -Label "Policies with no incidents in the last $($ReportData.IncidentLookbackDays) days" -Value ([string]$unusedPolicyCount) -Color $(if ($unusedPolicyCount -gt 0) { '#d97706' } else { '#16a34a' }))
        $unusedPolicyNote = if ($unusedPolicyCount -gt 0) {
            "<p class='muted' style='color:#991b1b;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:10px 14px'>There are $unusedPolicyCount policies that produced no incidents in the last $($ReportData.IncidentLookbackDays) days. Reviewing these policies is recommended (they may be inactive, unnecessary, or rules that never trigger).</p>"
        } else {
            "<p class='muted' style='color:#166534;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 14px'>All active policies produced at least one incident in the last $($ReportData.IncidentLookbackDays) days.</p>"
        }
        $unusedPolicyListHtml = ''
        if ($unusedPolicyCount -gt 0) {
            $unusedPolicyColumns = [ordered]@{ 'Policy Name' = 'PolicyName'; 'Type' = 'DataType' }
            $unusedPolicyListHtml = "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Policies with no incidents in the last $($ReportData.IncidentLookbackDays) days</h3>" +
                (Get-GenericTableHtml -Items $db.UnusedPolicies -Columns $unusedPolicyColumns -RowColorSelector { param($i) '#d97706' })
        }
        $typeNameTr = @{ 'NETWORKING' = 'Network DLP'; 'DISCOVERY' = 'Discovery' }
        $policyByTypeRows = @($db.PolicyByType | ForEach-Object {
            [pscustomobject]@{ TypeText = $(if ($typeNameTr.ContainsKey($_.DataType)) { $typeNameTr[$_.DataType] } else { $_.DataType }); Total = $_.Total; Enabled = $_.Enabled }
        })
        $policyByTypeColumns = [ordered]@{ 'Console Screen' = 'TypeText'; 'Total' = 'Total'; 'Enabled' = 'Enabled' }
        $policyByTypeHtml = ''
        if ($policyByTypeRows.Count -gt 1) {
            $policyByTypeHtml = "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Breakdown by Type</h3>" + (Get-GenericTableHtml -Items $policyByTypeRows -Columns $policyByTypeColumns) +
                "<p class='muted'>Forcepoint manages Network DLP policies and Discovery policies on SEPARATE console screens (Manage DLP Policies / Manage Discovery Policies). One type will not appear on the other screen; this is normal.</p>"
        }
        $disabledColumns = [ordered]@{ 'Policy Name' = 'Name'; 'Last Changed' = 'UpdateDate' }
        $disabledHtml = ''
        if (@($db.DisabledPolicies).Count -gt 0) {
            $disabledHtml = "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Disabled Policies</h3>" + (Get-GenericTableHtml -Items $db.DisabledPolicies -Columns $disabledColumns -RowColorSelector { param($i) '#d97706' })
        }
        $disabledHtml += "<p class='muted'>These counts only cover policies created by the organization itself; the hundreds of ready-made template policies that ship with Forcepoint's library but are never used (DEFINITION_TYPE=A_PREDEFINE) are excluded from the count.</p>"
        $policyHtml = "<div class='kpi-row'>$policyCards</div>$unusedPolicyNote$unusedPolicyListHtml$policyByTypeHtml$disabledHtml"

        $incTotalN = 0; $incTotalDisplay = if ([long]::TryParse([string]$db.IncidentTotal, [ref]$incTotalN)) { [string]$incTotalN } else { 'N/A' }
        $incRecentN = 0; $incRecentDisplay = if ([long]::TryParse([string]$db.IncidentRecent, [ref]$incRecentN)) { [string]$incRecentN } else { 'N/A' }
        $inc7N = 0; $inc7Display = if ([long]::TryParse([string]$db.IncidentLast7Days, [ref]$inc7N)) { [string]$inc7N } else { 'N/A' }
        $incTotalTr = $incTotalN; $incRecentTr = $incRecentN
        $incCards = (Get-KpiCardHtml -Label 'Total Incidents (Events)' -Value $incTotalDisplay) +
            (Get-KpiCardHtml -Label "In the last $($ReportData.IncidentLookbackDays) days" -Value $incRecentDisplay) +
            (Get-KpiCardHtml -Label 'In the last 7 days' -Value $inc7Display -Color $(if ($inc7Display -eq 'N/A') { '#d97706' } else { '#111827' }))
        $inc7WarnHtml = if ($inc7Display -eq 'N/A') { "<p class='muted' style='color:#d97706'>The 'last 7 days' query returned no data on this run (could be a transient SQL error - e.g. a lock timeout); this means NO DATA, not 0. Try regenerating the report.</p>" } else { '' }
        $archiveNoteHtml = if (@($db.ArchiveConf).Count -gt 0) {
            $a = $db.ArchiveConf[0]
            "<p class='muted'>Archive storage location: <strong>$(ConvertTo-HtmlSafe $a.Location)</strong> - Local directory: $(ConvertTo-HtmlSafe $a.LocalDirectory); temp directory: $(ConvertTo-HtmlSafe $a.ArchiveTempDir)</p>"
        } else { '' }
        $partColumns = [ordered]@{ 'ID' = 'PartitionId'; 'Status' = 'StatusDisplay'; 'From' = 'FromDate'; 'To' = 'ToDate'; '# of Incidents' = 'EventCount' }
        $partHtml = Get-GenericTableHtml -Items $db.IncidentPartitions -Columns $partColumns -RowColorSelector { param($i) if ($i.CatalogState -eq 'Not in catalog') { '#d97706' } else { $null } }
        $partSum = ((@($db.IncidentPartitions) | ForEach-Object { $n=0; [void][long]::TryParse($_.EventCount,[ref]$n); $n }) | Measure-Object -Sum).Sum
        $statusHtml = Get-BarChartHtml -Items $db.IncidentByStatus -LabelProp 'StatusName' -ValueProp 'Count' -Color '#db2777'
        $topPolTitle = "Top Violated Policies / Rules (Last $($ReportData.IncidentLookbackDays) days, Top 10)"
        $topPolRowSum = 0
        $topPolDistinct = $db.PolicyDistinctIncidentsRecent
        $topPolBase = $incRecentTr
        if (@($db.TopPolicies).Count -gt 0) {
            $topPolHtml = Get-BarChartHtml -Items $db.TopPolicies -LabelProp 'PolicyName' -ValueProp 'MatchCount' -Color '#db2777'
            $topPolRowSum = ((@($db.TopPolicies) | ForEach-Object { $n=0; [void][long]::TryParse($_.MatchCount,[ref]$n); $n }) | Measure-Object -Sum).Sum
        }
        elseif (@($db.TopPoliciesAllTime).Count -gt 0) {
            $topPolTitle = 'Top Violated Policies / Rules (All Time)'
            $topPolHtml = Get-BarChartHtml -Items $db.TopPoliciesAllTime -LabelProp 'PolicyName' -ValueProp 'MatchCount' -Color '#db2777'
            $topPolRowSum = ((@($db.TopPoliciesAllTime) | ForEach-Object { $n=0; [void][long]::TryParse($_.MatchCount,[ref]$n); $n }) | Measure-Object -Sum).Sum
            $topPolDistinct = $db.PolicyDistinctIncidents
            $topPolBase = $incTotalTr
        }
        else {
            $topPolHtml = "<p class='muted'>No data.</p>"
        }
        $topPolExplainer = "<p style='font-size:13px'><strong>How to read these numbers:</strong> There are <strong>$topPolBase</strong> total incidents in this period; <strong>$topPolDistinct</strong> of them were associated with at least one policy/rule (this number can never exceed the total incident count). The sum of the rows in the table below is <strong>$topPolRowSum</strong> - this MAY be HIGHER than the 'incident' count above, because <u>a single incident can violate more than one policy/rule at the same time</u> (e.g. triggering both a parent policy and a specific rule under it, counted in two separate rows). This is not an error; it shows that the same incident was caught by more than one policy/rule.</p>"

        # --- Total Incident Count (per user request only the total-incidents card remains;
        # the "Pending Delete" card + explanatory note were REMOVED, 2026-09-25) ---
        $trCulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
        $totalIncText = if ([long]::TryParse([string]$db.IncidentTotal, [ref]$incTotalTr)) { $incTotalTr.ToString('N0', $trCulture) } else { 'N/A' }
        $totalIncidentSectionHtml = "<section><h2>Total Incident Count</h2><div class='kpi-row'>$(Get-KpiCardHtml -Label 'Total Incidents in Database' -Value $totalIncText)</div></section>"

        # --- Incident Type Breakdown / Incident Breakdown by Detection Server (all time) ---
        $incidentTypeHtml = Get-BarChartHtml -Items $db.IncidentType -LabelProp 'IncidentType' -ValueProp 'Count' -Color '#7c3aed'
        $incidentByServerHtml = Get-BarChartHtml -Items $db.IncidentByServer -LabelProp 'ServerName' -ValueProp 'Count' -Color '#0891b2'
        $incidentTypeServerGridHtml = "<div class='grid-2'>" +
            "<section><h2>Incident Type Breakdown</h2>$incidentTypeHtml</section>" +
            "<section><h2>Incident Breakdown by Detection Server</h2>$incidentByServerHtml</section>" +
            '</div>'

        # --- Top Violated Policies - its own, separate section ---
        $topPolicySectionHtml = "<section><h2>$topPolTitle</h2>$topPolExplainer$topPolHtml</section>"

        # --- Network Senders / Endpoint Users (last N days) ---
        $networkSenderHtml = Get-BarChartHtml -Items $db.NetworkSenders -LabelProp 'SenderName' -ValueProp 'Count' -Color '#ea580c'
        $endpointUserHtml = Get-BarChartHtml -Items $db.EndpointUsers -LabelProp 'UserName' -ValueProp 'Count' -Color '#16a34a'
        $networkEndpointGridHtml = "<div class='grid-2'>" +
            "<section><h2>Network - Top Incident-Generating Senders (Last $($ReportData.IncidentLookbackDays) Days)</h2>$networkSenderHtml</section>" +
            "<section><h2>Endpoint - Top Incident-Generating Users (Last $($ReportData.IncidentLookbackDays) Days)</h2>$endpointUserHtml<p class='muted'>Channel separation is based on PA_RP_SERVICES.CHANNEL_TYPE; the Network panel covers channels other than the Endpoint agent (HTTP/HTTPS/SMTP/CASB/Discovery etc.) - this panel may appear empty if only Endpoint traffic exists.</p></section>" +
            '</div>'

        $incidentHtml = "<div class='kpi-row'>$incCards</div>$inc7WarnHtml" +
            "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Breakdown by Status</h3>$statusHtml" +
            "<p class='muted'>Status names are taken from the PA_RP_STATUS table (same as the FSM console's 'Filter by Status' list); an unmatched/unknown code is shown as the raw code, 'Code &lt;N&gt;'.</p>" +
            "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Archive Partitions</h3>$partHtml" +
            "<p class='muted'>This table corresponds to the FSM console's Settings &gt; General &gt; Archive &gt; Archive Partitions screen; the columns (ID, Status, From, To, # of Incidents) are shown in the same order as the console. Forcepoint automatically splits the incident database into a new partition <strong>every 90 days</strong> (~4 times a year); the most recent partition is 'Online-Active' (still receiving new incidents), while closed but not-yet-archived partitions show as 'Online'. On remote SQL Server setups, incident archiving does not work without extra installer configuration - in that case partitions remain 'Online' indefinitely. The table total always matches the 'Total Incidents' figure above: $partSum. Orange rows are tables that do not appear in the catalog at all (usually old/default tables with a different ID format).</p>$archiveNoteHtml"

        $adminCards = (Get-KpiCardHtml -Label 'Console Users' -Value ([string]@($db.Admins).Count)) +
            (Get-KpiCardHtml -Label 'Disabled Users' -Value ([string]@($db.Admins | Where-Object Disabled).Count) -Color $(if (@($db.Admins | Where-Object Disabled).Count -gt 0) { '#d97706' } else { '#16a34a' })) +
            (Get-KpiCardHtml -Label 'Roles' -Value ([string]@($db.Roles).Count))
        $adminColumns = [ordered]@{ 'User' = 'Name'; 'Email' = 'Email'; 'Type' = 'AdminType'; 'Account Type' = 'AccountType'; 'Role ID' = 'RoleId'; 'LDAP User' = 'IsExternalText' }
        $adminRows = @($db.Admins | ForEach-Object { $_ | Add-Member -NotePropertyName IsExternalText -NotePropertyValue $(if ($_.IsExternal) { 'Yes' } else { 'No' }) -Force -PassThru })
        $adminTable = Get-GenericTableHtml -Items $adminRows -Columns $adminColumns -RowColorSelector { param($i) if ($i.Disabled) { '#dc2626' } else { '#16a34a' } }
        $roleColumns = [ordered]@{ 'Role' = 'Name'; 'Description' = 'Description'; 'Type' = 'RoleType' }
        $roleTable = Get-GenericTableHtml -Items $db.Roles -Columns $roleColumns
        $adminHtml = "<div class='kpi-row'>$adminCards</div><h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Users</h3>$adminTable<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Roles</h3>$roleTable<p class='muted'>Password fields (PASSWORD, PASSWORD_HISTORY) are never read.</p>"

        # --- Integration Status: Syslog / OCR / MIP / AD-LDAP / Console AD Authentication ---
        $integRows = New-Object System.Collections.Generic.List[object]
        $syslogVar = [bool]$db.SyslogHostname
        $syslogDetay = if ($syslogVar) { "udp://$(ConvertTo-HtmlSafe $db.SyslogHostname):$(ConvertTo-HtmlSafe $db.SyslogPort), facility: $(ConvertTo-HtmlSafe $db.SyslogFacility)" } else { 'Server address not defined (not configured).' }
        [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'Syslog (system events)'; Var = $syslogVar; Detay = $syslogDetay })

        $ocrVar = $db.OcrEnabled -eq 'true'
        [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'OCR'; Var = $ocrVar; Detay = "FSMEnableOCR = $(if ($db.OcrEnabled) { ConvertTo-HtmlSafe $db.OcrEnabled } else { 'unknown' })" })

        $mipLabelInfo = @($db.FileLabeling | Where-Object { $_.SystemType -eq 'MIP' } | Select-Object -First 1)
        $mipImportOk = $mipLabelInfo.Count -gt 0 -and $mipLabelInfo[0].LastImportStatus -eq 'SUCCESS'
        $mipVar = ($db.MipEnabled -eq 'true') -or $mipImportOk
        $rmsText = if ($db.RmsEnabled) { ", RMS: $(ConvertTo-HtmlSafe $db.RmsEnabled)" } else { '' }
        $mipImportText = if ($mipLabelInfo.Count -gt 0) {
            if ($mipImportOk) {
                $mipDate = ConvertFrom-EpochMs $mipLabelInfo[0].ImportDateEpochMs
                ", File Labeling: import successful$(if ($mipDate) { " ($($mipDate.ToString('dd.MM.yyyy HH:mm')))" })"
            } else { ', File Labeling: not imported' }
        } else { '' }
        [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'MIP (Microsoft Information Protection)'; Var = $mipVar; Detay = "IS_MIP_FEATURE_ENABLED = $(if ($db.MipEnabled) { ConvertTo-HtmlSafe $db.MipEnabled } else { 'unknown' })$rmsText$mipImportText" })

        $bjLabelInfo = @($db.FileLabeling | Where-Object { $_.SystemType -eq 'BOLDON_JAMES' } | Select-Object -First 1)
        if ($bjLabelInfo.Count -gt 0) {
            $bjVar = $bjLabelInfo[0].LastImportStatus -eq 'SUCCESS'
            $bjDate = ConvertFrom-EpochMs $bjLabelInfo[0].ImportDateEpochMs
            $bjUsage = if ($bjLabelInfo[0].EnableApplyLabels -eq '1') { 'Detect + Apply labels' } else { 'Detect labels' }
            $bjDetay = if ($bjVar) { "$bjUsage. $($bjLabelInfo[0].TagsCount) labels imported ($($bjLabelInfo[0].UserName))$(if ($bjDate) { ", last successful import: $($bjDate.ToString('dd.MM.yyyy HH:mm'))" })." } else { "Status: $($bjLabelInfo[0].LastImportStatus)" }
            [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'File Labeling (Boldon James Classifier)'; Var = $bjVar; Detay = $bjDetay })
        }

        $adTotal = 0; $adSynced = 0
        foreach ($r in @($db.AdSync)) { $t=0;$s=0; [void][int]::TryParse($r.Total,[ref]$t); [void][int]::TryParse($r.Synced,[ref]$s); $adTotal+=$t; $adSynced+=$s }
        $adVar = $adTotal -gt 0
        $adDetay = if ($adVar) { "$adSynced / $adTotal records synchronized. Connection address/SSL details are not stored in the database - see FSM console &gt; Settings &gt; Users and Devices &gt; Directories." } else { 'No synchronized directory records found.' }
        [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'Active Directory (LDAP) sync'; Var = $adVar; Detay = $adDetay })

        $extCount = @($db.Admins | Where-Object IsExternal).Count
        $totalAdmins = @($db.Admins).Count
        $consoleAdVar = $extCount -gt 0
        [void]$integRows.Add([pscustomobject]@{ Entegrasyon = 'AD-account authentication at console login'; Var = $consoleAdVar; Detay = "$extCount / $totalAdmins users are authenticated via AD/LDAP (EXTERNAL_USER_DN populated)." })

        $integrationRowsHtml = ($integRows | ForEach-Object {
            $badgeColor = if ($_.Var) { '#16a34a' } else { '#6b7280' }
            $badgeText = if ($_.Var) { 'Yes' } else { 'No' }
            "<tr><td><span class='badge' style='background:$badgeColor'>$badgeText</span></td><td>$(ConvertTo-HtmlSafe $_.Entegrasyon)</td><td>$($_.Detay)</td></tr>"
        }) -join ''
        $integrationHtml = "<table class='report-table'><thead><tr><th>Status</th><th>Integration</th><th>Detail</th></tr></thead><tbody>$integrationRowsHtml</tbody></table><p class='muted'>Note: the `"AD-managed roles`" row was not included in this table - no verified equivalent was found in Forcepoint (all roles in this environment are PREDEFINED_VISBLE; no role assignment tied to a directory group was observed).</p>"

        # --- Endpoint Status: "Agent Versiyon Dağılımı" tasarımı (Symantec DLP HC ile ayni desen) -
        # yuzlerce agent olan ortamlarda tek tek satir listelemek yerine (2026-09-25, kullanici
        # istegi) versiyon bazinda bar-chart + ozet sayilar gosterilir. "Reporting"/"NotReporting"/
        # "Deleted" metrikleri KALDIRILDI (kullanici istegi, 2026-09-25 - Reporting/NotReporting
        # esik-bazli tahminden ibaretti, Deleted icin zaten hicbir sinyal yoktu); yerine GERCEK
        # veritabani alanlarina dayanan "Synchronized" (eps_os_Synced) ve "Discovery Status"
        # (eps_os_DiscoveryStatus dagilimi) eklendi.
        $endpointVersionGroups = @($db.EndpointStatus | Group-Object Version | ForEach-Object { [pscustomobject]@{ Version = $_.Name; Count = $_.Count } } | Sort-Object Count -Descending)
        $endpointVersionHtml = Get-BarChartHtml -Items $endpointVersionGroups -LabelProp 'Version' -ValueProp 'Count' -Color '#2563eb' -MaxItems 15
        $endpointInstallCount = @($db.EndpointStatus).Count
        $endpointSyncedCount = @($db.EndpointStatus | Where-Object { [string]$_.Synced -eq '1' }).Count
        $endpointDiscoveryGroups = @($db.EndpointStatus | Where-Object { $_.DiscoveryStatus } | Group-Object DiscoveryStatus | Sort-Object Count -Descending)
        $endpointDiscoveryText = if ($endpointDiscoveryGroups.Count -gt 0) {
            ($endpointDiscoveryGroups | ForEach-Object { "$(ConvertTo-HtmlSafe $_.Name) ($($_.Count))" }) -join ', '
        } else { 'Unknown' }

        # eps_os_OperationStatus (2026-09-25, kullanicinin kendi sorgusuyla DOGRULANDI): "Bypass
        # Endpoint..." ONCESI = OPERATION_NORMAL, SONRASI = OPERATION_REMOTE_BYPASS_ACTIVE. FSM
        # konsolundaki "Client status: Disabled" alaninin GERCEK, CANLI karsiligi budur - bu yuzden
        # "Agent Disable" artik "Bilinmiyor" DEGIL, bu alandan GERCEK bir sayiyla hesaplaniyor. SADECE
        # bu iki deger GOZLEMLENDI; baska/bilinmeyen bir deger gelirse UYDURULMADAN oldugu gibi gosterilir.
        # Detay listesi <details>/<summary> ile ACILIR PENCEREYE alindi (2026-09-25, kullanici istegi -
        # yuzlerce endpoint'li ortamlarda satir satir liste yer kaplar; baslikta sayi HER ZAMAN
        # gorunur, listeyi gormek isteyen tiklar).
        $endpointsWithOpStatus = @($db.EndpointStatus | Where-Object { $_.OperationStatus })
        $endpointsNotNormal = @($endpointsWithOpStatus | Where-Object { $_.OperationStatus -ne 'OPERATION_NORMAL' })
        $endpointDisableText = if ($endpointsWithOpStatus.Count -gt 0) { "$($endpointsNotNormal.Count)" } else { 'Unknown' }
        $endpointEnableText = if ($endpointsWithOpStatus.Count -gt 0) { "$(@($endpointsWithOpStatus | Where-Object { $_.OperationStatus -eq 'OPERATION_NORMAL' }).Count)" } else { 'Unknown' }

        # Endpoints whose last update (PA_DYNAMIC_STATUS.UPDATE_DATE) is older than 7 days
        # (2026-09-28, user request) - the agent has not reported to the console for a long time.
        $staleDays = 7
        $staleThreshold = (Get-Date).AddDays(-$staleDays)
        $endpointsStale = @($db.EndpointStatus | ForEach-Object {
            $luParsed = [DateTime]::MinValue
            if ([DateTime]::TryParseExact([string]$_.LastUpdate, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$luParsed) -and $luParsed -lt $staleThreshold) {
                [pscustomobject]@{ Endpoint = $_; LastUpdateDt = $luParsed }
            }
        } | Sort-Object LastUpdateDt)
        $endpointStaleCount = $endpointsStale.Count
        $endpointStaleDetail = if ($endpointStaleCount -gt 0) {
            $staleRows = ($endpointsStale | ForEach-Object {
                $ep = $_.Endpoint
                $ageDays = [int][math]::Floor(((Get-Date) - $_.LastUpdateDt).TotalDays)
                "<tr><td>$(ConvertTo-HtmlSafe $ep.Hostname)</td><td>$(ConvertTo-HtmlSafe $ep.IpAddress)</td><td>$(ConvertTo-HtmlSafe $ep.LoggedInUsers)</td><td>$(ConvertTo-HtmlSafe $ep.ProfileName)</td><td>$(ConvertTo-HtmlSafe $ep.LastUpdate)</td><td>$ageDays days ago</td></tr>"
            }) -join ''
            $staleTable = "<table class='report-table'><thead><tr><th>Hostname</th><th>IP Address</th><th>Logged-in Users</th><th>Profile</th><th>Last Update</th><th>Time Elapsed</th></tr></thead><tbody>$staleRows</tbody></table>"
            "<details class='status-details'><summary style='color:#d97706'><strong>$endpointStaleCount</strong> host(s) have a last update <strong>older than $staleDays days</strong></summary><div class='status-details-body'>$staleTable<p class='muted' style='color:#d97706'>Source: PA_DYNAMIC_STATUS.UPDATE_DATE (the time the agent last reported its state to FSM) - same information as the 'Last Update' column of the FSM console's Status &gt; Endpoint Status screen.</p></div></details>"
        } else { '' }

        # Acilir pencere govdesi artik duz cumle degil, KIMLIK BILGILERINI (Hostname/IP/Logged-in
        # Users/Profile) iceren bir TABLO (2026-09-25, kullanici istegi - sayi/liste tikaninca
        # kullanicinin HANGI host oldugunu, kimin oturum actigini, hangi profile bagli oldugunu
        # ANLAMASI gerekiyor). EndpointStatus'ta ZATEN bulunan alanlar kullanilir, yeni SQL gerekmedi.
        $endpointDisableDetail = if ($endpointsNotNormal.Count -gt 0) {
            $disableRows = ($endpointsNotNormal | ForEach-Object {
                $friendly = switch -Wildcard ($_.OperationStatus) {
                    '*BYPASS*ACTIVE*' { 'Bypass Active' }
                    default { $_.OperationStatus }
                }
                "<tr><td>$(ConvertTo-HtmlSafe $_.Hostname)</td><td>$(ConvertTo-HtmlSafe $_.IpAddress)</td><td>$(ConvertTo-HtmlSafe $_.LoggedInUsers)</td><td>$(ConvertTo-HtmlSafe $_.ProfileName)</td><td>$(ConvertTo-HtmlSafe $friendly)</td></tr>"
            }) -join ''
            $disableTable = "<table class='report-table'><thead><tr><th>Hostname</th><th>IP Address</th><th>Logged-in Users</th><th>Profile</th><th>Status</th></tr></thead><tbody>$disableRows</tbody></table>"
            "<details class='status-details'><summary style='color:#dc2626'>Right now <strong>$($endpointsNotNormal.Count)</strong> host(s) are not in a normal operating state</summary><div class='status-details-body'>$disableTable<p class='muted' style='color:#dc2626'>Source: PA_DYNAMIC_STATUS_PROPS.eps_os_OperationStatus (live state field) - same information as the FSM console's Status &gt; Endpoint Status screen's 'Client status'.</p></div></details>"
        } else { '' }

        $epLookup = @{}
        foreach ($e in @($db.EndpointStatus)) { $epLookup[$e.Hostname] = $e }
        $endpointBypassCount = @($db.EndpointBypassLog).Count
        $endpointBypassDetail = if ($endpointBypassCount -gt 0) {
            $bypassRows = ($db.EndpointBypassLog | ForEach-Object {
                $epInfo = $epLookup[$_.Hostname]
                $ip = if ($epInfo) { $epInfo.IpAddress } else { 'Unknown' }
                $users = if ($epInfo) { $epInfo.LoggedInUsers } else { 'Unknown' }
                $profileName = if ($epInfo) { $epInfo.ProfileName } else { 'Unknown' }
                "<tr><td>$(ConvertTo-HtmlSafe $_.Hostname)</td><td>$(ConvertTo-HtmlSafe $ip)</td><td>$(ConvertTo-HtmlSafe $users)</td><td>$(ConvertTo-HtmlSafe $profileName)</td><td>$(ConvertTo-HtmlSafe $_.LastBypassCodeTime)</td></tr>"
            }) -join ''
            $bypassTable = "<table class='report-table'><thead><tr><th>Hostname</th><th>IP Address</th><th>Logged-in Users</th><th>Profile</th><th>Bypass Code Generated At</th></tr></thead><tbody>$bypassRows</tbody></table>"
            "<details class='status-details'><summary style='color:#d97706'>In the last $($ReportData.IncidentLookbackDays) days, an Endpoint Bypass Code was generated for <strong>$endpointBypassCount</strong> host(s)</summary><div class='status-details-body'>$bypassTable<p class='muted' style='color:#d97706'>This is an event record (PA_AUDIT_INFO) - it does NOT indicate whether the code is still valid/active, only when it was generated; see the `"Agent Disable`" count above for the current/definitive state.</p></div></details>"
        } else { '' }
        $endpointStatusHtml = "$endpointVersionHtml<div class='agent-counts'><div>Agent Install : $endpointInstallCount</div><div>Agent Enable : $endpointEnableText</div><div>Agent Disable : $endpointDisableText</div><div>Last Update Older Than $staleDays Days : $endpointStaleCount</div><div>Synchronized : $endpointSyncedCount</div><div>Discovery Status : $endpointDiscoveryText</div><div>Bypass Code Generated (Last $($ReportData.IncidentLookbackDays) days) : $endpointBypassCount</div></div>$endpointStaleDetail$endpointDisableDetail$endpointBypassDetail<p class='muted'>Version distribution is computed from PA_DYNAMIC_STATUS / PA_DYNAMIC_STATUS_PROPS. `"Agent Enable`" is the number of hosts whose eps_os_OperationStatus field is `"OPERATION_NORMAL`", and `"Agent Disable`" the number where it is not (same live signal as the FSM console's `"Client status`"). `"Last Update Older Than $staleDays Days`" is the number of hosts whose PA_DYNAMIC_STATUS.UPDATE_DATE is more than $staleDays days old. `"Synchronized`" is the number of hosts whose eps_os_Synced field is 1. `"Discovery Status`" is the distribution of observed values in the eps_os_DiscoveryStatus field.</p>"

    }

    $lic = $ReportData.License
    if ($lic -and $lic.Status -ne 'NotFound') {
        $licColor = switch ($lic.Status) { 'OK' { '#16a34a' } 'Expiring soon' { '#d97706' } 'Expired' { '#dc2626' } default { '#6b7280' } }
        $licProdColumns = [ordered]@{ 'Product' = 'DisplayName'; 'Usage Limit (users)' = 'UsageLimit'; 'Expiry Date' = 'ExpiresOnText' }
        $licProdRows = @($lic.Products | ForEach-Object { $_ | Add-Member -NotePropertyName ExpiresOnText -NotePropertyValue $(if ($_.ExpiresOn) { $_.ExpiresOn.ToString('yyyy-MM-dd') } else { '-' }) -Force -PassThru })
        $licProdTable = Get-GenericTableHtml -Items $licProdRows -Columns $licProdColumns
        $licExpiresText = if ($lic.ExpiresOn) { $lic.ExpiresOn.ToString('yyyy-MM-dd') } else { 'Unknown' }
        $licDaysText = if ($null -ne $lic.DaysRemaining) { if ([int]$lic.DaysRemaining -lt 0) { "expired $([math]::Abs([int]$lic.DaysRemaining)) days ago" } else { "$($lic.DaysRemaining) days remaining" } } else { 'Unknown' }
        $licenseHtml = "<div class='info-cards'>" +
            "<div class='info-card'><div class='k'>Customer</div><div class='v'>$(ConvertTo-HtmlSafe $lic.CompanyName)</div></div>" +
            "<div class='info-card'><div class='k'>Status</div><div class='v' style='color:$licColor'>$(ConvertTo-HtmlSafe $lic.Status)</div></div>" +
            "<div class='info-card'><div class='k'>Expiry Date</div><div class='v'>$(ConvertTo-HtmlSafe $licExpiresText)</div></div>" +
            "<div class='info-card'><div class='k'>Time Remaining</div><div class='v' style='color:$licColor'>$(ConvertTo-HtmlSafe $licDaysText)</div></div>" +
            "<div class='info-card'><div class='k'>License Key</div><div class='v'>$(ConvertTo-HtmlSafe $lic.MaskedKey)</div></div>" +
            "</div><div style='margin-top:14px'>$licProdTable</div><p class='muted'>License file: $(ConvertTo-HtmlSafe $lic.FilePath)</p>"
    }
    elseif ($lic) {
        $licenseHtml = "<p class='muted'>License file (subscription.xml) not found or unreadable. $(ConvertTo-HtmlSafe $lic.Error)</p>"
    }

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forcepoint DLP Health Check Report - $(ConvertTo-HtmlSafe $ReportData.ComputerName)</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f3f4f6; color: #111827; margin: 0; padding: 24px; }
  .page { max-width: 1100px; margin: 0 auto; }
  .report-header { background: linear-gradient(135deg,#1e3a8a,#2563eb); color: #fff; border-radius: 12px; padding: 24px 28px; margin-bottom: 20px; }
  .report-header h1 { margin: 0 0 4px 0; font-size: 22px; }
  .report-header .sub { opacity: .9; font-size: 14px; }
  section { background: #fff; border-radius: 12px; padding: 20px 24px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  section h2 { font-size: 16px; margin: 0 0 14px 0; color: #1e3a8a; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 700px) { .grid-2 { grid-template-columns: 1fr; } }
  .kpi-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .kpi-card { flex: 1; min-width: 130px; background: #f9fafb; border-radius: 10px; padding: 14px; text-align: center; }
  .kpi-value { font-size: 24px; font-weight: 700; }
  .kpi-label { font-size: 12px; color: #6b7280; margin-top: 4px; }
  table.report-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.report-table th { text-align: left; background: #f3f4f6; padding: 8px 10px; font-size: 12px; color: #374151; }
  table.report-table td { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; }
  table.report-table tr:hover { background: #f8fafc; }
  .badge { color: #fff; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 13px; }
  .bar-label { flex: 0 0 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #374151; }
  .bar-track { flex: 1; background: #e5e7eb; border-radius: 6px; height: 14px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 6px; }
  .bar-value { flex: 0 0 90px; text-align: right; color: #374151; font-weight: 600; }
  .bar-value.wide { flex-basis: 190px; }
  .note-warn { margin: 12px 0 0 0; padding: 10px 14px; border-radius: 8px; font-size: 13px; background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
  .note-ok { margin: 12px 0 0 0; padding: 10px 14px; border-radius: 8px; font-size: 13px; background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
  .muted { color: #9ca3af; font-size: 13px; }
  .agent-counts { margin-top: 14px; padding-top: 12px; border-top: 1px solid #e5e7eb; font-size: 14px; line-height: 1.8; color: #111827; font-weight: 600; }
  .info-cards { display: flex; flex-wrap: wrap; gap: 10px; }
  .info-card { background: #f9fafb; border-radius: 8px; padding: 10px 14px; min-width: 160px; }
  .info-card .k { font-size: 11px; color: #6b7280; }
  .info-card .v { font-size: 14px; font-weight: 600; color: #111827; }
  .module-item { padding: 8px 4px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #111827; }
  .module-item summary { cursor: pointer; list-style: none; }
  .module-item summary::-webkit-details-marker { display: none; }
  .module-item summary:before { content: '▸ '; color: #9ca3af; }
  .module-item[open] summary:before { content: '▾ '; }
  .module-children { margin-left: 26px; border-left: 2px solid #e5e7eb; padding-left: 12px; margin-bottom: 6px; }
  .module-version { color: #6b7280; font-weight: 400; font-size: 12px; }
  .module-error-detail { margin: 6px 0 4px 18px; padding: 8px 12px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; font-size: 12px; color: #991b1b; }
  .status-details { margin-top: 8px; }
  .status-details summary { cursor: pointer; list-style: none; font-size: 13px; font-weight: 600; }
  .status-details summary::-webkit-details-marker { display: none; }
  .status-details summary:before { content: '▸ '; }
  .status-details[open] summary:before { content: '▾ '; }
  .status-details-body { margin-top: 4px; }
  footer { text-align: center; color: #9ca3af; font-size: 12px; margin-top: 20px; }
  @page { size: A4; margin: 12mm 10mm; }
  @media print {
    body { background: #fff; padding: 0; }
    .report-header { break-inside: avoid; break-after: avoid; page-break-after: avoid; }
    section { box-shadow: none; border: 1px solid #e5e7eb; break-inside: avoid; page-break-inside: avoid; }
    .kpi-row, .bar-row, .info-cards { break-inside: avoid; page-break-inside: avoid; }
    /* Long tables (e.g. Health Findings) may break ROW BY ROW - forcing break-inside:avoid on
       the WHOLE table pushes it entirely to the next page once it exceeds one page, leaving
       the section title alone with a mostly blank page below it (2026-09-26, OBSERVED and
       FIXED against real Chrome/Edge PDF output) - so only INDIVIDUAL rows (tr) avoid breaking;
       the table itself is allowed to flow across pages. thead repeats on every page by default
       (browser UA stylesheet behavior). */
    table.report-table tr { break-inside: avoid; page-break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <h1>Forcepoint DLP Health Check Report</h1>
    <div class="sub">Customer: $(ConvertTo-HtmlSafe $CustomerName) &nbsp;|&nbsp; Server: $(ConvertTo-HtmlSafe $ReportData.ComputerName) &nbsp;|&nbsp; Collected at: $(ConvertTo-HtmlSafe $ReportData.CollectedAt)</div>
  </div>

  <section>
    <h2>System Information</h2>
    <div class="info-cards">
      <div class="info-card"><div class="k">Manufacturer / Model</div><div class="v">$(ConvertTo-HtmlSafe $ReportData.SystemInfo.Manufacturer) / $(ConvertTo-HtmlSafe $ReportData.SystemInfo.Model)</div></div>
      <div class="info-card"><div class="k">Operating System</div><div class="v">$(ConvertTo-HtmlSafe $ReportData.SystemInfo.OperatingSystem)</div></div>
      <div class="info-card"><div class="k">OS Version / Architecture</div><div class="v">$(ConvertTo-HtmlSafe $ReportData.SystemInfo.OSVersion) / $(ConvertTo-HtmlSafe $ReportData.SystemInfo.Architecture)</div></div>
      <div class="info-card"><div class="k">Last Reboot</div><div class="v">$(ConvertTo-HtmlSafe $ReportData.SystemInfo.LastBoot)</div></div>
      <div class="info-card"><div class="k">Logical CPU / RAM</div><div class="v">$($ReportData.Hardware.LogicalCpu) / $($ReportData.Hardware.TotalMemoryGB) GB</div></div>
    </div>
  </section>

$(
    $fpVersionValue = 'Unknown'
    $fpVersionSource = ''
    if ($hasDb -and $db.FpVersionStatus -eq 'Successful' -and $db.FpVersion -and $db.FpVersion -ne 'N/A') {
        $fpVersionValue = $db.FpVersion; $fpVersionSource = 'Source: database (WS_SM_SITE_ELEMENTS)'
    } elseif ($ReportData.PSObject.Properties['LocalFpVersion'] -and $ReportData.LocalFpVersion) {
        $fpVersionValue = $ReportData.LocalFpVersion; $fpVersionSource = 'Source: local install record (registry)'
    } else {
        $fpVersionSource = 'Version could not be read from either the database or the local registry.'
    }
    $hw = $ReportData.HardwareAssessment
    $hwRows = @($hw.Rows | ForEach-Object {
        [pscustomobject]@{ Metrik = $_.Metric; Mevcut = $_.Current; Min = $_.Min; Onerilen = $_.Recommended }
    })
    $hwColumns = [ordered]@{ 'Component' = 'Metrik'; 'Current' = 'Mevcut'; 'Minimum' = 'Min'; 'Recommended' = 'Onerilen' }
    $hwTable = Get-GenericTableHtml -Items $hwRows -Columns $hwColumns -RowColorSelector {
        param($i) if ([double]$i.Mevcut -lt [double]$i.Min) { '#dc2626' } elseif ([double]$i.Mevcut -lt [double]$i.Onerilen) { '#d97706' } else { '#16a34a' }
    }
    $hwLevelTr = @{ 'Below minimum' = 'Below minimum'; 'Minimum' = 'Meets minimum level'; 'Recommended' = 'Meets recommended level' }
@"
  <section>
    <h2>Forcepoint DLP Information</h2>
    <div class="info-cards">
      <div class="info-card"><div class="k">Version</div><div class="v">$(ConvertTo-HtmlSafe $fpVersionValue)</div></div>
      <div class="info-card"><div class="k">Version Source</div><div class="v">$(ConvertTo-HtmlSafe $fpVersionSource)</div></div>
      <div class="info-card"><div class="k">Hardware Result</div><div class="v">$(ConvertTo-HtmlSafe $hwLevelTr[$hw.Level])</div></div>
    </div>
    <h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Hardware Comparison (Forcepoint DLP $(ConvertTo-HtmlSafe $hw.VersionKey) $(if (-not $hw.Matched) { '- estimated' }) official recommendation)</h3>
    $hwTable
    <p class="muted">$(ConvertTo-HtmlSafe $hw.Note)</p>
  </section>
"@
)

  <section><h2>Disk Usage</h2>$($diskRowsHtml.ToString())</section>

  <section>
    <h2>Forcepoint / Websense Services</h2>
    $(Get-GenericTableHtml -Items @($ReportData.FpServices) -Columns $serviceColumns -RowColorSelector { param($i) if ($i.StartMode -eq 'Auto' -and $i.State -ne 'Running') { '#dc2626' } elseif ($i.State -eq 'Running') { '#16a34a' } else { $null } })
  </section>

  <section>
    <h2>Overall Summary</h2>
    <div class="kpi-row">
      $(Get-KpiCardHtml -Label 'Normal Findings' -Value $normalCount -Color '#16a34a')
      $(Get-KpiCardHtml -Label 'Warning Findings' -Value $warningCount -Color '#d97706')
      $(Get-KpiCardHtml -Label 'Critical Findings' -Value $criticalCount -Color '#dc2626')
      $(Get-KpiCardHtml -Label 'Unknown Findings' -Value $unknownCount -Color '#6b7280')
      $(Get-KpiCardHtml -Label 'Uptime (days)' -Value $ReportData.SystemInfo.UptimeDays -Color $(if ([int]$ReportData.SystemInfo.UptimeDays -gt 45) { '#d97706' } else { '#16a34a' }))
      $(Get-KpiCardHtml -Label 'Average CPU %' -Value $(if($null -ne $cpuVal){"$cpuVal%"}else{'N/A'}) -Color $cpuColor)
      $(Get-KpiCardHtml -Label 'Memory Usage %' -Value "$memVal%" -Color $memColor)
    </div>
  </section>

  <section><h2>Health Findings</h2>$(Get-FindingsTableHtml -Findings $findings)</section>

  <section><h2>License Status</h2>$licenseHtml</section>

$(if ($hasDb) { @"
$(if ($db.PSObject.Properties['SqlWarnings'] -and $db.SqlWarnings) { "<section style='border-left:4px solid #d97706'><h2>SQL Server Warning</h2><p class='muted'>During this run, sqlcmd reported a warning/error on some queries (the connection overall succeeded, but some numbers may be incomplete/incorrect as a result - check fields showing 'N/A' in particular): $(ConvertTo-HtmlSafe $db.SqlWarnings)</p></section>" })
  <section><h2>Deployed Components</h2>$componentsHtml<p class='muted'>Cloud/unused (DUMMY) component types have been excluded from the list.</p></section>
  <section><h2>Active Channels / Services</h2>$channelsHtml</section>
  <section><h2>Endpoint Status</h2>$endpointStatusHtml</section>
  $totalIncidentSectionHtml
  $incidentTypeServerGridHtml
  <section><h2>Policy Summary</h2>$policyHtml</section>
  $topPolicySectionHtml
  $networkEndpointGridHtml
  <section><h2>Incident (Event) Summary</h2>$incidentHtml</section>
  <section><h2>Console Users and Roles</h2>$adminHtml</section>
  <section><h2>Integration Status</h2>$integrationHtml</section>
"@ } else {
    $dbErrText = ''
    if ($ReportData.PSObject.Properties['Database'] -and $ReportData.Database -and $ReportData.Database.PSObject.Properties['ErrorMessage'] -and $ReportData.Database.ErrorMessage) {
        $dbErrText = ' Note: ' + (ConvertTo-HtmlSafe $ReportData.Database.ErrorMessage)
    }
    "<section><h2>SQL Server Database Connection</h2><p class='muted'>Database check was not performed or failed.$dbErrText</p></section>"
})

  <footer>Forcepoint DLP Health Check &middot; $generatedAt &middot; FIRAT AYDIN</footer>
</div>
</body>
</html>
"@

    return $html
}

function Convert-FpHtmlToPdf {
    # Converts the HTML report to PDF using the headless print-to-PDF feature of whichever
    # browser (Microsoft Edge or Google Chrome) is found on the system (2026-09-26). Requires
    # NO extra PowerShell module/dependency - Edge already ships with Windows 10/11 and
    # Server 2019+. Returns $false if no browser is found or the conversion fails - the HTML
    # report is ALWAYS produced regardless; the PDF is only an ADDITIONAL, optional output.
    param([Parameter(Mandatory)] [string]$HtmlPath, [Parameter(Mandatory)] [string]$PdfPath)

    $candidates = @(
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe')
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe')
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe')
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe')
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
    )
    $browserExe = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $browserExe) { return $false }

    $tempProfile = $null
    try {
        $htmlUri = ([System.Uri]$HtmlPath).AbsoluteUri
        # Uses a separate/temporary user-data-dir - otherwise it can collide with a
        # browser session the user already has open ("user data directory is already in use").
        $tempProfile = Join-Path $env:TEMP ('FpDlpPdf_' + [guid]::NewGuid().ToString('N'))
        $argList = @(
            '--headless'
            '--disable-gpu'
            '--disable-extensions'
            "--user-data-dir=$tempProfile"
            "--print-to-pdf=$PdfPath"
            '--no-pdf-header-footer'
            '--print-to-pdf-no-header'
            $htmlUri
        )
        $proc = Start-Process -FilePath $browserExe -ArgumentList $argList -PassThru -WindowStyle Hidden
        $exited = $proc.WaitForExit(60000)
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            return $false
        }
        return (Test-Path -LiteralPath $PdfPath)
    }
    catch {
        return $false
    }
    finally {
        if ($tempProfile) { Remove-Item -Path $tempProfile -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ------------------------------------------------------------------------------------
# ANA AKIS
# ------------------------------------------------------------------------------------

$startedAt = Get-Date
$findings = [System.Collections.Generic.List[object]]::new()

if ([string]::IsNullOrWhiteSpace($CustomerName)) {
    $CustomerName = Read-Host -Prompt 'Customer name (may be left empty)'
}

Write-Host 'FORCEPOINT DLP HEALTH CHECK' -ForegroundColor White
Write-Host ('Server       : {0}' -f $env:COMPUTERNAME)
Write-Host ('Collected at : {0:yyyy-MM-dd HH:mm:ss}' -f $startedAt)

# --- Donanim ---
Write-Section -Title 'SYSTEM INFORMATION'
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$processors = @(Get-CimInstance -ClassName Win32_Processor)
$totalLogicalCpu = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
$totalMemoryGB = Convert-BytesToGB -Bytes ([double]$computerSystem.TotalPhysicalMemory)
$freeMemoryGB = Convert-BytesToGB -Bytes ([double]$operatingSystem.FreePhysicalMemory * 1KB)
$usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
$memoryUsedPct = if ($totalMemoryGB -gt 0) { [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1) } else { 0 }
$lastBoot = $operatingSystem.LastBootUpTime
$uptimeDays = [math]::Round(((Get-Date) - $lastBoot).TotalDays)

[pscustomobject]@{
    ComputerName    = $computerSystem.Name
    Manufacturer    = $computerSystem.Manufacturer
    Model           = $computerSystem.Model
    OperatingSystem = $operatingSystem.Caption
    OSVersion       = $operatingSystem.Version
    Architecture    = $operatingSystem.OSArchitecture
    LastBoot        = $lastBoot.ToString('dd.MM.yyyy HH:mm:ss')
} | Format-List

Write-Host '*** SERVER UPTIME ***' -ForegroundColor White
Write-Host ("      {0} DAYS      " -f $uptimeDays) -ForegroundColor $(if ($uptimeDays -gt 45) { 'Red' } else { 'Green' })
if ($uptimeDays -gt 45) { Write-Host 'A reboot of the machine is recommended.' -ForegroundColor Red }

Write-Section -Title 'PROCESSOR AND MEMORY'
Write-Host "Sampling CPU ($CpuSampleCount x $CpuSampleIntervalSeconds sec)..." -ForegroundColor DarkGray
$cpuSamples = @()
for ($i = 0; $i -lt $CpuSampleCount; $i++) {
    $cpuSamples += (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    if ($i -lt $CpuSampleCount - 1) { Start-Sleep -Seconds $CpuSampleIntervalSeconds }
}
$cpuAverage = [math]::Round((($cpuSamples | Measure-Object -Average).Average), 1)

[pscustomobject]@{
    VirtualCPUs   = $totalLogicalCpu
    CpuUsagePct   = $cpuAverage
    TotalMemoryGB = $totalMemoryGB
    UsedMemoryGB  = $usedMemoryGB
} | Format-List

Add-Finding -List $findings -Category 'Hardware' -Metric 'CPU usage' -Value "$cpuAverage%" `
    -Status (Get-Status -Value $cpuAverage -WarningThreshold $CpuWarningPercent -CriticalThreshold $CpuCriticalPercent) `
    -Note "Thresholds: Warning >= $CpuWarningPercent%, Critical >= $CpuCriticalPercent%"
Add-Finding -List $findings -Category 'Hardware' -Metric 'Memory usage' -Value "$memoryUsedPct%" `
    -Status (Get-Status -Value $memoryUsedPct -WarningThreshold $MemoryWarningUsedPercent -CriticalThreshold $MemoryCriticalUsedPercent) `
    -Note "Thresholds: Warning >= $MemoryWarningUsedPercent%, Critical >= $MemoryCriticalUsedPercent%"
Add-Finding -List $findings -Category 'Hardware' -Metric 'Server uptime' -Value "$uptimeDays days" `
    -Status $(if ($uptimeDays -gt 45) { 'Warning' } else { 'Normal' }) `
    -Note $(if ($uptimeDays -gt 45) { 'The server has not been rebooted for more than 45 days; a reboot should be considered during scheduled maintenance.' } else { 'Uptime is within the normal range.' })

Write-Section -Title 'FIXED DISKS'
$logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')
$diskObjects = @($logicalDisks | ForEach-Object {
    $sizeGB = Convert-BytesToGB -Bytes ([double]$_.Size)
    $freeGB = Convert-BytesToGB -Bytes ([double]$_.FreeSpace)
    $freePct = if ([double]$_.Size -gt 0) { [math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100, 1) } else { 0 }
    [pscustomobject]@{ Drive = $_.DeviceID; SizeGB = $sizeGB; FreeGB = $freeGB; FreePercent = $freePct }
})
$diskObjects | Format-Table -AutoSize
foreach ($disk in $diskObjects) {
    Add-Finding -List $findings -Category 'Hardware' -Metric "Disk $($disk.Drive) free space" -Value "$($disk.FreePercent)% ($($disk.FreeGB) GB)" `
        -Status (Get-Status -Value $disk.FreePercent -WarningThreshold $DiskWarningFreePercent -CriticalThreshold $DiskCriticalFreePercent -Direction 'LowerIsWorse') `
        -Note "Thresholds: Warning <= $DiskWarningFreePercent%, Critical <= $DiskCriticalFreePercent%"
}

Write-Section -Title 'EVENT VIEWER (FORCEPOINT/WEBSENSE)'
$eventLogInfo = Get-FpEventLogFindings -LookbackDays $EventLogLookbackDays
if ($eventLogInfo.Status -eq 'Successful') {
    if ($eventLogInfo.TotalCount -gt 0) {
        Write-Host "Found $($eventLogInfo.TotalCount) warning/error entries in the last $EventLogLookbackDays days." -ForegroundColor Yellow
        $eventLogInfo.Events | Format-Table -AutoSize -Wrap
        foreach ($ev in $eventLogInfo.Events) {
            $evStatus = if ($ev.Level -eq 'Error') { 'Critical' } else { 'Warning' }
            Add-Finding -List $findings -Category 'EventLog' -Metric "$($ev.Source) (ID $($ev.Id))" -Value $ev.Level -Status $evStatus -Note "$($ev.Time): $($ev.Message)"
        }
    }
    else {
        Write-Host "No Forcepoint/Websense-related warning/error entries found in the last $EventLogLookbackDays days." -ForegroundColor Green
        Add-Finding -List $findings -Category 'EventLog' -Metric 'Windows Event Log' -Value 'Clean' -Status 'Normal' -Note "No Forcepoint/Websense-related Error/Warning entries in the last $EventLogLookbackDays days."
    }
}
else {
    Write-Host "Could not read Event Log: $($eventLogInfo.Error)" -ForegroundColor DarkYellow
    Add-Finding -List $findings -Category 'EventLog' -Metric 'Windows Event Log' -Value 'Unreadable' -Status 'Unknown' -Note ([string]$eventLogInfo.Error)
}

Write-Section -Title 'FORCEPOINT DLP VERSION'
$localFpVersion = Get-FpLocalVersion
if ($localFpVersion) { Write-Host "Local install (registry) version: $localFpVersion" -ForegroundColor Cyan }
else { Write-Host 'Local install version could not be read from the registry (this machine may not be the FSM/Content Manager server).' -ForegroundColor DarkYellow }

Write-Section -Title 'HARDWARE COMPARISON (based on detected Forcepoint DLP version)'
$totalDiskGB = ($diskObjects | Measure-Object -Property SizeGB -Sum).Sum
$hwAssessment = Get-FpHardwareAssessment -LogicalCpu $totalLogicalCpu -RamGB $totalMemoryGB -TotalDiskGB $totalDiskGB -FpVersion $localFpVersion
Write-Host ("Version: {0} (table matched: {1}) - Result: {2}" -f $hwAssessment.VersionKey, $hwAssessment.Matched, $hwAssessment.Level) -ForegroundColor Cyan
$hwAssessment.Rows | Format-Table -AutoSize
Add-Finding -List $findings -Category 'Hardware' -Metric "Forcepoint DLP $($hwAssessment.VersionKey) hardware recommendation" `
    -Value ("{0} vCPU / {1} GB RAM / {2} GB disk -> {3}" -f $totalLogicalCpu, $totalMemoryGB, $totalDiskGB, $hwAssessment.Level) `
    -Status $hwAssessment.Status -Note $hwAssessment.Note

Write-Section -Title 'FORCEPOINT / WEBSENSE SERVICES'
$fpServices = @(Get-FpServices)
if ($fpServices.Count -gt 0) { $fpServices | Format-Table -AutoSize } else { Write-Host 'No Forcepoint/Websense service found.' -ForegroundColor DarkYellow }

# Saglik Bulgulari tablosunun cok uzamamasi icin: calisan servisler TEK bir ozet satirda,
# beklendigi gibi devre disi/manuel oldugu icin calismayanlar TEK bir ozet satirda toplanir.
# Sadece GERCEK SORUN olan servisler (Auto baslangicli ama calismiyor) tek tek listelenir.
$runningServices = @($fpServices | Where-Object { $_.State -eq 'Running' })
$expectedStoppedServices = @($fpServices | Where-Object { $_.State -ne 'Running' -and $_.StartMode -ne 'Auto' })
$problemServices = @($fpServices | Where-Object { $_.State -ne 'Running' -and $_.StartMode -eq 'Auto' })

if ($runningServices.Count -gt 0) {
    Add-Finding -List $findings -Category 'Service' -Metric 'Running services' -Value "$($runningServices.Count) service(s)" `
        -Status 'Normal' -Note (($runningServices | ForEach-Object { $_.DisplayName }) -join ', ')
}
if ($expectedStoppedServices.Count -gt 0) {
    Add-Finding -List $findings -Category 'Service' -Metric 'Stopped services (Manual/Disabled - expected)' -Value "$($expectedStoppedServices.Count) service(s)" `
        -Status 'Normal' -Note (($expectedStoppedServices | ForEach-Object { "$($_.DisplayName) ($($_.StartMode))" }) -join ', ')
}
foreach ($svc in $problemServices) {
    Add-Finding -List $findings -Category 'Service' -Metric $svc.DisplayName -Value $svc.State -Status 'Critical' -Note "Start mode is Auto but the service is not running."
}

# --- License (local) ---
Write-Section -Title 'LICENSE'
$licenseInfo = Get-FpLicenseInfo -WarningDays $LicenseWarningDays
switch ($licenseInfo.Status) {
    'OK' {
        Write-Host "License OK, expires: $($licenseInfo.ExpiresOn) ($($licenseInfo.DaysRemaining) days remaining)" -ForegroundColor Green
        Add-Finding -List $findings -Category 'License' -Metric 'Forcepoint DLP subscription' -Value 'OK' -Status 'Normal' -Note "Expires: $($licenseInfo.ExpiresOn), $($licenseInfo.DaysRemaining) days remaining."
    }
    'Expiring soon' {
        Write-Host "License expiring soon: $($licenseInfo.ExpiresOn) ($($licenseInfo.DaysRemaining) days remaining)" -ForegroundColor Yellow
        Add-Finding -List $findings -Category 'License' -Metric 'Forcepoint DLP subscription' -Value 'Expiring soon' -Status 'Warning' -Note "Expires: $($licenseInfo.ExpiresOn), $($licenseInfo.DaysRemaining) days remaining."
    }
    'Expired' {
        Write-Host "License has expired: $($licenseInfo.ExpiresOn)" -ForegroundColor Red
        Add-Finding -List $findings -Category 'License' -Metric 'Forcepoint DLP subscription' -Value 'Expired' -Status 'Critical' -Note "Expired: $($licenseInfo.ExpiresOn)."
    }
    default {
        Write-Host "License file could not be read: $($licenseInfo.Error)" -ForegroundColor DarkYellow
        Add-Finding -List $findings -Category 'License' -Metric 'Forcepoint DLP subscription' -Value 'Unknown' -Status 'Unknown' -Note ([string]$licenseInfo.Error)
    }
}

# --- SQL Server / Forcepoint DB ---
$databaseCheck = $null
$databaseChecked = $false
Write-Section -Title 'SQL SERVER / FORCEPOINT DLP DATABASE'
if ($SkipDatabaseCheck) {
    Write-Host 'Database check skipped via -SkipDatabaseCheck.' -ForegroundColor DarkYellow
}
else {
    if ([string]::IsNullOrWhiteSpace($SqlServerInstance)) {
        $SqlServerInstance = Read-Host -Prompt 'SQL Server name (example: SERVERNAME or SERVERNAME\INSTANCE)'
    }
    if (-not $PSBoundParameters.ContainsKey('SqlAuthMode')) {
        Write-Host ''
        Write-Host 'Select authentication type:'
        Write-Host '  1 = Windows Authentication (default, connects with the current session)'
        Write-Host '  2 = SQL Server Authentication (username/password)'
        $authChoice = Read-Host -Prompt 'Your choice [1]'
        if ($authChoice.Trim() -eq '2') { $SqlAuthMode = 'SqlLogin' }
    }
    if ($SqlAuthMode -eq 'SqlLogin' -and [string]::IsNullOrWhiteSpace($SqlUserName)) {
        $SqlUserName = Read-Host -Prompt 'SQL Server username'
    }
    try {
        $databaseCheck = Invoke-FpDatabaseCheck -ServerInstance $SqlServerInstance -DatabaseName $SqlDatabaseName -AuthMode $SqlAuthMode -UserName $SqlUserName -LookbackDays $IncidentLookbackDays -KeepTempFiles:$KeepTempSqlFiles
    }
    catch {
        $databaseCheck = [pscustomobject]@{
            DatabaseLogin = 'Failed'
            ErrorMessage  = "Unexpected error (call site): $($_.Exception.GetType().FullName): $($_.Exception.Message) [line: $($_.InvocationInfo.ScriptLineNumber), command: $($_.InvocationInfo.Line.Trim())]"
        }
    }
    $databaseChecked = $true

    if ($databaseCheck.DatabaseLogin -eq 'Successful') {
        Write-Host "SQL Server connection: SUCCESSFUL ($SqlServerInstance / $SqlDatabaseName)" -ForegroundColor Green
        Add-Finding -List $findings -Category 'Database' -Metric 'SQL Server connection' -Value 'Successful' -Status 'Normal' -Note "$SqlServerInstance / $SqlDatabaseName"

        if ($databaseCheck.FpVersionStatus -eq 'Successful') {
            Write-Host "Forcepoint DLP version: $($databaseCheck.FpVersion)" -ForegroundColor Cyan
        }

        Write-Section -Title 'DEPLOYED COMPONENTS'
        if (@($databaseCheck.Components).Count -gt 0) { $databaseCheck.Components | Format-Table -AutoSize } else { Write-Host 'Component information could not be read.' -ForegroundColor DarkYellow }
        # Keep the Health Findings table from growing too long: components with no problem
        # (DeployResult SUCCESS or empty) go into ONE summary row; components with a real
        # problem (last deployment FAILED) are listed individually.
        $normalComponents = @($databaseCheck.Components | Where-Object { -not $_.DeployResult -or $_.DeployResult -eq 'SUCCESS' })
        $problemComponents = @($databaseCheck.Components | Where-Object { $_.DeployResult -and $_.DeployResult -ne 'SUCCESS' })
        if ($normalComponents.Count -gt 0) {
            Add-Finding -List $findings -Category 'Component' -Metric 'Healthy components' -Value "$($normalComponents.Count) component(s)" `
                -Status 'Normal' -Note (($normalComponents | ForEach-Object { "$($_.Name) ($($_.ElementType) @ $($_.HostName))" }) -join ', ')
        }
        foreach ($c in $problemComponents) {
            $descText = if ($c.ResultDesc) { $c.ResultDesc } else { 'No detailed description' }
            Add-Finding -List $findings -Category 'Component' -Metric $c.Name -Value "$($c.ElementType) @ $($c.HostName)" -Status 'Warning' -Note "Last deployment result: $($c.DeployResult) - $descText"
        }
        # Tum bilesenlerin surumu ayni mi? (bos/N-A olanlar disinda)
        $distinctVersions = @($databaseCheck.Components | Where-Object { $_.Version } | Select-Object -ExpandProperty Version -Unique)
        $versionGroups = @($databaseCheck.Components | Where-Object { $_.Version } | Group-Object Version)
        if ($distinctVersions.Count -gt 1) {
            $versionDetail = ($versionGroups | ForEach-Object {
                $names = ($_.Group | ForEach-Object { ConvertTo-HtmlSafe $_.Name }) -join ', '
                "$(ConvertTo-HtmlSafe $_.Name) <strong>($names)</strong>"
            }) -join ', '
            Add-Finding -List $findings -Category 'Component' -Metric 'Component version consistency' -Value ($distinctVersions -join ', ') -Status 'Warning' `
                -Note "Components appear to be on different versions: $versionDetail. Incompatibility between different versions can cause problems; planning an update is recommended." -NoteIsHtml
        }
        elseif ($distinctVersions.Count -eq 1) {
            $names = ($versionGroups[0].Group | ForEach-Object { ConvertTo-HtmlSafe $_.Name }) -join ', '
            Add-Finding -List $findings -Category 'Component' -Metric 'Component version consistency' -Value $distinctVersions[0] -Status 'Normal' `
                -Note "All components reporting version information are on the same version. <strong>($names)</strong>" -NoteIsHtml
        }

        Write-Section -Title 'ACTIVE CHANNELS / BLOCK MODE'
        $blockingChannels = @($databaseCheck.Channels | Where-Object { $_.ServiceMode -eq 'BLOCKING' })
        Write-Host "Total active channels: $(@($databaseCheck.Channels).Count), in Blocking mode: $($blockingChannels.Count)" -ForegroundColor Cyan
        if ($blockingChannels.Count -eq 0) {
            Write-Host 'No channel is in Blocking mode; all appear to be in Monitoring mode.' -ForegroundColor DarkYellow
        }

        Write-Section -Title 'POLICY SUMMARY'
        Write-Host "Total: $($databaseCheck.PolicyTotal), Enabled: $($databaseCheck.PolicyEnabled), Disabled: $($databaseCheck.PolicyDisabled)" -ForegroundColor Cyan
        Write-Host '(Only policies created by the organization itself - Forcepoint''s ready-made template library is not included in the count.)' -ForegroundColor DarkGray
        if (@($databaseCheck.PolicyByType).Count -gt 1) {
            Write-Host 'By type (Network DLP and Discovery policies are managed on SEPARATE console screens):' -ForegroundColor DarkGray
            $databaseCheck.PolicyByType | Format-Table -AutoSize
        }

        Write-Section -Title 'INCIDENT (EVENT) SUMMARY'
        Write-Host "Total: $($databaseCheck.IncidentTotal), in the last $IncidentLookbackDays days: $($databaseCheck.IncidentRecent), in the last 7 days: $($databaseCheck.IncidentLast7Days)" -ForegroundColor Cyan

        Write-Section -Title "TOP VIOLATED POLICIES (Last $IncidentLookbackDays days, Top 10)"
        if (@($databaseCheck.TopPolicies).Count -gt 0) {
            Write-Host "There are $($databaseCheck.IncidentRecent) incidents in this period; $($databaseCheck.PolicyDistinctIncidentsRecent) of them were associated with at least one policy/rule. The sum of the rows in the table below may be higher than this, because a single incident can trigger more than one different policy (this is not double-counting)." -ForegroundColor DarkGray
            $databaseCheck.TopPolicies | Format-Table -AutoSize -Wrap
        } elseif (@($databaseCheck.TopPoliciesAllTime).Count -gt 0) {
            Write-Host "No violations in the last $IncidentLookbackDays days; showing the all-time summary instead:" -ForegroundColor DarkYellow
            Write-Host "There are $($databaseCheck.IncidentTotal) incidents in total; $($databaseCheck.PolicyDistinctIncidents) of them were associated with at least one policy/rule." -ForegroundColor DarkGray
            $databaseCheck.TopPoliciesAllTime | Format-Table -AutoSize -Wrap
        } else {
            Write-Host 'No policy violation records found.' -ForegroundColor DarkYellow
        }

        Write-Section -Title 'CONSOLE USERS AND ROLES'
        Write-Host "Users: $(@($databaseCheck.Admins).Count), Roles: $(@($databaseCheck.Roles).Count)" -ForegroundColor Cyan
        $disabledAdmins = @($databaseCheck.Admins | Where-Object Disabled)
        if ($disabledAdmins.Count -gt 0) {
            Add-Finding -List $findings -Category 'Access' -Metric 'Disabled console users' -Value $disabledAdmins.Count -Status 'Warning' -Note (($disabledAdmins | ForEach-Object { $_.Name }) -join ', ')
        }

        Write-Section -Title 'AD / LDAP DIRECTORY SYNC'
        if (@($databaseCheck.AdSync).Count -gt 0) {
            $databaseCheck.AdSync | Format-Table -AutoSize
            foreach ($row in $databaseCheck.AdSync) {
                $tot = 0; $syn = 0
                [void][int]::TryParse($row.Total, [ref]$tot); [void][int]::TryParse($row.Synced, [ref]$syn)
                if ($tot -gt 0 -and $syn -lt $tot) {
                    Add-Finding -List $findings -Category 'Integration' -Metric "AD sync ($($row.Repo))" -Value "$syn / $tot synchronized" -Status 'Warning' -Note 'Some AD records are not synchronized (SYNCH_STATUS <> SYNCHRONIZED). Check via Console > User Directories.'
                }
            }
        } else { Write-Host 'AD/LDAP sync data could not be read or is empty (AD integration may not be configured).' -ForegroundColor DarkYellow }

        Write-Section -Title 'ARCHIVE STORAGE'
        if (@($databaseCheck.ArchiveConf).Count -gt 0) {
            $databaseCheck.ArchiveConf | Format-Table -AutoSize
        } else { Write-Host 'Archive storage configuration could not be read or is empty.' -ForegroundColor DarkYellow }

        Write-Section -Title 'DISCOVERY / FINGERPRINTING TASKS'
        if (@($databaseCheck.DiscoveryTasks).Count -gt 0) {
            $databaseCheck.DiscoveryTasks | Format-Table -AutoSize
            $failedTasks = @($databaseCheck.DiscoveryTasks | Where-Object { $_.OperationStatus -and $_.OperationStatus -match 'FAIL|ERROR' })
            if ($failedTasks.Count -gt 0) {
                foreach ($t in $failedTasks) {
                    Add-Finding -List $findings -Category 'Discovery' -Metric $t.Name -Value $t.OperationStatus -Status 'Warning' -Note "Task type: $($t.TaskType)"
                }
            } else {
                Add-Finding -List $findings -Category 'Discovery' -Metric 'Discovery/Fingerprinting tasks' -Value "$(@($databaseCheck.DiscoveryTasks).Count) task(s)" -Status 'Normal' -Note 'No task appears to be in a failed/error state.'
            }
        } else { Write-Host 'No defined Discovery/Fingerprinting tasks found.' -ForegroundColor DarkYellow }

        Write-Section -Title 'POLICY TIERING'
        Write-Host "Number of defined policy levels (tiers): $($databaseCheck.PolicyLevelCount)" -ForegroundColor Cyan

        Write-Section -Title 'SQL SERVER DISK SPACE'
        if ($databaseCheck.SqlDiskStatus -eq 'Successful') {
            $databaseCheck.SqlDisks | Format-Table -AutoSize
            foreach ($d in $databaseCheck.SqlDisks) {
                $freeMb = 0; [void][int]::TryParse($d.FreeMB, [ref]$freeMb)
                $freeGb = [math]::Round($freeMb / 1024, 1)
                $sqlDiskStatusLevel = if ($freeGb -lt 5) { 'Critical' } elseif ($freeGb -lt 10) { 'Warning' } else { 'Normal' }
                Add-Finding -List $findings -Category 'Database' -Metric "SQL Server disk $($d.Drive):" -Value "$freeGb GB free" -Status $sqlDiskStatusLevel -Note 'Thresholds (absolute; total capacity cannot be obtained via xp_fixeddrives): Warning < 10 GB, Critical < 5 GB free space.'
            }
        }
        elseif ($databaseCheck.SqlDiskStatus -like 'Failed:*') {
            Write-Host "SQL Server disk information could not be read: $($databaseCheck.SqlDiskStatus)" -ForegroundColor DarkYellow
            Add-Finding -List $findings -Category 'Database' -Metric 'SQL Server disk information' -Value 'Unreadable' -Status 'Unknown' -Note "$($databaseCheck.SqlDiskStatus) (xp_fixeddrives may require elevated permissions)"
        }
        else { Write-Host 'SQL Server disk information could not be obtained.' -ForegroundColor DarkYellow }
    }
    else {
        Write-Host "SQL Server connection FAILED: $($databaseCheck.ErrorMessage)" -ForegroundColor Red
        Add-Finding -List $findings -Category 'Database' -Metric 'SQL Server connection' -Value 'Failed' -Status 'Critical' -Note ([string]$databaseCheck.ErrorMessage)
    }
}

Write-Section -Title 'SYSLOG'
if ($databaseChecked -and $databaseCheck.SyslogStatus -eq 'Successful') {
    if ($databaseCheck.SyslogHostname) {
        Write-Host "Syslog target: $($databaseCheck.SyslogHostname):$($databaseCheck.SyslogPort) (facility: $($databaseCheck.SyslogFacility))" -ForegroundColor Cyan
        Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog' -Value "$($databaseCheck.SyslogHostname):$($databaseCheck.SyslogPort)" -Status 'Normal' -Note "Facility: $($databaseCheck.SyslogFacility). Source: PA_CONFIG_PROPERTIES (INCIDENTS_SYSLOG-*)."
    } else {
        Write-Host 'Syslog target is not defined (INCIDENTS_SYSLOG-HOSTNAME is empty) - forwarding is not configured.' -ForegroundColor DarkYellow
        Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog' -Value 'Not configured' -Status 'Warning' -Note 'Syslog server address is not defined; if SIEM/log collection integration is desired, configure it via FSM > Settings > General > Remediation. If intentional (SIEM integration not desired), this can be disregarded.'
    }
}
else {
    Write-Host 'Syslog setting could not be read (database check failed, or PA_CONFIG_PROPERTIES not found).' -ForegroundColor DarkYellow
    Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog' -Value 'Unknown' -Status 'Unknown' -Note 'Syslog setting could not be read; check manually from the Security Manager console (Settings > General > Remediation).'
}

# --- Ozet ve HTML export ---
Write-Section -Title 'SUMMARY'
$normalCount = @($findings | Where-Object Status -eq 'Normal').Count
$warningCount = @($findings | Where-Object Status -eq 'Warning').Count
$criticalCount = @($findings | Where-Object Status -eq 'Critical').Count
$unknownCount = @($findings | Where-Object Status -eq 'Unknown').Count
Write-Host "Normal: $normalCount, Warning: $warningCount, Critical: $criticalCount, Unknown: $unknownCount"

$reportData = [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    CollectedAt          = $startedAt.ToString('yyyy-MM-dd HH:mm:ss')
    SystemInfo           = [pscustomobject]@{
        Manufacturer    = $computerSystem.Manufacturer
        Model           = $computerSystem.Model
        OperatingSystem = $operatingSystem.Caption
        OSVersion       = $operatingSystem.Version
        Architecture    = $operatingSystem.OSArchitecture
        LastBoot        = $lastBoot.ToString('dd.MM.yyyy HH:mm:ss')
        UptimeDays      = $uptimeDays
    }
    Hardware             = [pscustomobject]@{ LogicalCpu = $totalLogicalCpu; TotalMemoryGB = $totalMemoryGB; CpuAveragePct = $cpuAverage; MemoryUsedPct = $memoryUsedPct; TotalDiskGB = $totalDiskGB }
    HardwareAssessment   = $hwAssessment
    Disks                = $diskObjects
    FpServices           = $fpServices
    License              = $licenseInfo
    LocalFpVersion       = $localFpVersion
    DatabaseChecked      = $databaseChecked
    Database             = $databaseCheck
    IncidentLookbackDays = $IncidentLookbackDays
    Findings             = $findings
}

$htmlReport = New-FpHtmlReport -ReportData $reportData -CustomerName $CustomerName
$desktopPath = [Environment]::GetFolderPath('Desktop')
# The report file name is based on the CUSTOMER NAME (2026-09-26, user request) - if no
# customer name was entered (left blank), it falls back to the computer name as before.
$safeCustomerName = if (-not [string]::IsNullOrWhiteSpace($CustomerName)) { ($CustomerName -replace '[^\w\-]', '_').Trim('_') } else { $null }
$safeComputerName = ($env:COMPUTERNAME -replace '[^\w\-]', '_')
$reportBaseId = if ($safeCustomerName) { $safeCustomerName } else { $safeComputerName }
$reportBaseName = "{0}_FP_DLP_HC_{1}" -f $reportBaseId, (Get-Date -Format 'yyyy-MM-dd_HHmm')
$reportPath = Join-Path $desktopPath "$reportBaseName.html"
Set-Content -LiteralPath $reportPath -Value $htmlReport -Encoding UTF8

Write-Host ''
Write-Host "HTML report generated: $reportPath" -ForegroundColor Green

$pdfPath = Join-Path $desktopPath "$reportBaseName.pdf"
if (Convert-FpHtmlToPdf -HtmlPath $reportPath -PdfPath $pdfPath) {
    Write-Host "PDF report generated: $pdfPath" -ForegroundColor Green
} else {
    Write-Host 'PDF report could not be generated (Microsoft Edge or Google Chrome not found, or the conversion failed) - only the HTML report is available.' -ForegroundColor DarkYellow
}

Write-Host 'FIRAT AYDIN' -ForegroundColor DarkGray
